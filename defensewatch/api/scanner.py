import json
import time
import asyncio
import logging
from urllib.parse import urlparse
from fastapi import APIRouter, Query
from pydantic import BaseModel
from defensewatch.database import get_db
from defensewatch.audit import log_audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scanner", tags=["scanner"])

# Module-level state set during lifespan
_config = None
_manager = None
_scan_lock = asyncio.Lock()
_current_scan: dict | None = None
_cancel_event: asyncio.Event | None = None


def set_scanner_deps(config, manager):
    global _config, _manager
    _config = config
    _manager = manager


class ScanRequest(BaseModel):
    targets: list[str] = []  # empty = auto-detect from config
    auto_profile: bool = True  # auto-detect services and select Nuclei tags
    extra_tags: list[str] = []  # additional Nuclei tags to include


@router.post("/scan")
async def start_scan(body: ScanRequest | None = None):
    """Start a Nuclei vulnerability scan. Only one scan can run at a time."""
    global _current_scan

    if _config is None or not _config.nuclei.enabled:
        return {"error": "Nuclei scanning is not enabled. Set nuclei.enabled: true in config.yaml"}

    if _scan_lock.locked():
        return {"error": "A scan is already in progress", "scan": _current_scan}

    # Build target list
    targets = []
    if body and body.targets:
        targets = body.targets
    else:
        targets = _build_targets_from_config()

    if not targets:
        return {"error": "No targets specified and none could be auto-detected from config"}

    # Build service profile for smart tag selection
    profile_summary = None
    nuclei_tags = []
    if body is None or body.auto_profile:
        from defensewatch.scanner.service_profiler import profile_services
        profile = profile_services(_config)
        nuclei_tags = list(profile.nuclei_tags)
        profile_summary = profile.summary()
        logger.info(f"Service profile: {len(profile.detected_techs)} technologies, {len(nuclei_tags)} tags")

    if body and body.extra_tags:
        nuclei_tags = list(set(nuclei_tags + body.extra_tags))

    # Group targets into batches by host/service
    batches = _group_targets_into_batches(targets)

    # Launch batched scan in background
    asyncio.create_task(_run_batched_scan(targets, batches, nuclei_tags))

    return {"status": "started", "targets": targets, "batches": [b["label"] for b in batches], "profile": profile_summary}


@router.get("/profile")
async def get_profile():
    """Preview detected services and the Nuclei tags that would be used."""
    if _config is None:
        return {"error": "Config not loaded"}
    from defensewatch.scanner.service_profiler import profile_services
    profile = profile_services(_config)
    return {
        "targets": _build_targets_from_config(),
        **profile.summary(),
    }


@router.get("/status")
async def scan_status():
    """Get the current scan status."""
    if _current_scan:
        return _current_scan
    return {"status": "idle", "last_scan": await _get_last_scan_time()}


@router.post("/stop")
async def stop_scan():
    """Stop the currently running scan."""
    if not _scan_lock.locked() or not _cancel_event:
        return {"error": "No scan is currently running"}
    _cancel_event.set()
    return {"status": "stopping"}


@router.get("/results")
async def get_results(
    severity: str | None = None,
    scan_id: int | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
):
    """Get scan results with optional filtering."""
    db = get_db()
    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if scan_id:
        conditions.append("scan_id = ?")
        params.append(scan_id)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    total = (await db.execute_fetchall(
        f"SELECT COUNT(*) FROM nuclei_findings {where}", params
    ))[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT id, scan_id, template_id, name, severity, host, matched_url,
            description, tags, reference, matcher_name, curl_command, remediation,
            protocol, ip, request, response, extracted_results, found_at
            FROM nuclei_findings {where}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                    ELSE 4
                END,
                found_at DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    findings = []
    for r in rows:
        tags = []
        refs = []
        extracted = []
        try:
            tags = json.loads(r[8]) if r[8] else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            refs = json.loads(r[9]) if r[9] else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            extracted = json.loads(r[17]) if r[17] else []
        except (json.JSONDecodeError, TypeError):
            pass
        findings.append({
            "id": r[0], "scan_id": r[1], "template_id": r[2],
            "name": r[3], "severity": r[4], "host": r[5],
            "matched_url": r[6], "description": r[7],
            "tags": tags, "reference": refs,
            "matcher_name": r[10], "curl_command": r[11],
            "remediation": r[12], "protocol": r[13],
            "ip": r[14], "request": r[15], "response": r[16],
            "extracted_results": extracted, "found_at": r[18],
        })

    return {"total": total, "page": page, "limit": limit, "findings": findings}


@router.get("/summary")
async def get_summary():
    """Get aggregated scan summary with severity counts and scan history."""
    db = get_db()

    # Severity breakdown from latest scan
    latest_scan = await db.execute_fetchall(
        "SELECT id FROM nuclei_scans ORDER BY started_at DESC LIMIT 1"
    )
    scan_id = latest_scan[0][0] if latest_scan else None

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if scan_id:
        rows = await db.execute_fetchall(
            "SELECT severity, COUNT(*) FROM nuclei_findings WHERE scan_id=? GROUP BY severity",
            (scan_id,)
        )
        for r in rows:
            severity_counts[r[0]] = r[1]

    # Scan history
    scans = await db.execute_fetchall(
        """SELECT id, targets, status, finding_count, started_at, finished_at
           FROM nuclei_scans ORDER BY started_at DESC LIMIT 20"""
    )
    scan_history = []
    for s in scans:
        targets = []
        try:
            targets = json.loads(s[1]) if s[1] else []
        except (json.JSONDecodeError, TypeError):
            pass
        scan_history.append({
            "id": s[0], "targets": targets, "status": s[2],
            "finding_count": s[3], "started_at": s[4], "finished_at": s[5],
        })

    # Top findings by frequency (across all scans)
    top_findings = await db.execute_fetchall(
        """SELECT template_id, name, severity, COUNT(*) as cnt
           FROM nuclei_findings GROUP BY template_id
           ORDER BY cnt DESC LIMIT 10"""
    )

    return {
        "latest_scan_id": scan_id,
        "severity_counts": severity_counts,
        "total_findings": sum(severity_counts.values()),
        "scan_history": scan_history,
        "top_findings": [
            {"template_id": r[0], "name": r[1], "severity": r[2], "count": r[3]}
            for r in top_findings
        ],
    }


@router.delete("/results")
async def clear_results(scan_id: int | None = None):
    """Clear scan results. If scan_id is given, only clear that scan."""
    db = get_db()
    if scan_id:
        await db.execute("DELETE FROM nuclei_findings WHERE scan_id=?", (scan_id,))
        await db.execute("DELETE FROM nuclei_scans WHERE id=?", (scan_id,))
    else:
        await db.execute("DELETE FROM nuclei_findings")
        await db.execute("DELETE FROM nuclei_scans")
    await db.commit()
    return {"status": "cleared"}


def _group_targets_into_batches(targets: list[str]) -> list[dict]:
    """Group targets by host/domain for batched scanning."""
    groups: dict[str, list[str]] = {}
    for target in targets:
        parsed = urlparse(target if "://" in target else f"tcp://{target}")
        host = parsed.hostname or target
        if host not in groups:
            groups[host] = []
        groups[host].append(target)
    return [{"label": host, "targets": tgts} for host, tgts in groups.items()]


def _build_targets_from_config():
    """
    Auto-detect scan targets from web server configurations and monitored services.

    Priority:
    1. Nginx/Apache vhost configs (most accurate)
    2. HTTP log vhosts (extracted from log filenames)
    3. SSH services from config
    """
    from defensewatch.scanner.vhost_detect import detect_all_vhosts

    targets = []
    host = _config.host.name or "127.0.0.1"
    seen_targets = set()

    # 1. Detect vhosts from Nginx/Apache configs
    try:
        vhosts = detect_all_vhosts()
        for vhost in vhosts:
            target = vhost.url
            if target not in seen_targets:
                seen_targets.add(target)
                targets.append(target)
                logger.debug(f"Added vhost target from config: {target}")

        if vhosts:
            logger.info(f"Detected {len(vhosts)} vhosts from web server configs")
    except Exception as e:
        logger.warning(f"Failed to detect vhosts from web server configs: {e}")

    # 2. Fall back to HTTP log vhosts if no vhosts were detected
    if not targets:
        for entry in _config.logs.http_entries():
            port = entry.port or 80
            scheme = "https" if port == 443 else "http"

            if entry.vhost:
                # Use vhost extracted from log filename
                target = f"{scheme}://{entry.vhost}:{port}" if port not in (80, 443) else f"{scheme}://{entry.vhost}"
            else:
                # Fall back to IP address
                target = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

            if target not in seen_targets:
                seen_targets.add(target)
                targets.append(target)

    # 3. Add SSH services
    for entry in _config.logs.ssh_entries():
        port = entry.port or 22
        target = f"{host}:{port}"
        if target not in seen_targets:
            seen_targets.add(target)
            targets.append(target)

    return targets


async def _run_batched_scan(
    all_targets: list[str],
    batches: list[dict],
    nuclei_tags: list[str] | None = None,
):
    """Execute scan in batches per host/service, broadcasting per-finding and per-batch updates."""
    global _current_scan, _cancel_event
    from defensewatch.scanner.nuclei import run_nuclei_scan

    async with _scan_lock:
        _cancel_event = asyncio.Event()
        db = get_db()

        now = time.time()
        cursor = await db.execute(
            """INSERT INTO nuclei_scans (targets, status, finding_count, started_at)
               VALUES (?, 'running', 0, ?)""",
            (json.dumps(all_targets), now)
        )
        scan_id = cursor.lastrowid
        await db.commit()
        await log_audit("scan_start", str(scan_id), f"Started vulnerability scan", actor="api")

        batch_labels = [b["label"] for b in batches]
        _current_scan = {
            "status": "running",
            "scan_id": scan_id,
            "targets": all_targets,
            "started_at": now,
            "findings_so_far": 0,
            "batches": batch_labels,
            "current_batch": None,
            "current_batch_index": 0,
            "total_batches": len(batches),
            "batch_findings": {},
        }

        if _manager:
            await _manager.broadcast("scan_status", _current_scan)

        total_finding_count = 0
        overall_status = "completed"

        for batch_idx, batch in enumerate(batches):
            # Check if scan was cancelled before starting next batch
            if _cancel_event.is_set():
                overall_status = "stopped"
                break

            batch_label = batch["label"]
            batch_targets = batch["targets"]

            _current_scan["current_batch"] = batch_label
            _current_scan["current_batch_index"] = batch_idx
            _current_scan["batch_findings"][batch_label] = 0

            if _manager:
                await _manager.broadcast("scan_batch_start", {
                    "scan_id": scan_id,
                    "batch_index": batch_idx,
                    "total_batches": len(batches),
                    "batch_label": batch_label,
                    "batch_targets": batch_targets,
                })

            batch_finding_count = 0

            async def on_finding(finding):
                nonlocal total_finding_count, batch_finding_count
                total_finding_count += 1
                batch_finding_count += 1
                _current_scan["findings_so_far"] = total_finding_count
                _current_scan["batch_findings"][batch_label] = batch_finding_count

                # Store in DB
                await db.execute(
                    """INSERT INTO nuclei_findings
                       (scan_id, template_id, name, severity, host, matched_url,
                        description, tags, reference, matcher_name, curl_command,
                        remediation, raw_json, protocol, ip, request, response,
                        extracted_results, found_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, finding.template_id, finding.name, finding.severity,
                     finding.host, finding.matched_url, finding.description,
                     json.dumps(finding.tags), json.dumps(finding.reference),
                     finding.matcher_name, finding.curl_command, finding.remediation,
                     finding.raw_json, finding.protocol, finding.ip,
                     finding.request, finding.response,
                     json.dumps(finding.extracted_results), finding.found_at)
                )
                await db.commit()

                # Broadcast finding immediately to all clients
                if _manager:
                    await _manager.broadcast("nuclei_finding", {
                        "scan_id": scan_id,
                        "id": total_finding_count,
                        "batch_label": batch_label,
                        "template_id": finding.template_id,
                        "name": finding.name,
                        "severity": finding.severity,
                        "host": finding.host,
                        "matched_url": finding.matched_url,
                        "description": finding.description,
                        "tags": finding.tags,
                        "reference": finding.reference,
                        "curl_command": finding.curl_command,
                        "remediation": finding.remediation,
                        "protocol": finding.protocol,
                        "ip": finding.ip,
                        "request": finding.request,
                        "response": finding.response,
                        "extracted_results": finding.extracted_results,
                        "found_at": finding.found_at,
                    })

            try:
                await run_nuclei_scan(
                    batch_targets, _config.nuclei,
                    on_finding=on_finding, tags=nuclei_tags or None,
                    cancel_event=_cancel_event,
                )
                batch_status = "stopped" if _cancel_event.is_set() else "completed"
            except Exception as e:
                logger.error(f"Batch {batch_label} failed: {e}")
                batch_status = "failed"
                overall_status = "failed"

            if _cancel_event.is_set():
                overall_status = "stopped"

            if _manager:
                await _manager.broadcast("scan_batch_complete", {
                    "scan_id": scan_id,
                    "batch_index": batch_idx,
                    "total_batches": len(batches),
                    "batch_label": batch_label,
                    "batch_status": batch_status,
                    "batch_findings": batch_finding_count,
                    "total_findings": total_finding_count,
                })

            logger.info(
                f"Batch {batch_idx + 1}/{len(batches)} '{batch_label}' {batch_status}: "
                f"{batch_finding_count} findings"
            )

            if _cancel_event.is_set():
                break

        # Finalize scan record
        finished = time.time()
        await db.execute(
            "UPDATE nuclei_scans SET status=?, finding_count=?, finished_at=? WHERE id=?",
            (overall_status, total_finding_count, finished, scan_id)
        )
        await db.commit()

        _current_scan = {
            "status": overall_status,
            "scan_id": scan_id,
            "targets": all_targets,
            "started_at": now,
            "finished_at": finished,
            "findings_so_far": total_finding_count,
            "batches": batch_labels,
            "batch_findings": _current_scan["batch_findings"],
            "total_batches": len(batches),
        }

        _cancel_event = None

        if _manager:
            await _manager.broadcast("scan_status", _current_scan)

        logger.info(f"Scan {scan_id} {overall_status}: {total_finding_count} findings in {finished - now:.0f}s")


async def _get_last_scan_time():
    try:
        db = get_db()
        rows = await db.execute_fetchall(
            "SELECT finished_at FROM nuclei_scans ORDER BY started_at DESC LIMIT 1"
        )
        return rows[0][0] if rows else None
    except Exception:
        return None

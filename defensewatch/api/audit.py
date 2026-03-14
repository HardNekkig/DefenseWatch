"""API endpoints for the audit log."""

import time

from fastapi import APIRouter, Query
from defensewatch.database import get_db

router = APIRouter()


@router.get("/api/audit")
async def list_audit(
    action: str | None = Query(None, description="Filter by exact action type"),
    actor: str | None = Query(None, description="Filter by exact actor"),
    target: str | None = Query(None, description="Filter by target (LIKE search)"),
    since: float | None = Query(None, description="Unix timestamp lower bound"),
    until: float | None = Query(None, description="Unix timestamp upper bound"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = get_db()

    clauses: list[str] = []
    params: list = []

    if action is not None:
        clauses.append("action = ?")
        params.append(action)
    if actor is not None:
        clauses.append("actor = ?")
        params.append(actor)
    if target is not None:
        clauses.append("target LIKE ?")
        params.append(f"%{target}%")
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until is not None:
        clauses.append("timestamp <= ?")
        params.append(until)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    count_row = await db.execute_fetchall(
        f"SELECT COUNT(*) FROM audit_log{where}", params
    )
    total = count_row[0][0] if count_row else 0

    rows = await db.execute_fetchall(
        f"""SELECT id, timestamp, actor, action, target, detail, ip_address
            FROM audit_log{where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )

    entries = [
        {
            "id": r[0],
            "timestamp": r[1],
            "actor": r[2],
            "action": r[3],
            "target": r[4],
            "detail": r[5],
            "ip_address": r[6],
        }
        for r in rows
    ]

    return {"entries": entries, "total": total, "limit": limit, "offset": offset}


@router.get("/api/audit/stats")
async def audit_stats(hours: int = Query(24, ge=1, le=720)):
    db = get_db()
    cutoff = time.time() - (hours * 3600)

    # Actions per type
    action_rows = await db.execute_fetchall(
        """SELECT action, COUNT(*) as cnt FROM audit_log
           WHERE timestamp >= ?
           GROUP BY action ORDER BY cnt DESC""",
        (cutoff,),
    )
    actions_per_type = {r[0]: r[1] for r in action_rows}

    # Most active actors
    actor_rows = await db.execute_fetchall(
        """SELECT actor, COUNT(*) as cnt FROM audit_log
           WHERE timestamp >= ?
           GROUP BY actor ORDER BY cnt DESC LIMIT 10""",
        (cutoff,),
    )
    most_active_actors = {r[0]: r[1] for r in actor_rows}

    # Recent activity count
    recent_count_row = await db.execute_fetchall(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?",
        (cutoff,),
    )
    recent_count = recent_count_row[0][0] if recent_count_row else 0

    return {
        "hours": hours,
        "actions_per_type": actions_per_type,
        "most_active_actors": most_active_actors,
        "recent_activity_count": recent_count,
    }

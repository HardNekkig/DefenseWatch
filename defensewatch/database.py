import logging
import aiosqlite
import time
from pathlib import Path
from defensewatch.config import AppConfig

logger = logging.getLogger(__name__)

_db: aiosqlite.Connection | None = None


async def init_db(config: AppConfig) -> aiosqlite.Connection:
    global _db
    db_path = Path(config.database.path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    _db = await aiosqlite.connect(str(db_path))
    _db.row_factory = aiosqlite.Row

    if config.database.wal_mode:
        await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA foreign_keys=ON")

    await _create_tables(_db)
    await _migrate(_db)
    await _db.commit()
    return _db


def get_db() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


async def close_db():
    global _db
    if _db:
        await _db.close()
        _db = None


async def _create_tables(db: aiosqlite.Connection):
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS ip_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            rdns TEXT,
            asn TEXT,
            org TEXT,
            country_code TEXT,
            country_name TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            isp TEXT,
            whois_raw TEXT,
            source TEXT,
            enriched_at REAL,
            created_at REAL NOT NULL DEFAULT (unixepoch('now')),
            shodan_data TEXT,
            virustotal_data TEXT,
            censys_data TEXT
        );

        CREATE TABLE IF NOT EXISTS ssh_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            auth_method TEXT,
            hostname TEXT,
            pid INTEGER,
            raw_line TEXT,
            service_port INTEGER,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_ssh_timestamp ON ssh_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ssh_source_ip ON ssh_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_ssh_event_type ON ssh_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_ssh_ip_id ON ssh_events(ip_id);
        CREATE INDEX IF NOT EXISTS idx_ssh_ip_timestamp ON ssh_events(source_ip, timestamp);

        CREATE TABLE IF NOT EXISTS http_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT,
            path TEXT,
            http_version TEXT,
            status_code INTEGER,
            response_bytes INTEGER,
            referer TEXT,
            user_agent TEXT,
            vhost TEXT,
            attack_types TEXT,
            scanner_name TEXT,
            severity TEXT,
            raw_line TEXT,
            service_port INTEGER,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_http_source_ip ON http_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_http_severity ON http_events(severity);
        CREATE INDEX IF NOT EXISTS idx_http_ip_id ON http_events(ip_id);
        CREATE INDEX IF NOT EXISTS idx_http_ip_timestamp ON http_events(source_ip, timestamp);

        CREATE TABLE IF NOT EXISTS brute_force_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            session_start REAL NOT NULL,
            session_end REAL,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            usernames_tried TEXT,
            event_type TEXT NOT NULL DEFAULT 'ssh_brute_force',
            status TEXT NOT NULL DEFAULT 'active',
            service_port INTEGER,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_brute_source_ip ON brute_force_sessions(source_ip);
        CREATE INDEX IF NOT EXISTS idx_brute_ip_id ON brute_force_sessions(ip_id);
        CREATE INDEX IF NOT EXISTS idx_brute_session_end ON brute_force_sessions(session_end);

        CREATE TABLE IF NOT EXISTS log_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            inode INTEGER,
            byte_offset INTEGER NOT NULL DEFAULT 0,
            line_count INTEGER NOT NULL DEFAULT 0,
            last_seen REAL,
            updated_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );

        CREATE TABLE IF NOT EXISTS threat_intel_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            data TEXT,
            checked_at REAL NOT NULL,
            UNIQUE(ip, source)
        );
        CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel_hits(ip);

        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric TEXT UNIQUE NOT NULL,
            mean REAL NOT NULL,
            stddev REAL NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            computed_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric TEXT NOT NULL,
            current_value REAL NOT NULL,
            baseline_mean REAL NOT NULL,
            z_score REAL NOT NULL,
            severity TEXT NOT NULL,
            message TEXT,
            detected_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_anomaly_detected ON anomaly_alerts(detected_at);

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'open',
            source_ips TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status);

        CREATE TABLE IF NOT EXISTS incident_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            UNIQUE(incident_id, event_type, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);

        CREATE TABLE IF NOT EXISTS nuclei_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            targets TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            finding_count INTEGER NOT NULL DEFAULT 0,
            started_at REAL,
            finished_at REAL
        );

        CREATE TABLE IF NOT EXISTS nuclei_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES nuclei_scans(id) ON DELETE CASCADE,
            template_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            host TEXT,
            matched_url TEXT,
            description TEXT,
            tags TEXT,
            reference TEXT,
            matcher_name TEXT,
            curl_command TEXT,
            remediation TEXT,
            raw_json TEXT,
            protocol TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            request TEXT DEFAULT '',
            response TEXT DEFAULT '',
            extracted_results TEXT DEFAULT '',
            found_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_nuclei_findings_scan ON nuclei_findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity ON nuclei_findings(severity);

        CREATE TABLE IF NOT EXISTS service_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            service_type TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            detail TEXT,
            severity TEXT,
            service_port INTEGER,
            raw_line TEXT,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_svc_timestamp ON service_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_svc_source_ip ON service_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_svc_service_type ON service_events(service_type);
        CREATE INDEX IF NOT EXISTS idx_svc_ip_id ON service_events(ip_id);

        CREATE TRIGGER IF NOT EXISTS fill_svc_ip_id
        AFTER INSERT ON service_events
        WHEN NEW.ip_id IS NULL AND NEW.source_ip IS NOT NULL
        BEGIN
            UPDATE service_events
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TABLE IF NOT EXISTS firewall_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT DEFAULT '',
            source TEXT NOT NULL DEFAULT 'manual',
            blocked_at REAL NOT NULL,
            unblocked_at REAL,
            expires_at REAL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_fw_blocks_ip ON firewall_blocks(ip);
        CREATE INDEX IF NOT EXISTS idx_fw_blocks_active ON firewall_blocks(active);

        CREATE TABLE IF NOT EXISTS port_scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            detected_at REAL NOT NULL,
            ports_hit TEXT NOT NULL DEFAULT '[]',
            port_count INTEGER NOT NULL DEFAULT 0,
            window_seconds INTEGER NOT NULL DEFAULT 300,
            status TEXT NOT NULL DEFAULT 'active',
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_portscan_ip ON port_scan_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_portscan_detected ON port_scan_events(detected_at);

        CREATE TRIGGER IF NOT EXISTS fill_portscan_ip_id
        AFTER INSERT ON port_scan_events
        WHEN NEW.ip_id IS NULL AND NEW.source_ip IS NOT NULL
        BEGIN
            UPDATE port_scan_events
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            actor TEXT NOT NULL DEFAULT 'system',
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            last_login REAL,
            created_at REAL NOT NULL DEFAULT (unixepoch('now')),
            updated_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_jti TEXT UNIQUE NOT NULL,
            token_type TEXT NOT NULL DEFAULT 'access',
            issued_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(token_jti);

        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT,
            path TEXT NOT NULL,
            user_agent TEXT,
            headers TEXT,
            status_code INTEGER NOT NULL DEFAULT 403,
            auto_blocked INTEGER NOT NULL DEFAULT 0,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_honeypot_timestamp ON honeypot_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_honeypot_source_ip ON honeypot_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_honeypot_path ON honeypot_events(path);

        CREATE TRIGGER IF NOT EXISTS fill_honeypot_ip_id
        AFTER INSERT ON honeypot_events
        WHEN NEW.ip_id IS NULL AND NEW.source_ip IS NOT NULL
        BEGIN
            UPDATE honeypot_events
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TABLE IF NOT EXISTS blocklist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_name TEXT NOT NULL,
            network TEXT NOT NULL,
            description TEXT DEFAULT '',
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_blocklist_list ON blocklist_entries(list_name);

        CREATE TRIGGER IF NOT EXISTS fill_ssh_ip_id
        AFTER INSERT ON ssh_events
        WHEN NEW.ip_id IS NULL
        BEGIN
            UPDATE ssh_events 
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS fill_http_ip_id
        AFTER INSERT ON http_events
        WHEN NEW.ip_id IS NULL
        BEGIN
            UPDATE http_events 
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TRIGGER IF NOT EXISTS fill_brute_ip_id
        AFTER INSERT ON brute_force_sessions
        WHEN NEW.ip_id IS NULL
        BEGIN
            UPDATE brute_force_sessions
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;

        CREATE TABLE IF NOT EXISTS playbook_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            actions_taken TEXT NOT NULL DEFAULT '[]',
            detail TEXT DEFAULT '',
            executed_at REAL NOT NULL,
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pb_exec_rule ON playbook_executions(rule_name);
        CREATE INDEX IF NOT EXISTS idx_pb_exec_ip ON playbook_executions(source_ip);
        CREATE INDEX IF NOT EXISTS idx_pb_exec_time ON playbook_executions(executed_at);
    """)


async def cleanup_old_data(retention_days: int):
    cutoff = time.time() - (retention_days * 86400)
    db = get_db()
    await db.execute("DELETE FROM ssh_events WHERE timestamp < ?", (cutoff,))
    await db.execute("DELETE FROM http_events WHERE timestamp < ?", (cutoff,))
    await db.execute("DELETE FROM brute_force_sessions WHERE session_end < ?", (cutoff,))
    await db.execute("DELETE FROM service_events WHERE timestamp < ?", (cutoff,))
    await db.execute("""DELETE FROM ip_intel WHERE id NOT IN (
        SELECT DISTINCT ip_id FROM ssh_events WHERE ip_id IS NOT NULL
        UNION SELECT DISTINCT ip_id FROM http_events WHERE ip_id IS NOT NULL
        UNION SELECT DISTINCT ip_id FROM brute_force_sessions WHERE ip_id IS NOT NULL
        UNION SELECT DISTINCT ip_id FROM service_events WHERE ip_id IS NOT NULL
    )""")
    await db.execute("DELETE FROM honeypot_events WHERE timestamp < ?", (cutoff,))
    await db.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
    await db.execute("DELETE FROM threat_intel_hits WHERE checked_at < ?", (cutoff,))
    await db.execute("DELETE FROM anomaly_alerts WHERE detected_at < ?", (cutoff,))
    await db.execute("DELETE FROM playbook_executions WHERE executed_at < ?", (cutoff,))
    await db.commit()


async def _migrate(db: aiosqlite.Connection):
    cursor = await db.execute("PRAGMA table_info(ip_intel)")
    columns = {row[1] for row in await cursor.fetchall()}
    if "shodan_data" not in columns:
        await db.execute("ALTER TABLE ip_intel ADD COLUMN shodan_data TEXT")
    if "virustotal_data" not in columns:
        await db.execute("ALTER TABLE ip_intel ADD COLUMN virustotal_data TEXT")
    if "censys_data" not in columns:
        await db.execute("ALTER TABLE ip_intel ADD COLUMN censys_data TEXT")

    # Add service_port columns for port-independent service tracking
    for table in ("ssh_events", "http_events", "brute_force_sessions"):
        cursor = await db.execute(f"PRAGMA table_info({table})")
        cols = {row[1] for row in await cursor.fetchall()}
        if "service_port" not in cols:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN service_port INTEGER")

    # Add evidence columns to nuclei_findings
    cursor = await db.execute("PRAGMA table_info(nuclei_findings)")
    nf_cols = {row[1] for row in await cursor.fetchall()}
    if nf_cols:  # table exists
        for col, coltype in (
            ("protocol", "TEXT DEFAULT ''"),
            ("ip", "TEXT DEFAULT ''"),
            ("request", "TEXT DEFAULT ''"),
            ("response", "TEXT DEFAULT ''"),
            ("extracted_results", "TEXT DEFAULT ''"),
        ):
            if col not in nf_cols:
                await db.execute(f"ALTER TABLE nuclei_findings ADD COLUMN {col} {coltype}")

    # Add ua_class column to http_events
    cursor = await db.execute("PRAGMA table_info(http_events)")
    http_cols = {row[1] for row in await cursor.fetchall()}
    if "ua_class" not in http_cols:
        await db.execute("ALTER TABLE http_events ADD COLUMN ua_class TEXT DEFAULT ''")

    # Add event_count columns for deduplication
    for table in ("ssh_events", "http_events"):
        cursor = await db.execute(f"PRAGMA table_info({table})")
        cols = {row[1] for row in await cursor.fetchall()}
        if "event_count" not in cols:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN event_count INTEGER NOT NULL DEFAULT 1")

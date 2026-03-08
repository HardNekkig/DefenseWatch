#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INTERACTIVE=true
if [[ "${1:-}" == "--no-interactive" ]]; then
    INTERACTIVE=false
fi

echo "=== DefenseWatch Setup ==="
echo ""

# ── Python check ──────────────────────────────────────────────────────
PYTHON=""
for cmd in python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.11+ is required but not found."
    echo "Install it with: sudo apt install python3"
    exit 1
fi

PY_VERSION=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$("$PYTHON" -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$("$PYTHON" -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    echo "ERROR: Python 3.11+ is required (found $PY_VERSION)."
    exit 1
fi

echo "[+] Using Python $PY_VERSION ($PYTHON)"

# ── Virtual environment ───────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    if ! "$PYTHON" -m venv venv 2>/dev/null; then
        echo "ERROR: Failed to create venv. You may need: sudo apt install python3-venv"
        exit 1
    fi
else
    echo "[+] Virtual environment already exists"
fi

echo "[+] Installing dependencies..."
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -r requirements.txt

# ── Data directory ────────────────────────────────────────────────────
mkdir -p data

# ── Config file ───────────────────────────────────────────────────────
if [ ! -f "config.yaml" ]; then
    echo "[+] Creating config.yaml from template..."
    cat > config.yaml << 'YAML'
server:
  host: 127.0.0.1
  port: 9000
logs:
  ssh:
  - path: /var/log/auth.log
    port: 22
  http:
  - path: /var/log/nginx/access.log
    port: 443
  mysql: []
  postgresql: []
  mail: []
  ftp: []
detection:
  ssh_brute_threshold: 5
  ssh_brute_window_seconds: 300
  http_scan_threshold: 20
  http_scan_window_seconds: 60
  portscan_threshold: 3
  portscan_window_seconds: 300
geoip:
  mmdb_path: data/GeoLite2-City.mmdb
  fallback_api: http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,asname,reverse
  re_enrich_after_days: 7
host:
  name: my-server
  latitude: 0.0
  longitude: 0.0
database:
  path: data/defensewatch.db
  wal_mode: true
  retention_days: 30
enrichment:
  max_queue_size: 1000
  worker_count: 3
  whois_enabled: true
notifications:
  enabled: false
  webhook_url: ''
  min_severity: high
  cooldown_seconds: 300
  notify_events:
  - brute_force
  - http_attack
  - anomaly
  - firewall_block
telegram:
  enabled: false
  bot_token: ''
  chat_ids: []
  min_severity: high
  cooldown_seconds: 300
  notify_events:
  - brute_force
  - http_attack
  - firewall_block
  daily_reports: false
  weekly_reports: false
  report_hour: 9
threat_intel:
  enabled: false
  refresh_interval_hours: 6
  abuseipdb_api_key: ''
  otx_api_key: ''
reports:
  enabled: false
  interval_hours: 24
  webhook_url: ''
nuclei:
  enabled: false
  docker_image: projectdiscovery/nuclei:latest
  severity_filter: low,medium,high,critical
  rate_limit: 150
  timeout_minutes: 30
  extra_args: []
firewall:
  auto_block_enabled: false
  ssh_block_threshold: 20
  brute_session_block_threshold: 3
  http_block_threshold: 100
  score_block_threshold: 70
  auto_block_window_seconds: 3600
  auto_block_duration_hours: 0
  check_interval_seconds: 300
  whitelist:
  - 127.0.0.1
  - '::1'
external_apis:
  shodan_api_key: ''
  virustotal_api_key: ''
  censys_api_id: ''
  censys_api_secret: ''
YAML
    echo "    Created config.yaml with default settings."
    echo "    IMPORTANT: Edit config.yaml to customize:"
    echo "      - Log file paths (check /var/log/ for your system)"
    echo "      - Server name and GPS coordinates for the attack map"
    echo "      - Detection thresholds and firewall settings"
    echo "    See config.yaml.example for all available options."
else
    echo "[+] config.yaml already exists"
fi

# ── .env file ─────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "[+] Creating .env from .env.example..."
        cp .env.example .env
        echo "    Created .env file for secrets."
        echo "    OPTIONAL: Add API keys and tokens to .env for enhanced features:"
        echo "      - Shodan, VirusTotal, Censys (IP enrichment)"
        echo "      - AbuseIPDB, OTX (threat intelligence)"
        echo "      - Telegram bot (notifications and reports)"
        echo "      - Webhook URLs (Slack, Discord, etc.)"
    else
        echo "[!] No .env.example found, skipping .env creation."
    fi
else
    echo "[+] .env already exists"
fi

# ── GeoLite2 database ────────────────────────────────────────────────
MMDB="data/GeoLite2-City.mmdb"
if [ ! -f "$MMDB" ]; then
    echo ""
    echo "[!] GeoLite2 database not found."
    echo "    For local GeoIP lookups, download GeoLite2-City.mmdb from:"
    echo "      https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "    and place it at: $MMDB"
    echo "    The system will use ip-api.com as a fallback."
fi

# ── Log file access check ────────────────────────────────────────────
echo ""
echo "[+] Checking log file access..."
LOGS_OK=true

# Read configured log paths from config.yaml
LOG_PATHS=$(venv/bin/python3 -c "
import yaml
with open('config.yaml') as f:
    c = yaml.safe_load(f) or {}
logs = c.get('logs', {})
for svc in ('ssh', 'http', 'mysql', 'postgresql', 'mail', 'ftp'):
    for entry in logs.get(svc, []):
        if isinstance(entry, dict):
            print(entry.get('path', ''))
        elif isinstance(entry, str):
            print(entry)
" 2>/dev/null || echo "/var/log/auth.log")

while IFS= read -r logfile; do
    [ -z "$logfile" ] && continue
    if [ -f "$logfile" ]; then
        if [ -r "$logfile" ]; then
            echo "    $logfile - readable"
        else
            echo "    $logfile - NOT readable (add user to 'adm' group: sudo usermod -aG adm $USER)"
            LOGS_OK=false
        fi
    else
        echo "    $logfile - not found (skipping)"
    fi
done <<< "$LOG_PATHS"

if [ "$LOGS_OK" = false ]; then
    echo ""
    echo "[!] Some log files are not readable. You may need to:"
    echo "    sudo usermod -aG adm $USER"
    echo "    Then log out and back in."
fi

# ── Firewall capability check ────────────────────────────────────────
echo ""
echo "[+] Checking firewall capabilities..."
if command -v ufw &>/dev/null; then
    echo "    ufw found"
    if sudo -n ufw status &>/dev/null 2>&1; then
        echo "    sudo access for ufw: yes"
    else
        echo "    sudo access for ufw: no (auto-block will not work without passwordless sudo)"
        echo "    To enable, add to /etc/sudoers.d/defensewatch:"
        echo "      $USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw"
    fi
elif command -v iptables &>/dev/null; then
    echo "    iptables found (ufw not available)"
else
    echo "    No firewall tool found (ufw or iptables required for auto-block)"
fi

# ── Docker check (for Nuclei scanner) ────────────────────────────────
echo ""
echo "[+] Checking Docker (for Nuclei vulnerability scanner)..."
if command -v docker &>/dev/null; then
    if docker info &>/dev/null 2>&1; then
        echo "    Docker available"
        echo "    Pre-pulling Nuclei image..."
        docker pull projectdiscovery/nuclei:latest --quiet 2>/dev/null || echo "    Could not pull Nuclei image (pull manually: docker pull projectdiscovery/nuclei:latest)"
    else
        echo "    Docker installed but not accessible (add user to docker group: sudo usermod -aG docker $USER)"
    fi
else
    echo "    Docker not found (Nuclei scanner will be unavailable)"
fi

# ── Systemd service ──────────────────────────────────────────────────
echo ""
if [ "$INTERACTIVE" = true ]; then
    read -rp "[?] Install systemd service? [y/N] " INSTALL_SERVICE
    if [[ "$INSTALL_SERVICE" =~ ^[Yy]$ ]]; then
        # Read host/port from config.yaml
        SVC_HOST=$(venv/bin/python3 -c "
import yaml
with open('config.yaml') as f:
    c = yaml.safe_load(f)
print(c.get('server', {}).get('host', '127.0.0.1'))
" 2>/dev/null || echo "127.0.0.1")
        SVC_PORT=$(venv/bin/python3 -c "
import yaml
with open('config.yaml') as f:
    c = yaml.safe_load(f)
print(c.get('server', {}).get('port', 9000))
" 2>/dev/null || echo "9000")

        # Generate service file with correct paths, user, and config values
        SERVICE_FILE="/etc/systemd/system/defensewatch.service"
        sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=DefenseWatch Host Intrusion Detection System
After=network.target

[Service]
Type=simple
User=$USER
Group=adm
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/venv/bin/uvicorn defensewatch.main:app --host $SVC_HOST --port $SVC_PORT
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload
        sudo systemctl enable defensewatch
        echo "    Service installed and enabled."
        echo "    Start with: sudo systemctl start defensewatch"
        echo "    Logs:       sudo journalctl -u defensewatch -f"
    fi
else
    echo "[i] Skipping systemd service install (non-interactive mode)"
    echo "    To install manually: sudo cp defensewatch.service /etc/systemd/system/"
fi

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete ==="
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "REQUIRED: Configure DefenseWatch before first run"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Edit config.yaml (REQUIRED):"
echo "   - Set your log file paths (SSH, HTTP, etc.)"
echo "   - Set your server coordinates for the attack map"
echo "   - Adjust detection thresholds if needed"
echo "   - Add trusted IPs to firewall whitelist"
echo ""
echo "2. Edit .env (OPTIONAL but recommended):"
echo "   - Add API keys for enrichment (Shodan, VirusTotal, etc.)"
echo "   - Configure Telegram bot for notifications"
echo "   - Set webhook URLs for alerts"
echo ""
echo "3. Ensure log file access:"
echo "   - Your user must be in the 'adm' group"
echo "   - Run: sudo usermod -aG adm \$USER"
echo "   - Log out and back in for changes to take effect"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "To start DefenseWatch:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  ./run.sh"
echo ""
echo "Then open: http://127.0.0.1:9000"
echo ""
echo "For help finding log paths and coordinates, see README.md"
echo ""

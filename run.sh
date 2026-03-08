#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Validate prerequisites ───────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "ERROR: Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

if [ ! -f "config.yaml" ]; then
    echo "ERROR: config.yaml not found. Run ./setup.sh first."
    exit 1
fi

if [ ! -f ".env" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "WARNING: .env file not found"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "DefenseWatch will start, but enhanced features will be unavailable:"
    echo "  - IP enrichment (Shodan, VirusTotal, Censys)"
    echo "  - Threat intelligence (AbuseIPDB, OTX)"
    echo "  - Telegram notifications"
    echo "  - Webhook alerts"
    echo ""
    echo "To enable these features:"
    echo "  1. cp .env.example .env"
    echo "  2. Edit .env and add your API keys"
    echo "  3. Restart DefenseWatch"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    sleep 3
fi

# ── Read host/port from config.yaml ──────────────────────────────────
HOST=$(venv/bin/python3 -c "
import yaml
with open('config.yaml') as f:
    c = yaml.safe_load(f)
print(c.get('server', {}).get('host', '127.0.0.1'))
" 2>/dev/null || echo "127.0.0.1")

PORT=$(venv/bin/python3 -c "
import yaml
with open('config.yaml') as f:
    c = yaml.safe_load(f)
print(c.get('server', {}).get('port', 9000))
" 2>/dev/null || echo "9000")

echo "Starting DefenseWatch on ${HOST}:${PORT}..."

exec venv/bin/uvicorn defensewatch.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --log-level info

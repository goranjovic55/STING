#!/bin/bash
#
# Honeypot Intelligence Pipeline - Cron Job Script
# Daily analysis and reporting at 06:00 UTC
#

set -e

# Configuration
PIPELINE_DIR="/root/honeypot-intel"
SRC_DIR="${PIPELINE_DIR}/src"
LOG_DIR="${PIPELINE_DIR}/logs"
DATA_DIR="${PIPELINE_DIR}/data"
CONFIG_FILE="${PIPELINE_DIR}/config/pipeline.conf"

# Logging
LOG_FILE="${LOG_DIR}/cron.log"
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Ensure directories exist
mkdir -p "${LOG_DIR}" "${DATA_DIR}"

# Logging function
log() {
    echo "[${TIMESTAMP}] $1" | tee -a "${LOG_FILE}"
}

log "========================================"
log "Honeypot Intelligence Daily Analysis"
log "========================================"

# Check if running at correct time (06:00 UTC)
CURRENT_HOUR=$(date -u '+%H')
if [ "${CURRENT_HOUR}" != "06" ]; then
    log "Warning: Not running at 06:00 UTC (current: ${CURRENT_HOUR}:00)"
fi

# Load environment variables from .env file if present
if [ -f "${PIPELINE_DIR}/.env" ]; then
    log "Loading environment from .env file"
    set -a
    source "${PIPELINE_DIR}/.env"
    set +a
fi

# Check Python and dependencies
if ! command -v python3 &> /dev/null; then
    log "ERROR: python3 not found"
    exit 1
fi

# Verify source files exist
if [ ! -f "${SRC_DIR}/main.py" ]; then
    log "ERROR: main.py not found in ${SRC_DIR}"
    exit 1
fi

cd "${SRC_DIR}"

# Step 1: Process last 24 hours of logs
log "Step 1: Processing honeypot logs (last 24h)..."
python3 main.py --mode batch --since 24 --config "${CONFIG_FILE}" >> "${LOG_FILE}" 2>&1
if [ $? -eq 0 ]; then
    log "✓ Log processing completed successfully"
else
    log "✗ Log processing failed with exit code $?"
fi

# Step 2: Generate and send daily summary
log "Step 2: Generating daily summary report..."
python3 main.py --daily-report --config "${CONFIG_FILE}" >> "${LOG_FILE}" 2>&1
if [ $? -eq 0 ]; then
    log "✓ Daily report sent successfully"
else
    log "✗ Failed to send daily report"
fi

# Step 3: Archive old events (older than 7 days)
log "Step 3: Archiving old events..."
ARCHIVE_DATE=$(date -u -d '7 days ago' '+%Y%m%d')
ARCHIVE_FILE="${PIPELINE_DIR}/archive/events_${ARCHIVE_DATE}.jsonl"

if [ -f "${ARCHIVE_FILE}" ]; then
    log "  Archive already exists: ${ARCHIVE_FILE}"
else
    # Run archive operation via Python
    python3 -c "
import sys
sys.path.insert(0, '${SRC_DIR}')
from storage import Storage
import logging
logging.basicConfig(level=logging.INFO)
storage = Storage('${DATA_DIR}/honeypot.db', '${PIPELINE_DIR}/archive')
from datetime import datetime, timedelta
archive_date = datetime.utcnow() - timedelta(days=7)
filepath = storage.archive_events(archive_date)
print(f'Archived to: {filepath}')
" >> "${LOG_FILE}" 2>&1
    log "✓ Archive completed"
fi

# Step 4: Database maintenance (VACUUM)
log "Step 4: Database maintenance..."
sqlite3 "${DATA_DIR}/honeypot.db" "VACUUM;" 2>/dev/null
if [ $? -eq 0 ]; then
    DB_SIZE=$(du -h "${DATA_DIR}/honeypot.db" | cut -f1)
    log "✓ Database optimized (size: ${DB_SIZE})"
else
    log "⚠ Database vacuum failed or sqlite3 not available"
fi

# Step 5: Generate statistics
log "Step 5: Generating statistics..."
python3 -c "
import sys
sys.path.insert(0, '${SRC_DIR}')
from storage import Storage
import json
import logging
logging.basicConfig(level=logging.INFO)
storage = Storage('${DATA_DIR}/honeypot.db', '${PIPELINE_DIR}/archive')
stats = storage.get_daily_stats()
print(json.dumps(stats, indent=2))
" > "${LOG_DIR}/daily_stats_$(date -u '+%Y%m%d').json"
log "✓ Statistics saved to ${LOG_DIR}/daily_stats_$(date -u '+%Y%m%d').json"

# Cleanup old log files (keep 30 days)
log "Step 6: Cleaning up old log files..."
find "${LOG_DIR}" -name "daily_stats_*.json" -mtime +30 -delete 2>/dev/null
find "${LOG_DIR}" -name "*.log" -mtime +30 -delete 2>/dev/null
log "✓ Cleanup completed"

log "========================================"
log "Daily analysis completed"
log "========================================"

# Optional: Health check notification
# Uncomment and configure for health monitoring
# curl -s -X POST "https://hc-ping.com/YOUR-UUID" > /dev/null

exit 0

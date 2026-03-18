#!/usr/bin/env bash
# Panopticon Launcher — one-click start
set -euo pipefail

PROJECT_DIR="$HOME/The-Big-Project/The-Big-Project"
VENV_DIR="$PROJECT_DIR/.venv"
LOG_FILE="$PROJECT_DIR/panopticon.log"
PID_FILE="$PROJECT_DIR/panopticon.pid"
URL="http://127.0.0.1:8420"

# If already running, just open the browser
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    notify-send "Panopticon" "Already running — opening browser" -i network-server
    xdg-open "$URL" &
    exit 0
fi

# Activate venv
source "$VENV_DIR/bin/activate"
cd "$PROJECT_DIR"

# Run migrations (fast no-op if already current)
alembic upgrade head >> "$LOG_FILE" 2>&1

# Start server in background
nohup python3 -m netsec >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

# Wait for server to be ready (up to 15s)
notify-send "Panopticon" "Starting server..." -i network-server
for i in $(seq 1 30); do
    if curl -s --max-time 1 "$URL/api/overview/" > /dev/null 2>&1; then
        notify-send "Panopticon" "Server ready on port 8420" -i network-server
        xdg-open "$URL" &
        exit 0
    fi
    sleep 0.5
done

notify-send "Panopticon" "Server failed to start — check $LOG_FILE" -i dialog-error
exit 1

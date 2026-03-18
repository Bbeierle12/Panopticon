#!/usr/bin/env bash
# Panopticon Stop
PID_FILE="$HOME/The-Big-Project/The-Big-Project/panopticon.pid"

if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        notify-send "Panopticon" "Server stopped" -i network-server 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
else
    pkill -f "python3 -m netsec" 2>/dev/null || true
    notify-send "Panopticon" "Server stopped" -i network-server 2>/dev/null || true
fi

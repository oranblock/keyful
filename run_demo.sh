#!/bin/bash
# 🚀 1-Click Interactive Demo Launcher for QVault 5 Mobile
PORT=8099
DEMO_DIR="$(dirname "$0")/demo"

echo "=================================================================="
echo " 🔐 QVAULT 5 MOBILE - INTERACTIVE COMPOSE PROTOTYPE & DEMO"
echo "=================================================================="
echo " Launching local demo server on port $PORT..."
echo " Open in your browser: http://localhost:$PORT"
echo " Press Ctrl+C to stop the server."
echo "=================================================================="

cd "$DEMO_DIR" && python3 -m http.server $PORT

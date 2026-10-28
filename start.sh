#!/bin/zsh
cd "$(dirname "$0")/.."
python3 backend/server.py &
cloudflared tunnel --url http://127.0.0.1:8787 --no-autoupdate

#!/bin/sh
set -eu

APP_PORT="${PORT:-8000}"
export ZTNA_API_PORT="$APP_PORT"

exec uvicorn app.main:app --host 0.0.0.0 --port "$APP_PORT"

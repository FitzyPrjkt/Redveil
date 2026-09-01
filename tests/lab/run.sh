#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export FLASK_APP=app.py
export FLASK_ENV=development
exec python3 app.py
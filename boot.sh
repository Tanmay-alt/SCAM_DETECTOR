#!/bin/sh
# boot.sh (Updated for both local development and production)

set -e

# This command runs migrations every time, which is safe.
flask db upgrade

# When running locally, the PORT variable won't be set, so it defaults to 5000.
# On Render, Render sets the PORT variable automatically.
# The --reload flag tells Gunicorn to restart when it detects code changes.
exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 8 --timeout 0 --reload "app:app"
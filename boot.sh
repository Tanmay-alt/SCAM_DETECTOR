#!/bin/sh
# boot.sh (update the last line)

set -e

# This command stays the same
flask db upgrade

# This command is updated to use the PORT environment variable
exec gunicorn --bind 0.0.0.0:$PORT "app:app"
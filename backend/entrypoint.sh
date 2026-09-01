#!/usr/bin/env bash
# Waits for PostgreSQL, applies migrations, then starts the API.
set -euo pipefail

echo "Waiting for PostgreSQL…"
until python -c "
import sys, psycopg2
from app.core.config import settings
url = settings.DATABASE_URL.replace('postgresql+psycopg2', 'postgresql')
try:
    psycopg2.connect(url).close()
except Exception as exc:
    print(exc); sys.exit(1)
" 2>/dev/null; do
  sleep 2
done
echo "PostgreSQL is ready."

echo "Applying database migrations…"
alembic upgrade head

if [ "${SEED_DEMO_ON_START:-false}" = "true" ]; then
  echo "Seeding the demonstration dataset…"
  python -m app.cli seed-demo || echo "Seeding skipped."
fi

exec "$@"

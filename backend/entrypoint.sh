#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "Starting FixNex"
echo "========================================"

# ==================================================
# FAST STARTUP
# ==================================================

echo "OWASP ZAP is disabled."
echo "Starting FixNex API directly."

# ==================================================
# DATABASE
# ==================================================
#
# Do not wait for PostgreSQL here.
# FastAPI handles database connectivity.
#
# Run Alembic migrations separately during deployment.
# ==================================================

echo "Skipping startup database wait."
echo "Skipping startup Alembic migration."

# ==================================================
# OPTIONAL DEMO SEED
# ==================================================

if [ "${SEED_DEMO_ON_START:-false}" = "true" ]; then
    echo "Demo seed requested."
    echo "Skipping demo seed during fast startup."
fi

# ==================================================
# START FIXNEX API
# ==================================================

echo "========================================"
echo "Starting FixNex API immediately..."
echo "========================================"

exec "$@"
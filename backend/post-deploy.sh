#!/bin/bash
# Post-deployment verification script for Render

set -e

BACKEND_URL="${RENDER_EXTERNAL_URL:-http://localhost:8000}"

echo "🚀 Running post-deployment verification..."
echo "Backend URL: $BACKEND_URL"

# Check health endpoint
echo "Checking /health endpoint..."
if curl -sf "$BACKEND_URL/health" > /dev/null; then
  echo "✓ Health check passed"
else
  echo "❌ Health check failed"
  exit 1
fi

# Check API docs
echo "Checking /api/docs endpoint..."
if curl -sf "$BACKEND_URL/api/docs" > /dev/null; then
  echo "✓ API docs accessible"
else
  echo "❌ API docs not accessible"
  exit 1
fi

echo "✅ Post-deployment verification passed!"
echo ""
echo "Next steps:"
echo "1. Run database migrations: alembic upgrade head"
echo "2. Test frontend connectivity"
echo "3. Verify login with demo credentials"

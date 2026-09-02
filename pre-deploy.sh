#!/bin/bash
# Pre-deployment checks for FixNex

set -e

echo "🔍 Running pre-deployment checks..."

# Check backend requirements
echo "✓ Checking backend requirements.txt..."
if ! grep -q "psycopg2-binary" backend/requirements.txt; then
  echo "❌ Missing psycopg2-binary in requirements.txt"
  exit 1
fi

# Check frontend package.json
echo "✓ Checking frontend package.json..."
if ! grep -q "vite" frontend/package.json; then
  echo "❌ Missing vite in package.json"
  exit 1
fi

# Check for .env file
if [ ! -f ".env" ]; then
  echo "⚠️  No .env file found. Create one before deploying."
  exit 1
fi

# Check environment variables
if ! grep -q "DATABASE_URL" .env; then
  echo "❌ DATABASE_URL not set in .env"
  exit 1
fi

if ! grep -q "JWT_SECRET" .env; then
  echo "❌ JWT_SECRET not set in .env"
  exit 1
fi

echo "✅ All pre-deployment checks passed!"
echo ""
echo "Next steps:"
echo "1. git add ."
echo "2. git commit -m 'Deploy: Production-ready FixNex'"
echo "3. git push origin main"

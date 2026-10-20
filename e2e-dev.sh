#!/bin/bash
set -e

current_dir="$(dirname "$(readlink -f "$0")")"

# Configuration - Update these absolute paths for your local environment
CONFIG_DIR="$current_dir/runtime/config"  # Path to config directory (contains settings.json)
DATA_DIR="$current_dir/runtime/data"     # Path to data directory (contains static/ and provider folders)

mkdir -p "$CONFIG_DIR" "$DATA_DIR"
if [[ ! -e "$CONFIG_DIR/settings.json" ]]; then
    cat > "$CONFIG_DIR/settings.json" <<EOF
{
  "baseUrl": "http://localhost:${PWSAFE_PORT:-8080}",
  "providers": {
    "mock": {}
  }
}
EOF
fi

# On first start, visit the UI in your browser to choose an auth mode.
# To skip setup for dev, add "auth": { "mode": "disabled" } to your settings.json.

# This value usually does not need to be changed
STATIC_DIR="$current_dir/frontend/dist" # Path to frontend build output

echo "Building frontend..."
cd "$current_dir/frontend" && npm ci && npm run build

echo "Building e2e..."
cd "$current_dir/e2e" && npm ci

echo "Building backend..."
cd "$current_dir/backend" && go mod download && go build -o pwsafe-service cmd/pwsafe-service/main.go

echo "Stopping any running instance..."
pkill -f pwsafe-service || true

cd "$current_dir/backend"

echo "Starting pwsafe-service..."
PWSAFE_CONFIG_DIR="$CONFIG_DIR" \
PWSAFE_DATA_DIR="$DATA_DIR" \
PWSAFE_STATIC_DIR="$STATIC_DIR" \
"$current_dir/backend/pwsafe-service"

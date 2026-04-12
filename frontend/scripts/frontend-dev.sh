#!/bin/sh
set -eu

APP_DIR="/app"
LOCKFILE="$APP_DIR/package-lock.json"
PACKAGE_JSON="$APP_DIR/package.json"
STAMP_FILE="$APP_DIR/node_modules/.manifest.hash"

compute_manifest_hash() {
  runtime_fingerprint="$(node -p '`${process.platform}-${process.arch}-${process.version}`')"

  if [ -f "$LOCKFILE" ]; then
    printf '%s\n' "$runtime_fingerprint"
    sha256sum "$LOCKFILE" | awk '{ print $1 }'
    return
  fi

  if [ -f "$PACKAGE_JSON" ]; then
    printf '%s\n' "$runtime_fingerprint"
    sha256sum "$PACKAGE_JSON" | awk '{ print $1 }'
    return
  fi

  printf '%s\n%s\n' "$runtime_fingerprint" "missing-manifest"
}

install_dependencies() {
  echo "[frontend-dev] Installing dependencies..."
  mkdir -p "$APP_DIR/node_modules"
  find "$APP_DIR/node_modules" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  npm install --no-fund --no-audit
  mkdir -p "$APP_DIR/node_modules"
  compute_manifest_hash > "$STAMP_FILE"
}

ensure_dependencies() {
  current_hash="$(compute_manifest_hash)"
  saved_hash=""

  if [ -f "$STAMP_FILE" ]; then
    saved_hash="$(cat "$STAMP_FILE")"
  fi

  if [ ! -d "$APP_DIR/node_modules" ] || [ "$current_hash" != "$saved_hash" ]; then
    install_dependencies
  fi
}

watch_manifests() {
  last_hash="$(compute_manifest_hash)"

  while sleep 2; do
    next_hash="$(compute_manifest_hash)"

    if [ "$next_hash" != "$last_hash" ]; then
      echo "[frontend-dev] package manifest changed. Reinstalling dependencies..."
      install_dependencies
      last_hash="$(compute_manifest_hash)"
    fi
  done
}

cd "$APP_DIR"
ensure_dependencies
watch_manifests &

exec npm run dev -- --host 0.0.0.0 --port 5173

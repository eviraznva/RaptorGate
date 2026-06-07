#!/usr/bin/env bash
set -e

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")
export PATH="$REAL_HOME/.local/share/mise/installs/bun/latest/bin:$REAL_HOME/.bun/bin:$PATH"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

cd ..
docker compose up app_build --build || exit 1

rm /tmp/*-ssh-config.txt || true
# 1. Deploy VMs without the backend service
cd "$SCRIPT_DIR/../vagrant" && ./deploy.sh --no-backend || true

# 2. Generate proto bindings and run tests
cd "$SCRIPT_DIR" && bun run generate && bun test --max-concurrency=1

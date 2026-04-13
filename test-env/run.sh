#!/usr/bin/env bash
set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# 1. Deploy VMs without the backend service
cd "$SCRIPT_DIR/../vagrant" && ./deploy.sh --no-backend || true

# 2. Generate proto bindings and run tests
cd "$SCRIPT_DIR" && bun run generate && bun test

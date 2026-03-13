#!/usr/bin/env bash
PROJECT_NAME="${PROJECT_NAME:-ngfw}"

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR/.."

# project name (can be overridden from environment)

docker compose up --build || exit 1

cd "$SCRIPT_DIR"
mkdir -p .router_sync/"$PROJECT_NAME"
rm -rf .router_sync/proto && mkdir -p .router_sync/proto
cp -f ../bin/"$PROJECT_NAME" .router_sync/"$PROJECT_NAME"/"$PROJECT_NAME"
cp -rf ../proto/* .router_sync/proto/
cp -rf services .router_sync
vagrant up --provision

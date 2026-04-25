#!/usr/bin/env bash
PROJECT_NAME="${PROJECT_NAME:-ngfw}"
LIBVIRT_DEFAULT_URI=qemu:///system

set -e

# Parse flags
if [[ "$1" == "--no-backend" || "$1" == "-n" ]]; then
  export NO_BACKEND=1
fi

sudo sysctl -w net.ipv4.ip_forward=1

# 2. Allow virbr1 traffic through Docker's FORWARD chain
sudo iptables -I FORWARD 1 -i virbr1 -j ACCEPT
sudo iptables -I FORWARD 1 -o virbr1 -m state --state RELATED,ESTABLISHED -j ACCEPT

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR/.."

# project name (can be overridden from environment)
MODEL_NAME="${MODEL_NAME:-raptorgate-cicids2017-v4-focal}"
MODEL_SRC="${MODEL_SRC:-ml_pipeline/data/models}"

# cd "$SCRIPT_DIR/../backend" && bun run proto:generate || exit 1
cd "$SCRIPT_DIR/.."
docker compose up --build || exit 1

test -d bin/backend/node_modules/@nestjs/websockets || {
  echo "backend artifact is missing @nestjs/websockets; rebuild backend_build failed or produced stale bin/backend" >&2
  exit 1
}

grep -q 'module-alias/register' bin/backend/dist/src/main.js || {
  echo "backend artifact is missing module-alias/register; rebuild backend_build produced stale dist" >&2
  exit 1
}

test -f bin/frontend/dist/index.html || {
  echo "frontend artifact is missing dist/index.html; rebuild frontend_build failed or produced stale bin/frontend" >&2
  exit 1
}

cd "$SCRIPT_DIR"
mkdir -p .router_sync/"$PROJECT_NAME"
test -f ../"$MODEL_SRC"/"$MODEL_NAME".onnx || {
  echo "ML model is missing: $MODEL_SRC/$MODEL_NAME.onnx" >&2
  exit 1
}
test -f ../"$MODEL_SRC"/"$MODEL_NAME".onnx.data || {
  echo "ML model external data is missing: $MODEL_SRC/$MODEL_NAME.onnx.data" >&2
  exit 1
}
test -f ../"$MODEL_SRC"/"$MODEL_NAME".onnx.json || {
  echo "ML model metadata is missing: $MODEL_SRC/$MODEL_NAME.onnx.json" >&2
  exit 1
}
rm -rf .router_sync/backend && mkdir -p .router_sync/backend
rm -rf .router_sync/frontend && mkdir -p .router_sync/frontend
rm -rf .router_sync/proto && mkdir -p .router_sync/proto
rm -rf .router_sync/logrotate && mkdir -p .router_sync/logrotate
rm -rf .router_sync/nginx && mkdir -p .router_sync/nginx
rm -rf .router_sync/vector && mkdir -p .router_sync/vector
rm -rf .router_sync/"$PROJECT_NAME"/ml && mkdir -p .router_sync/"$PROJECT_NAME"/ml
cp -f ../bin/"$PROJECT_NAME" .router_sync/"$PROJECT_NAME"/"$PROJECT_NAME"
cp -f \
  ../"$MODEL_SRC"/"$MODEL_NAME".onnx \
  ../"$MODEL_SRC"/"$MODEL_NAME".onnx.data \
  ../"$MODEL_SRC"/"$MODEL_NAME".onnx.json \
  .router_sync/"$PROJECT_NAME"/ml/
cp -rf ../bin/backend/* .router_sync/backend/
rm -rf .router_sync/backend/data/json-db
mkdir -p .router_sync/backend/data
cp -rf ../backend/data/json-db .router_sync/backend/data/
cp -rf ../bin/frontend/dist .router_sync/frontend/
cd "$SCRIPT_DIR"
rm -rf .router_sync/backend/devCerts && mkdir -p .router_sync/backend/devCerts
cp -rf ../backend/devCerts/* .router_sync/backend/devCerts/
rm -rf .router_sync/backend/data && mkdir -p .router_sync/backend/data
cp -rf ../backend/data/* .router_sync/backend/data/
cp -rf ../proto/* .router_sync/proto/
cp -rf ./configs/* .router_sync/ngfw
cp -rf services .router_sync
cp -rf nginx/* .router_sync/nginx/
cp -rf logrotate/* .router_sync/logrotate/
cp -rf vector/* .router_sync/vector/

R1_STATE="$(vagrant status r1 --machine-readable | awk -F, '$3=="state"{print $4}' | tail -n1)"

if [ "$R1_STATE" = "running" ]; then
  vagrant rsync r1
else
  echo "r1 is not running yet; skipping rsync and relying on vagrant up for initial sync"
fi
vagrant up --provision

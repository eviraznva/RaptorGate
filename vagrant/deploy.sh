#!/usr/bin/env bash
PROJECT_NAME="${PROJECT_NAME:-ngfw}"
LIBVIRT_DEFAULT_URI=qemu:///system

set -e

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  echo "Do not run this script with sudo; it invokes sudo only for host-level setup." >&2
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

for work_dir in "$SCRIPT_DIR/.vagrant" "$SCRIPT_DIR/.router_sync"; do
  if [ -e "$work_dir" ]; then
    sudo chown -R "$(id -u):$(id -g)" "$work_dir"
  fi
done

ensure_iptables_rule() {
  local chain="$1"
  shift

  sudo iptables -C "$chain" "$@" 2>/dev/null || sudo iptables -I "$chain" 1 "$@"
}

# Parse flags
if [[ "$1" == "--no-backend" || "$1" == "-n" ]]; then
  export NO_BACKEND=1
fi

sudo sysctl -w net.ipv4.ip_forward=1

# 2. Allow virbr1 traffic through Docker's FORWARD chain
ensure_iptables_rule FORWARD -i virbr1 -j ACCEPT
ensure_iptables_rule FORWARD -o virbr1 -m state --state RELATED,ESTABLISHED -j ACCEPT
ensure_iptables_rule INPUT -i virbr0 -p udp --dport 67 -j ACCEPT
ensure_iptables_rule INPUT -i virbr0 -p udp --dport 53 -j ACCEPT
ensure_iptables_rule INPUT -i virbr0 -p tcp --dport 53 -j ACCEPT
ensure_iptables_rule INPUT -i virbr1 -p udp --dport 67 -j ACCEPT
ensure_iptables_rule INPUT -i virbr1 -p udp --dport 53 -j ACCEPT
ensure_iptables_rule INPUT -i virbr1 -p tcp --dport 53 -j ACCEPT

cd "$SCRIPT_DIR/.."

# project name (can be overridden from environment)

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
rm -rf .router_sync/backend && mkdir -p .router_sync/backend
rm -rf .router_sync/frontend && mkdir -p .router_sync/frontend
rm -rf .router_sync/proto && mkdir -p .router_sync/proto
rm -rf .router_sync/logrotate && mkdir -p .router_sync/logrotate
rm -rf .router_sync/nginx && mkdir -p .router_sync/nginx
rm -rf .router_sync/vector && mkdir -p .router_sync/vector
cp -f ../bin/"$PROJECT_NAME" .router_sync/"$PROJECT_NAME"/"$PROJECT_NAME"
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

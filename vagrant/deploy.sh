#!/usr/bin/env bash
PROJECT_NAME="${PROJECT_NAME:-ngfw}"
LIBVIRT_DEFAULT_URI=qemu:///system

set -e

sudo sysctl -w net.ipv4.ip_forward=1

# 2. Allow virbr1 traffic through Docker's FORWARD chain
sudo iptables -I FORWARD 1 -i virbr1 -j ACCEPT
sudo iptables -I FORWARD 1 -o virbr1 -m state --state RELATED,ESTABLISHED -j ACCEPT

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR/.."

# project name (can be overridden from environment)

docker compose up --build || exit 1

cd "$SCRIPT_DIR"
mkdir -p .router_sync/"$PROJECT_NAME"
rm -rf .router_sync/backend && mkdir -p .router_sync/backend
rm -rf .router_sync/proto && mkdir -p .router_sync/proto
cp -f ../bin/"$PROJECT_NAME" .router_sync/"$PROJECT_NAME"/"$PROJECT_NAME"
cp -rf ../bin/backend/* .router_sync/backend/
cp -rf ../proto/* .router_sync/proto/
cp -rf services .router_sync

vagrant rsync r1 || true
vagrant up --provision

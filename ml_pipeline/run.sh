#!/usr/bin/env bash
set -euo pipefail

# Default to skipping the dataset download — the on-disk /data/raw/ is the
# source of truth. Override by exporting SKIP_DOWNLOAD=0 (forces a fresh
# download even when the data exists; failures surface during build/train).
export SKIP_DOWNLOAD="${SKIP_DOWNLOAD:-1}"
export DATASET="${DATASET:-cicids2017}"

# Rust + Python build-time debug logs (set to 0 to silence).
export RG_LIB_DEBUG="${RG_LIB_DEBUG:-1}"
export RG_FEATURES_DEBUG="${RG_FEATURES_DEBUG:-1}"
export RG_MATCH_DEBUG="${RG_MATCH_DEBUG:-1}"
export RAPTORGATE_PIPELINE_DEBUG="${RAPTORGATE_PIPELINE_DEBUG:-1}"

cd "$(dirname "$0")"
docker compose build pipeline &&
docker compose --profile rocm run --rm pipeline

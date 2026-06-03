#!/usr/bin/env bash
# Entrypoint for the docker-compose "pipeline" service. Reads env vars and
# runs the download → build → train → evaluate chain, skipping any step whose
# output already exists. Idempotent: re-runs pick up where the last run left
# off.
#
# Env vars (all optional; sensible defaults):
#   DATASET            cicids2017 | cicids2018 | unsw_nb15  (default: cicids2017)
#   RAW_DIR            target dir for downloads             (default: /data/raw)
#   LABELS_DIR         label dir for build                  (default: $RAW_DIR/GeneratedLabelledFlows)
#   TRAIN_PARQUET      output of build                      (default: /data/train.parquet)
#   TEST_PARQUET       output of build                      (default: /data/test.parquet)
#   MODEL_PATH         output of train                      (default: /data/model.onnx)
#   METADATA_PATH      output of train                      (default: $MODEL_PATH.json)
#   EVAL_PARQUET       parquet for evaluate                 (default: $TEST_PARQUET)
#   EVAL_REPORT        output of evaluate                   (default: /data/eval.json)
#   SKIP_DOWNLOAD      set to 1 to skip                     (default: 0)
#   SKIP_BUILD         set to 1 to skip                     (default: 0)
#   SKIP_TRAIN         set to 1 to skip                     (default: 0)
#   SKIP_EVALUATE      set to 1 to skip                     (default: 0)
#   EPOCHS             training epochs                      (default: 35)
#   BATCH_SIZE         training batch size                  (default: 131072)
#   LEARNING_RATE      training lr                          (default: 3e-4)
#   LOSS               weighted_ce | focal                  (default: focal)
#   FOCAL_GAMMA        focal loss gamma                     (default: 1.5)
#   JOBS               build workers                        (default: 4)
#   DEVICE             auto | cuda | rocm | cpu             (default: auto)
#   AMP                1 | 0                                (default: 1)
#   ACCURACY_GATE      evaluate gate                        (default: 0.8)

set -euo pipefail

DATASET="${DATASET:-cicids2017}"
RAW_DIR="${RAW_DIR:-/data/raw}"
LABELS_DIR="${LABELS_DIR:-$RAW_DIR/GeneratedLabelledFlows}"
TRAIN_PARQUET="${TRAIN_PARQUET:-/data/train.parquet}"
TEST_PARQUET="${TEST_PARQUET:-/data/test.parquet}"
MODEL_PATH="${MODEL_PATH:-/data/model.onnx}"
METADATA_PATH="${METADATA_PATH:-${MODEL_PATH}.json}"
EVAL_PARQUET="${EVAL_PARQUET:-$TEST_PARQUET}"
EVAL_REPORT="${EVAL_REPORT:-/data/eval.json}"
SKIP_DOWNLOAD="${SKIP_DOWNLOAD:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_TRAIN="${SKIP_TRAIN:-0}"
SKIP_EVALUATE="${SKIP_EVALUATE:-0}"
EPOCHS="${EPOCHS:-35}"
BATCH_SIZE="${BATCH_SIZE:-131072}"
LEARNING_RATE="${LEARNING_RATE:-3e-4}"
LOSS="${LOSS:-focal}"
FOCAL_GAMMA="${FOCAL_GAMMA:-1.5}"
JOBS="${JOBS:-4}"
DEVICE="${DEVICE:-auto}"
AMP_FLAG=(--amp)
if [[ "${AMP:-1}" == "0" ]]; then AMP_FLAG=(--no-amp); fi

log() { printf '\n=== %s ===\n' "$*"; }

# Patch torch's bundled HIP libraries so dlopen succeeds on hardened
# kernels (CachyOS bore, Arch linux-hardened). The torch+rocm wheel ships
# libamdhip64.so and libhiprtc.so with PT_GNU_STACK PF_X set; the kernel
# refuses to enable executable stack for them at import time. Clearing
# the flag is a no-op for these libraries (they don't use trampolines).
# Idempotent: skipped entirely if no RWE .so is found.
patch_torch_execstack() {
  local torch_lib=""
  for d in /usr/local/lib/python*/site-packages/torch/lib /opt/conda/lib/python*/site-packages/torch/lib; do
    if [[ -d "$d" ]]; then torch_lib="$d"; break; fi
  done
  [[ -z "$torch_lib" ]] && return 0

  local rwe_files=()
  while IFS= read -r -d '' f; do
    local flags
    flags=$(readelf -lW "$f" 2>/dev/null | awk '/GNU_STACK/{getline; for(i=1;i<=NF;i++) if($i=="RWE"){print "RWE"; exit}}')
    [[ "$flags" == "RWE" ]] && rwe_files+=("$f")
  done < <(find "$torch_lib" -maxdepth 1 -type f -name '*.so*' -not -name '*.hsaco' -print0)

  if [[ ${#rwe_files[@]} -eq 0 ]]; then
    log "torch execstack: no RWE .so found, nothing to patch"
    return 0
  fi

  if ! command -v patchelf >/dev/null 2>&1; then
    log "torch execstack: installing patchelf"
    apt-get update -qq && apt-get install -y -qq patchelf
  fi

  log "torch execstack: clearing PT_GNU_STACK PF_X on ${#rwe_files[@]} file(s)"
  for f in "${rwe_files[@]}"; do
    echo "  $f"
    patchelf --clear-execstack "$f"
  done
}

patch_torch_execstack

if [[ "$SKIP_DOWNLOAD" != "1" ]]; then
  log "download dataset=$DATASET target=$RAW_DIR"
  raptorgate-ml download --dataset "$DATASET" --target "$RAW_DIR"
else
  log "download skipped (SKIP_DOWNLOAD=1)"
fi

if [[ "$SKIP_BUILD" != "1" ]]; then
  if [[ -f "$TRAIN_PARQUET" ]]; then
    log "build skipped (train.parquet exists at $TRAIN_PARQUET)"
  else
    log "build pcap-dir=$RAW_DIR labels-dir=$LABELS_DIR"
    raptorgate-ml build \
      --pcap-dir "$RAW_DIR" \
      --labels-dir "$LABELS_DIR" \
      --out "$TRAIN_PARQUET" \
      --test-out "$TEST_PARQUET" \
      --jobs "$JOBS"
  fi
else
  log "build skipped (SKIP_BUILD=1)"
fi

train_args=(
  --train "$TRAIN_PARQUET"
  --test "$TEST_PARQUET"
  --out "$MODEL_PATH"
  --metadata-out "$METADATA_PATH"
  --epochs "$EPOCHS"
  --batch-size "$BATCH_SIZE"
  --learning-rate "$LEARNING_RATE"
  --loss "$LOSS"
  --focal-gamma "$FOCAL_GAMMA"
  --device "$DEVICE"
  "${AMP_FLAG[@]}"
)

if [[ "$SKIP_TRAIN" != "1" ]]; then
  if [[ -f "$MODEL_PATH" ]]; then
    log "train skipped (model exists at $MODEL_PATH)"
  else
    log "train model=$MODEL_PATH"
    raptorgate-ml train "${train_args[@]}"
  fi
else
  log "train skipped (SKIP_TRAIN=1)"
fi

if [[ "$SKIP_EVALUATE" != "1" ]]; then
  log "evaluate model=$MODEL_PATH parquet=$EVAL_PARQUET"
  eval_args=(--model "$MODEL_PATH" --parquet "$EVAL_PARQUET" --report "$EVAL_REPORT")
  if [[ -n "${ACCURACY_GATE:-}" ]]; then
    eval_args+=(--gate "$ACCURACY_GATE")
  fi
  raptorgate-ml evaluate "${eval_args[@]}"
else
  log "evaluate skipped (SKIP_EVALUATE=1)"
fi

log "done"

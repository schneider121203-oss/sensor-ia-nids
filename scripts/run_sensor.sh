#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG=/etc/sensor-ia-nids/sensor.env
[[ -r "$CONFIG" ]] || { echo "No se puede leer $CONFIG" >&2; exit 1; }
# Archivo propiedad de root generado por install.sh.
# shellcheck disable=SC1090
source "$CONFIG"

required=(CAPTURE_INTERFACE INSTALL_DIR DATA_DIR ALERT_LOG RUN_ID ORDERING_DELAY_MS BATCH_SIZE)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || { echo "Falta $name en $CONFIG" >&2; exit 1; }
done
ip link show "$CAPTURE_INTERFACE" >/dev/null 2>&1 || {
  echo "No existe la interfaz $CAPTURE_INTERFACE" >&2
  exit 1
}

command=(
  "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/app/flow_monitor_v4.py"
  --iface "$CAPTURE_INTERFACE"
  --models-dir "$INSTALL_DIR/models"
  --output-dir "$DATA_DIR"
  --alert-log "$ALERT_LOG"
  --run-id "$RUN_ID"
  --ordering-delay-ms "$ORDERING_DELAY_MS"
  --batch-size "$BATCH_SIZE"
  --device cpu
)
if [[ -n "${BPF_FILTER:-}" ]]; then
  command+=(--bpf-filter "$BPF_FILTER")
fi
exec "${command[@]}"

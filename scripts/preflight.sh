#!/usr/bin/env bash
set -u

IFACE=
MANAGER=
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
errors=0
warnings=0

while (($#)); do
  case "$1" in
    --iface) [[ $# -ge 2 ]] || { echo "[ERROR] Falta valor para --iface"; exit 2; }; IFACE=$2; shift 2 ;;
    --wazuh-manager) [[ $# -ge 2 ]] || { echo "[ERROR] Falta valor para --wazuh-manager"; exit 2; }; MANAGER=$2; shift 2 ;;
    -h|--help) echo "Uso: $0 --iface INTERFAZ --wazuh-manager HOST"; exit 0 ;;
    *) echo "[ERROR] Opción desconocida: $1"; exit 2 ;;
  esac
done

ok() { echo "[OK] $*"; }
error() { echo "[ERROR] $*"; errors=$((errors + 1)); }
warn() { echo "[ADVERTENCIA] $*"; warnings=$((warnings + 1)); }

[[ -n "$IFACE" ]] || error "Falta --iface"
[[ -n "$MANAGER" ]] || error "Falta --wazuh-manager"
if [[ -n "$MANAGER" && ! "$MANAGER" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
  error "Dirección del Wazuh Manager inválida"
  MANAGER=
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]] \
    && ok "Ubuntu 22.04 LTS" || error "Se requiere Ubuntu 22.04 LTS; detectado ${PRETTY_NAME:-desconocido}"
fi

python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
[[ "$python_version" == 3.10 ]] && ok "Python 3.10" || error "Se requiere Python 3.10; detectado ${python_version:-ninguno}"

cpus=$(nproc)
((cpus >= 4)) && ok "$cpus CPU lógicas" || warn "$cpus CPU lógicas; se recomiendan 4"
memory_kib=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
((memory_kib >= 3900000)) && ok "RAM >= 4 GB" || warn "RAM inferior a 4 GB"
disk_kib=$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')
((disk_kib >= 20 * 1024 * 1024)) && ok "Espacio libre >= 20 GiB" || warn "Menos de 20 GiB libres; se recomiendan 40 GB de disco"

if ! command -v ip >/dev/null 2>&1; then
  error "No está disponible el comando ip (paquete iproute2)"
elif [[ -n "$IFACE" ]]; then
  if ip link show "$IFACE" >/dev/null 2>&1; then
    ok "Interfaz existente: $IFACE"
    ip -o addr show dev "$IFACE" scope global | grep -q . \
      && warn "La interfaz SPAN tiene una dirección IP" || ok "Interfaz SPAN sin IP global"
    ip route show default | grep -Eq "dev[[:space:]]+$IFACE([[:space:]]|$)" \
      && error "La interfaz SPAN es la ruta predeterminada" || ok "La ruta predeterminada no usa la NIC SPAN"
  else
    error "No existe la interfaz $IFACE"
  fi
fi

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then
  ok "NTP sincronizado"
else
  warn "No se confirmó sincronización NTP"
fi

if [[ -n "$MANAGER" ]]; then
  if timeout 3 bash -c '</dev/tcp/$1/1514' _ "$MANAGER" 2>/dev/null; then
    ok "Wazuh Manager accesible por TCP/1514"
  else
    warn "No se confirmó TCP/1514 hacia $MANAGER"
  fi
fi

if "$ROOT_DIR/scripts/verify_model.py" --models-dir "$ROOT_DIR/sensor/models" >/dev/null; then
  ok "Modelo v4 congelado e íntegro"
else
  error "El modelo no superó la validación de hashes"
fi

echo "Resumen: $errors errores, $warnings advertencias"
((errors == 0))

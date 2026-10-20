#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR=/opt/sensor-ia-nids
CONFIG_DIR=/etc/sensor-ia-nids
DATA_DIR=/var/lib/sensor-ia-nids
ALERT_DIR=/var/log/ensemble
SERVICE_FILE=/etc/systemd/system/sensor-ia-nids.service
RUN_USER=sensor-nids
RUN_GROUP=sensor-nids

CAPTURE_IFACE=
WAZUH_MANAGER=
AGENT_NAME=sensor-ia-nids-fisi
WAZUH_VERSION=
SKIP_WAZUH_INSTALL=false
NO_START=false
BPF_FILTER=
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  cat <<'EOF'
Uso:
  sudo bash install.sh --iface INTERFAZ --wazuh-manager IP_O_FQDN [opciones]

Obligatorios:
  --iface INTERFAZ          NIC conectada al puerto SPAN; nunca se autodetecta
  --wazuh-manager HOST      IP o FQDN del Wazuh Manager existente

Opciones:
  --agent-name NOMBRE       Nombre del Wazuh Agent
  --wazuh-version VERSION   Versión DEB compatible, por ejemplo 4.14.9-1
  --bpf-filter EXPRESION    Filtro BPF opcional
  --skip-wazuh-install      No instala el agente; configura uno existente si lo hay
  --no-start                Instala y habilita sin iniciar servicios
  -h, --help                Muestra esta ayuda
EOF
}

die() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[OK] $*"; }
warn() { echo "[ADVERTENCIA] $*" >&2; }

while (($#)); do
  case "$1" in
    --iface) [[ $# -ge 2 ]] || die "Falta valor para --iface"; CAPTURE_IFACE=$2; shift 2 ;;
    --wazuh-manager) [[ $# -ge 2 ]] || die "Falta valor para --wazuh-manager"; WAZUH_MANAGER=$2; shift 2 ;;
    --agent-name) [[ $# -ge 2 ]] || die "Falta valor para --agent-name"; AGENT_NAME=$2; shift 2 ;;
    --wazuh-version) [[ $# -ge 2 ]] || die "Falta valor para --wazuh-version"; WAZUH_VERSION=$2; shift 2 ;;
    --bpf-filter) [[ $# -ge 2 ]] || die "Falta valor para --bpf-filter"; BPF_FILTER=$2; shift 2 ;;
    --skip-wazuh-install) SKIP_WAZUH_INSTALL=true; shift ;;
    --no-start) NO_START=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
done

[[ $(id -u) -eq 0 ]] || die "Ejecuta el instalador con sudo"
[[ -n "$CAPTURE_IFACE" ]] || die "--iface es obligatorio"
[[ -n "$WAZUH_MANAGER" ]] || die "--wazuh-manager es obligatorio"
[[ "$CAPTURE_IFACE" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "Nombre de interfaz inválido"
[[ "$WAZUH_MANAGER" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "Dirección del Wazuh Manager inválida"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "Nombre de agente inválido"
[[ -d "$SCRIPT_DIR/sensor" && -d "$SCRIPT_DIR/sensor/models" ]] || die "Repositorio incompleto"

# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]] || \
  die "Este instalador soporta Ubuntu 22.04 LTS; detectado: ${PRETTY_NAME:-desconocido}"

echo "Sensor IA/NIDS v4 — instalación idempotente"
echo "Interfaz SPAN: $CAPTURE_IFACE"
echo "Wazuh Manager: $WAZUH_MANAGER"
if [[ -z "$WAZUH_VERSION" && "$SKIP_WAZUH_INSTALL" == false ]]; then
  warn "No se fijó --wazuh-version; se instalará la disponible en el repositorio. Confirma que el Manager sea igual o más reciente."
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip iproute2 libpcap-dev libpcap0.8 gcc g++ \
  curl gnupg apt-transport-https ca-certificates logrotate
[[ $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') == 3.10 ]] || \
  die "Se requiere Python 3.10, incluido por defecto en Ubuntu 22.04 LTS"
ip link show "$CAPTURE_IFACE" >/dev/null 2>&1 || die "No existe la interfaz $CAPTURE_IFACE"

if ! id "$RUN_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$RUN_USER"
fi

install_wazuh_agent() {
  if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
    info "Wazuh Agent ya está instalado"
    return
  fi
  if [[ "$SKIP_WAZUH_INSTALL" == true ]]; then
    warn "Se omitió la instalación de Wazuh Agent"
    return
  fi

  install -d -m 0755 /usr/share/keyrings
  rm -f /usr/share/keyrings/wazuh.gpg
  curl --fail --silent --show-error https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 0644 /usr/share/keyrings/wazuh.gpg
  printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
    >/etc/apt/sources.list.d/wazuh.list
  apt-get update

  package=wazuh-agent
  [[ -z "$WAZUH_VERSION" ]] || package="wazuh-agent=$WAZUH_VERSION"
  WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y "$package"
  apt-mark hold wazuh-agent >/dev/null
  info "Wazuh Agent instalado y retenido para evitar actualizaciones incompatibles"
}

install_wazuh_agent
"$SCRIPT_DIR/scripts/verify_model.py" --models-dir "$SCRIPT_DIR/sensor/models"

install -d -m 0755 "$INSTALL_DIR/app" "$INSTALL_DIR/models" "$INSTALL_DIR/scripts"
runtime_files=(
  ensemble_predictor.py feature_adapter.py feature_contract.py
  feature_contract_v4_native.py flow_monitor_v4.py
  nfstream_extractor.py nfstream_native_extractor.py
)
for filename in "${runtime_files[@]}"; do
  install -m 0644 "$SCRIPT_DIR/sensor/$filename" "$INSTALL_DIR/app/$filename"
done
install -m 0644 "$SCRIPT_DIR"/sensor/models/* "$INSTALL_DIR/models/"
install -m 0755 "$SCRIPT_DIR/scripts/run_sensor.sh" "$INSTALL_DIR/scripts/run_sensor.sh"
install -m 0755 "$SCRIPT_DIR/scripts/verify_model.py" "$INSTALL_DIR/scripts/verify_model.py"
install -m 0644 "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"

if [[ ! -x "$INSTALL_DIR/venv/bin/python" ]]; then
  python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --disable-pip-version-check --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --requirement "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/scripts/verify_model.py" \
  --models-dir "$INSTALL_DIR/models"

install -d -o root -g "$RUN_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 0750 "$DATA_DIR" "$ALERT_DIR"
touch "$ALERT_DIR/alerts.json"
chown "$RUN_USER:$RUN_GROUP" "$ALERT_DIR/alerts.json"
chmod 0640 "$ALERT_DIR/alerts.json"

{
  printf 'CAPTURE_INTERFACE=%q\n' "$CAPTURE_IFACE"
  printf 'BPF_FILTER=%q\n' "$BPF_FILTER"
  printf 'INSTALL_DIR=%q\n' "$INSTALL_DIR"
  printf 'DATA_DIR=%q\n' "$DATA_DIR"
  printf 'ALERT_LOG=%q\n' "$ALERT_DIR/alerts.json"
  printf 'RUN_ID=%q\n' "fisi-live-$(hostname -s)"
  printf 'ORDERING_DELAY_MS=6000\nBATCH_SIZE=100\n'
} >"$CONFIG_DIR/sensor.env"
chown root:"$RUN_GROUP" "$CONFIG_DIR/sensor.env"
chmod 0640 "$CONFIG_DIR/sensor.env"

install -m 0644 "$SCRIPT_DIR/deploy/systemd/sensor-ia-nids.service" "$SERVICE_FILE"
install -m 0644 "$SCRIPT_DIR/deploy/logrotate/sensor-ia-nids" /etc/logrotate.d/sensor-ia-nids

if [[ -f /var/ossec/etc/ossec.conf ]]; then
  python3 "$SCRIPT_DIR/scripts/configure_wazuh_agent.py" \
    --config /var/ossec/etc/ossec.conf --manager "$WAZUH_MANAGER" \
    --alert-log "$ALERT_DIR/alerts.json"
else
  warn "Wazuh Agent no está instalado/configurado; el sensor funcionará localmente"
fi

chown -R root:root "$INSTALL_DIR"
chmod -R go-w "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable sensor-ia-nids.service

if systemctl list-unit-files wazuh-agent.service --no-legend 2>/dev/null | grep -q wazuh-agent; then
  systemctl enable wazuh-agent.service
fi

if [[ "$NO_START" == false ]]; then
  if systemctl list-unit-files wazuh-agent.service --no-legend 2>/dev/null | grep -q wazuh-agent; then
    systemctl restart wazuh-agent.service
  fi
  systemctl restart sensor-ia-nids.service
fi

info "Instalación completada"
echo "Verifica con: sudo bash $SCRIPT_DIR/scripts/verify_deployment.sh"

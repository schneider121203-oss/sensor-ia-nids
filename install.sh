#!/bin/bash
# ================================================================
#  install.sh — Instalador del Sensor IA NIDS
#  Tesis: Sistema de Detección de Intrusos basado en
#         Ensemble No Supervisado con Integración SIEM
#  Autor: Jorge D. Salinas R. — FISI
#
#  Uso:
#    sudo bash install.sh --wazuh-ip <IP_WAZUH_MANAGER> [opciones]
#
#  Ejemplo:
#    sudo bash install.sh --wazuh-ip 192.168.10.50
#    sudo bash install.sh --wazuh-ip 192.168.10.50 --iface eth0
#
#  Parámetros:
#    --wazuh-ip    IP del Wazuh Manager de la FISI [REQUERIDO]
#    --agent-name  Nombre del agente (default: sensor-ia-nids-jds)
#    --iface       Interfaz del puerto espejo (default: se detecta sola)
# ================================================================

set -e

# ── Defaults ─────────────────────────────────────────────────────
WAZUH_IP=""
AGENT_NAME="sensor-ia-nids-jds"
IFACE=""
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
SENSOR_DIR="$SCRIPT_DIR/sensor"
LOG_DIR="/var/log/ensemble"
SYSTEMD_SERVICE="/etc/systemd/system/sensor-ia-nids.service"

# ── Colores ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[~]${NC} $1"; }
step()    { echo -e "${CYAN}${BOLD}[→]${NC} $1"; }
error()   { echo -e "${RED}[✗] ERROR:${NC} $1"; exit 1; }

# ── Parsear argumentos ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --wazuh-ip)    WAZUH_IP="$2";    shift 2 ;;
        --agent-name)  AGENT_NAME="$2";  shift 2 ;;
        --iface)       IFACE="$2";       shift 2 ;;
        *) error "Argumento desconocido: $1" ;;
    esac
done

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  🛡️  Sensor IA NIDS — Instalador v1.0${NC}"
echo -e "${BOLD}  Tesis JDSR — Integración SIEM Wazuh FISI${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

# ── Validaciones ─────────────────────────────────────────────────
[[ "$(id -u)" -ne 0 ]] && error "Ejecuta como root: sudo bash install.sh --wazuh-ip <IP>"
[[ -z "$WAZUH_IP" ]]   && error "Debes pasar la IP del Wazuh Manager.\n  Ejemplo: sudo bash install.sh --wazuh-ip 192.168.10.50"
[[ ! -d "$SENSOR_DIR" ]] && error "No se encontró la carpeta sensor/. Ejecuta desde el directorio del instalador."

info "Wazuh Manager IP: $WAZUH_IP"
info "Nombre del agente: $AGENT_NAME"

# ── Auto-detectar interfaz de red si no se especificó ────────────
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    warn "Interfaz auto-detectada: $IFACE (puedes cambiarla con --iface)"
fi
info "Interfaz de red del puerto espejo: $IFACE"
echo ""

# ── PASO 1: Dependencias del sistema ─────────────────────────────
step "Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv \
    libpcap-dev libpcap0.8 curl gnupg lsb-release gcc
info "Dependencias del sistema instaladas."

# ── PASO 2: Entorno virtual Python + librerías IA ────────────────
step "Creando entorno virtual Python e instalando librerías IA..."
python3 -m venv "$SENSOR_DIR/venv"
"$SENSOR_DIR/venv/bin/pip" install --upgrade pip -q
"$SENSOR_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" -q
info "Librerías IA instaladas (NFStream, scikit-learn, PyTorch, EIF)."

# ── PASO 3: Directorio de alertas JSON ───────────────────────────
step "Creando directorio de alertas..."
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/alerts.json"
chmod 777 "$LOG_DIR/alerts.json"
info "Directorio $LOG_DIR listo."

# ── PASO 4: Instalar Wazuh Agent 4.9.2 ──────────────────────────
step "Instalando Wazuh Agent 4.9.2..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
    | tee /etc/apt/sources.list.d/wazuh.list > /dev/null
apt-get update -qq

# Configurar variables de entorno para el instalador de Wazuh
WAZUH_MANAGER="$WAZUH_IP" \
WAZUH_MANAGER_PORT="1514" \
WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq wazuh-agent=4.9.2-1
info "Wazuh Agent instalado → apuntando a $WAZUH_IP:1514"

# ── PASO 5: Configurar lectura del log JSON de la IA ─────────────
step "Configurando Wazuh Agent para leer alertas de la IA..."
AGENT_CONF="/var/ossec/etc/ossec.conf"

python3 - <<PYEOF
import re

with open("$AGENT_CONF", "r") as f:
    content = f.read()

localfile_block = """
  <!-- ===================================================== -->
  <!-- Sensor IA NIDS — Alertas JSON (Tesis JDSR)            -->
  <!-- ===================================================== -->
  <localfile>
    <log_format>json</log_format>
    <location>$LOG_DIR/alerts.json</location>
  </localfile>

"""

if "alerts.json" not in content:
    content = content.replace("</ossec_config>", localfile_block + "</ossec_config>")
    with open("$AGENT_CONF", "w") as f:
        f.write(content)
    print("  → Bloque <localfile> insertado en ossec.conf")
else:
    print("  → El bloque <localfile> ya existía. Sin cambios.")
PYEOF

# ── PASO 6: Crear servicio systemd para el sensor IA ─────────────
step "Creando servicio systemd para el sensor IA..."
cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Sensor IA NIDS — Tesis JDSR
Documentation=https://github.com/jdsr-fisi/tesis-nids
After=network.target wazuh-agent.service
Wants=wazuh-agent.service

[Service]
Type=simple
User=root
ExecStart=$SENSOR_DIR/venv/bin/python3 $SENSOR_DIR/flow_monitor.py --iface $IFACE
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sensor-ia-nids

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sensor-ia-nids
info "Servicio sensor-ia-nids.service creado y habilitado."

# ── PASO 7: Registrar el agente y arrancar servicios ─────────────
step "Iniciando servicios..."
systemctl restart wazuh-agent
sleep 3
systemctl start sensor-ia-nids
sleep 2

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅  Instalación completada exitosamente${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Estado de los servicios:${NC}"
systemctl status wazuh-agent  --no-pager | grep -E "Active:|agent name"
systemctl status sensor-ia-nids --no-pager | grep -E "Active:"
echo ""
echo -e "  ${BOLD}Para monitorear el sensor en tiempo real:${NC}"
echo -e "    journalctl -u sensor-ia-nids -f"
echo ""
echo -e "  ${BOLD}Para ver las alertas JSON que envía al Wazuh:${NC}"
echo -e "    tail -f $LOG_DIR/alerts.json"
echo ""
echo -e "  ${YELLOW}IMPORTANTE para el sysadmin del Wazuh Manager ($WAZUH_IP):${NC}"
echo -e "  Instalar los archivos de la carpeta wazuh_manager_config/ en el Manager:"
echo ""
echo -e "    sudo cp custom_decoder.xml /var/ossec/etc/decoders/"
echo -e "    sudo cp custom_rules.xml   /var/ossec/etc/rules/"
echo -e "    sudo /var/ossec/bin/wazuh-control restart"
echo ""

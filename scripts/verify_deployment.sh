#!/usr/bin/env bash
set -u

errors=0
check() {
  local description=$1; shift
  if "$@" >/dev/null 2>&1; then echo "[OK] $description"; else echo "[ERROR] $description"; errors=$((errors + 1)); fi
}

check "Configuración instalada" test -r /etc/sensor-ia-nids/sensor.env
check "Modelo íntegro" /opt/sensor-ia-nids/venv/bin/python \
  /opt/sensor-ia-nids/scripts/verify_model.py --models-dir /opt/sensor-ia-nids/models
check "Servicio del sensor activo" systemctl is-active --quiet sensor-ia-nids.service
check "Archivo de alertas disponible" test -f /var/log/ensemble/alerts.json

if systemctl list-unit-files wazuh-agent.service --no-legend 2>/dev/null | grep -q wazuh-agent; then
  check "Wazuh Agent activo" systemctl is-active --quiet wazuh-agent.service
  if [[ -r /var/ossec/var/run/wazuh-agentd.state ]] && grep -q "^status='connected'" /var/ossec/var/run/wazuh-agentd.state; then
    echo "[OK] Wazuh Agent conectado al manager"
  else
    echo "[ERROR] Wazuh Agent no figura conectado"
    errors=$((errors + 1))
  fi
else
  echo "[ADVERTENCIA] Wazuh Agent no está instalado"
fi

echo "Modelo esperado: nfstream-native-ensemble-v4-60s"
echo "Umbral esperado: 0.9343915343915343"
((errors == 0))

#!/usr/bin/env bash
set -Eeuo pipefail

PURGE_DATA=false
if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  echo "Uso: $0 [--purge-data]"
  exit 0
fi
[[ ${1:-} != --purge-data ]] || PURGE_DATA=true
[[ $# -le 1 ]] || { echo "Uso: $0 [--purge-data]" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo "Ejecutar con sudo" >&2; exit 1; }

systemctl disable --now sensor-ia-nids.service 2>/dev/null || true
rm -f /etc/systemd/system/sensor-ia-nids.service /etc/logrotate.d/sensor-ia-nids
systemctl daemon-reload

if [[ -f /var/ossec/etc/ossec.conf ]]; then
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  python3 "$script_dir/configure_wazuh_agent.py" \
    --config /var/ossec/etc/ossec.conf --remove-localfile
  systemctl restart wazuh-agent.service 2>/dev/null || true
fi

rm -rf /opt/sensor-ia-nids /etc/sensor-ia-nids
if [[ "$PURGE_DATA" == true ]]; then
  rm -rf /var/lib/sensor-ia-nids /var/log/ensemble
  echo "Datos y alertas locales eliminados por solicitud explícita"
else
  echo "Datos preservados en /var/lib/sensor-ia-nids y /var/log/ensemble"
fi
echo "Wazuh Agent no fue desinstalado"

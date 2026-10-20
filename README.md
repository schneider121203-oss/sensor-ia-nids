# Sensor IA/NIDS para FISI-UNMSM

Sensor pasivo de anomalías de red basado en NFStream y un ensemble no supervisado
(Extended Isolation Forest, Autoencoder y Local Outlier Factor). Está preparado para
una VM Ubuntu 22.04 LTS conectada a un puerto SPAN/port mirroring autorizado y envía
únicamente las alertas JSON a un Wazuh Manager existente.

El sensor funciona en modo sombra: observa y alerta, pero no bloquea conexiones.

## Arquitectura

```text
Switch ── puerto SPAN ──> NIC de captura de la VM
                              │
                              ├─ NFStream + contrato temporal de 60 s
                              ├─ ensemble v4 congelado (CPU)
                              ├─ flujos/telemetría locales
                              └─ alertas JSON ─> Wazuh Agent ─> Wazuh Manager
```

Se recomienda separar la NIC de captura de la NIC de administración. La interfaz de
captura debe indicarse explícitamente: el instalador nunca elige automáticamente la
interfaz por defecto.

## Requisitos

| Recurso | Recomendado |
|---|---|
| Sistema | Ubuntu Server 22.04 LTS, x86_64 |
| CPU | 4 vCPU; no requiere GPU |
| RAM | 4 GB |
| Disco | 40 GB, ampliable según retención |
| Red | NIC de gestión y NIC de captura SPAN dedicada |
| Wazuh | Manager existente, versión igual o posterior a la del agente |

Requisitos de red:

- SPAN configurado y autorizado por el administrador del datacenter;
- NIC de captura sin DHCP, IP ni ruta predeterminada;
- salida desde la NIC de gestión hacia el manager por TCP/1514;
- TCP/1515 si el manager utiliza inscripción automática;
- NTP activo en sensor y manager.

## Instalación rápida

```bash
git clone https://github.com/schneider121203-oss/sensor-ia-nids.git
cd sensor-ia-nids

# Revisión previa; no modifica el sistema.
sudo bash scripts/preflight.sh \
  --iface enp0s8 --wazuh-manager 192.168.10.50

# La interfaz es obligatoria.
sudo bash install.sh \
  --iface enp0s8 \
  --wazuh-manager 192.168.10.50 \
  --agent-name sensor-ia-nids-fisi

sudo bash scripts/verify_deployment.sh
```

Si el Wazuh Agent ya es administrado por la facultad:

```bash
sudo bash install.sh --iface enp0s8 --wazuh-manager 192.168.10.50 \
  --skip-wazuh-install
```

El instalador es idempotente: se puede volver a ejecutar con los mismos parámetros para
reparar archivos, permisos, entorno Python o servicio. No elimina evidencia existente.

## Instalación en el Wazuh Manager

El administrador debe comprobar primero que los IDs 110001–110004 estén libres:

```bash
sudo grep -R 'id="11000[1-4]"' /var/ossec/etc/rules
sudo cp wazuh_manager_config/custom_rules.xml /var/ossec/etc/rules/sensor_ia_nids_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/sensor_ia_nids_rules.xml
sudo chmod 0640 /var/ossec/etc/rules/sensor_ia_nids_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

Solo después de una validación correcta debe reiniciarse el manager durante una ventana
autorizada. El agente lee `/var/log/ensemble/alerts.json` con el decoder JSON nativo de
Wazuh; no necesita un decoder personalizado.

La instalación oficial del agente usa variables de despliegue y recomienda que el
manager sea igual o más reciente que el agente:
[documentación oficial de Wazuh](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html).

## Rutas instaladas

| Ruta | Contenido |
|---|---|
| `/opt/sensor-ia-nids` | código, modelo congelado y entorno virtual |
| `/etc/sensor-ia-nids/sensor.env` | interfaz y parámetros operativos |
| `/var/lib/sensor-ia-nids` | flujos, telemetría y resumen |
| `/var/log/ensemble/alerts.json` | alertas consumidas por Wazuh Agent |
| `/etc/systemd/system/sensor-ia-nids.service` | servicio del sensor |

El modelo activo es `nfstream-native-ensemble-v4-60s`, con 22 características observables,
ventana temporal de 60 segundos, ECDF fijas y umbral congelado `0.9343915343915343`.
`scripts/verify_model.py` valida sus hashes antes y después de instalarlo.

## Operación

```bash
sudo systemctl status sensor-ia-nids wazuh-agent
sudo journalctl -u sensor-ia-nids -f
sudo tail -f /var/log/ensemble/alerts.json
sudo grep '^status' /var/ossec/var/run/wazuh-agentd.state
```

Para cambiar la interfaz, editar `/etc/sensor-ia-nids/sensor.env`, ejecutar
`scripts/preflight.sh --iface NUEVA_INTERFAZ --wazuh-manager HOST` y reiniciar el
servicio. Los logs tienen rotación configurada para proteger el disco de 40 GB.

## Desinstalación y rollback

```bash
# Retira sensor, servicio y configuración; conserva datos y Wazuh Agent.
sudo bash scripts/uninstall.sh

# La opción explícita también elimina flujos y alertas locales.
sudo bash scripts/uninstall.sh --purge-data
```

El script no elimina el Wazuh Agent ni modifica el manager, porque pueden ser componentes
institucionales compartidos.

## Desarrollo

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Los modelos candidatos y los datasets de entrenamiento no forman parte del despliegue.
El directorio `sensor/models/` contiene únicamente el modelo promovido y congelado.

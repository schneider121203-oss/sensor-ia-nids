# Sensor IA NIDS — Componente de Seguridad
## Tesis de Ingeniería: Sistema de Detección de Intrusos con Ensemble No Supervisado
**Autor:** Jorge D. Salinas R. | **Facultad:** FISI | **Año:** 2026

---

## ¿Qué es este componente?

Este es un **sensor de red inteligente** basado en Machine Learning que analiza el tráfico
de red en tiempo real a través de un puerto espejo (SPAN/Mirror Port) y envía alertas de
anomalías al Wazuh Manager existente en la infraestructura FISI.

El núcleo del sistema es un **Ensemble No Supervisado** compuesto por tres algoritmos
complementarios:
- **Extended Isolation Forest (EIF)** — Detección de outliers basada en particionado aleatorio
- **Autoencoder (PyTorch)** — Red neuronal de reconstrucción para detección de patrones inusuales
- **Local Outlier Factor (LOF)** — Detección por densidad local

Los tres modelos votan y producen un **score de anomalía de 0.0 a 1.0**. Si el score supera
el umbral de 0.70, se genera una alerta JSON que el Wazuh Agent reenvía automáticamente
al Wazuh Manager de la FISI.

---

## Arquitectura

```
[Infraestructura de Red FISI]
  (Servidores Web, Matrícula, etc.)
          │
          ▼
  [Switch Cisco — Puerto Espejo (SPAN)]
          │
          ▼
  [VM Sensor IA — sensor-ia-nids-jds]
    ├── NFStream (captura flujos de red)
    ├── Ensemble IA (EIF + Autoencoder + LOF)
    ├── /var/log/ensemble/alerts.json
    └── Wazuh Agent ──► [Wazuh Manager FISI]
                           └── Dashboard de alertas
```

---

## Requisitos de la VM

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disco | 20 GB | 40 GB |
| Red | 1 NIC conectada al puerto espejo | 1 NIC |
| Internet | Requerido (solo para instalación) | — |

---

## Instalación

### Paso 1: Para el Sysadmin del Wazuh Manager

En el servidor donde corre el **Wazuh Manager de la FISI**, copiar los archivos de la
carpeta `wazuh_manager_config/` e instalarlos:

```bash
# Copiar los archivos al servidor Wazuh Manager
sudo cp wazuh_manager_config/custom_decoder.xml /var/ossec/etc/decoders/
sudo cp wazuh_manager_config/custom_rules.xml   /var/ossec/etc/rules/

# Verificar que los archivos son válidos
sudo /var/ossec/bin/wazuh-analysisd -t

# Reiniciar el Manager para aplicar
sudo /var/ossec/bin/wazuh-control restart
```

> **¿Qué hace cada archivo?**
> - `custom_decoder.xml`: Enseña a Wazuh a interpretar el formato JSON de las alertas de la IA
> - `custom_rules.xml`: Define 5 niveles de alerta (IDs 100001-100005, niveles 7-13)

### Paso 2: En la VM del Sensor

```bash
# Dar permisos de ejecución al instalador
chmod +x install.sh

# Ejecutar el instalador pasándole la IP del Wazuh Manager de la FISI
sudo bash install.sh --wazuh-ip <IP_DEL_WAZUH_MANAGER_FISI>

# Ejemplo:
sudo bash install.sh --wazuh-ip 192.168.10.50
```

El instalador hace automáticamente:
1. Instala dependencias del sistema (`libpcap`, `python3-venv`, `gcc`)
2. Crea entorno virtual Python e instala librerías IA
3. Instala y configura el **Wazuh Agent 4.9.2** apuntando al Manager indicado
4. Configura el Agent para leer `/var/log/ensemble/alerts.json`
5. Crea un **servicio systemd** (`sensor-ia-nids`) que arranca automáticamente con el servidor

#### Parámetros opcionales:

```bash
# Especificar manualmente la interfaz de red del puerto espejo
sudo bash install.sh --wazuh-ip 192.168.10.50 --iface eth1

# Cambiar el nombre del agente (default: sensor-ia-nids-jds)
sudo bash install.sh --wazuh-ip 192.168.10.50 --agent-name mi-sensor
```

---

## Verificación

Después de instalar, verificar que todo funciona:

```bash
# Ver estado del sensor IA
sudo systemctl status sensor-ia-nids

# Ver alertas en tiempo real (terminal 1)
journalctl -u sensor-ia-nids -f

# Ver JSON de alertas (terminal 2)
tail -f /var/log/ensemble/alerts.json

# Ver estado del Wazuh Agent
sudo systemctl status wazuh-agent
sudo /var/ossec/bin/agent_control -l   # Listar agentes registrados
```

En el Wazuh Dashboard de la FISI, el agente `sensor-ia-nids-jds` debería aparecer como
**Active** y las alertas de la IA llegarán bajo las reglas con ID `100001` al `100005`.

---

## Niveles de Alerta

| Regla ID | Nivel Wazuh | Score IA | Descripción |
|----------|-------------|----------|-------------|
| 100001 | 5 (Bajo) | — | Alerta base de detección IA |
| 100002 | 7 (Medio) | ≥ 0.70 | Tráfico sospechoso detectado |
| 100003 | 10 (Alto) | ≥ 0.85 | Posible ataque detectado |
| 100004 | 12 (Crítico) | ≥ 0.95 | Ataque confirmado — Score alto |
| 100005 | 13 (Máximo) | — | Intento de evasión adversaria |

---

## Gestión del Servicio

```bash
# Iniciar / Detener / Reiniciar el sensor
sudo systemctl start   sensor-ia-nids
sudo systemctl stop    sensor-ia-nids
sudo systemctl restart sensor-ia-nids

# Ver logs en tiempo real
journalctl -u sensor-ia-nids -f

# Deshabilitar el arranque automático
sudo systemctl disable sensor-ia-nids
```

---

## Contenido del Paquete

```
sensor_ia_fisi/
├── README.md                          ← Este archivo
├── install.sh                         ← Instalador (ejecutar con sudo)
├── requirements.txt                   ← Dependencias Python
├── sensor/
│   ├── flow_monitor.py                ← Captura y análisis en tiempo real
│   ├── ensemble_predictor.py          ← Lógica del modelo Ensemble IA
│   └── models/
│       ├── eif_model.pkl              ← Extended Isolation Forest
│       ├── lof_model.pkl              ← Local Outlier Factor
│       ├── autoencoder.pt             ← Autoencoder (PyTorch)
│       ├── scaler.pkl                 ← Normalizador de características
│       ├── pca.pkl                    ← Reducción de dimensionalidad
│       └── encoders.pkl               ← Codificadores de variables categóricas
└── wazuh_manager_config/
    ├── custom_decoder.xml             ← INSTALAR en el Wazuh Manager FISI
    └── custom_rules.xml               ← INSTALAR en el Wazuh Manager FISI
```

---

## Soporte

Para consultas técnicas, contactar al autor de la tesis.

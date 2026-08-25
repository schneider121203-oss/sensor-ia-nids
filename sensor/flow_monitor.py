"""
============================================================================
flow_monitor.py — Daemon de captura y análisis de flujos en tiempo real
============================================================================
Captura tráfico de red usando nfstream, genera features de flujo,
aplica el ensemble y escribe alertas JSON que Wazuh lee en tiempo real.

Uso:
    # Captura real de la interfaz de red virtual (VMs)
    sudo python flow_monitor.py --iface virbr0

    # Modo test con archivo pcap
    python flow_monitor.py --pcap sample.pcap

    # Listar interfaces disponibles
    python flow_monitor.py --list-ifaces
============================================================================
"""

import argparse
import json
import logging
import os
import sys
import time
import threading
import queue
from datetime import datetime
from pathlib import Path

import pandas as pd
import nfstream

# ── Logging ───────────────────────────────────────────────────────────────
LOG_DIR      = Path("/var/log/ensemble")
ALERT_LOG    = LOG_DIR / "alerts.json"
MONITOR_LOG  = LOG_DIR / "flow_monitor.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(MONITOR_LOG),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

# ── Importar predictor ─────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from ensemble_predictor import EnsemblePredictor

# ── Mapeo nfstream → columnas UNSW-NB15 ───────────────────────────────────
# nfstream genera nombres de columna distintos a UNSW-NB15.
# Este mapeo aproxima los equivalentes disponibles.
NFSTREAM_TO_UNSW = {
    "src_ip":                    "src_ip",        # meta (no feature)
    "dst_ip":                    "dst_ip",        # meta (no feature)
    "src_port":                  "sport",
    "dst_port":                  "dport",
    "protocol":                  "proto",
    "bidirectional_duration_ms": "dur",           # ms → convertir a s
    "src2dst_bytes":             "sbytes",
    "dst2src_bytes":             "dbytes",
    "src2dst_packets":           "spkts",
    "dst2src_packets":           "dpkts",
    "src2dst_min_ttl":           "sttl",
    "dst2src_min_ttl":           "dttl",
}

SCORE_THRESHOLD   = 0.70   # Score mínimo para generar alerta
CAPTURE_DURATION  = 60      # segundos por ventana de captura
BATCH_INTERVAL    = 60      # segundos entre ciclos (en modo iface)


def nfstream_to_df(streamer) -> pd.DataFrame:
    """Convierte los flujos de nfstream a DataFrame con columnas UNSW-like."""
    records = []
    # Puertos de infraestructura a ignorar (SSH, Wazuh, NTP)
    IGNORE_PORTS = {22, 123, 1514, 1515}
    
    for flow in streamer:
        # Filtrar ruido de infraestructura local
        if flow.src_port in IGNORE_PORTS or flow.dst_port in IGNORE_PORTS:
            continue
            
        record = {}
        for nf_col, unsw_col in NFSTREAM_TO_UNSW.items():
            val = getattr(flow, nf_col, 0) or 0
            record[unsw_col] = val
        # Convertir duración de ms a segundos
        record["dur"] = record.get("dur", 0) / 1000.0
        # Columnas UNSW que nfstream no tiene directamente (rellenar con 0)
        for col in ["sload", "dload", "ct_srv_dst", "ct_state_ttl",
                    "service", "state", "ct_dst_src_ltm"]:
            record.setdefault(col, 0)
        records.append(record)
    return pd.DataFrame(records)


def write_alert(alert: dict) -> None:
    """Escribe una alerta JSON al log que lee Wazuh."""
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


def analyze_batch(df_raw: pd.DataFrame, predictor: EnsemblePredictor) -> int:
    """
    Analiza un batch de flujos y escribe alertas para los anómalos.
    Devuelve el número de alertas generadas.
    """
    if df_raw.empty:
        return 0

    results    = predictor.predict(df_raw)
    anomalies  = results[results["is_anomaly"] == 1]
    n_alerts   = 0

    for _, row in anomalies.iterrows():
        score = float(row["ensemble_score"])
        if score < SCORE_THRESHOLD:
            continue

        flow_dict = row.to_dict()
        alert     = predictor.format_alert(flow_dict, score)
        write_alert(alert)
        n_alerts += 1

        logger.info(
            f"🚨 ANOMALÍA | score={score:.4f} | "
            f"{row.get('src_ip','?')}:{int(row.get('sport',0))} → "
            f"{row.get('dst_ip','?')}:{int(row.get('dport',0))} | "
            f"proto={row.get('proto','?')}"
        )

    return n_alerts


def run_pcap_mode(pcap_path: str, predictor: EnsemblePredictor) -> None:
    """Modo test: analiza un archivo pcap completo."""
    logger.info(f"📂 Modo PCAP: {pcap_path}")
    streamer = nfstream.NFStreamer(source=pcap_path, statistical_analysis=True)
    df_raw   = nfstream_to_df(streamer)
    logger.info(f"   Flujos capturados: {len(df_raw)}")
    n = analyze_batch(df_raw, predictor)
    logger.info(f"   Alertas generadas: {n}")


def run_iface_mode(iface: str, predictor: EnsemblePredictor) -> None:
    """Modo producción: captura continua en la interfaz especificada (Multithreading)."""
    logger.info(f"🔴 Iniciando captura en interfaz: {iface}")
    logger.info(f"   Umbral: {SCORE_THRESHOLD}")
    logger.info(f"   Alertas → {ALERT_LOG}")
    logger.info("   Ctrl+C para detener\\n")

    total_flows = 0
    total_alerts = 0
    BATCH_SIZE = 100  # Lote grande para que la IA aproveche la vectorización
    
    flow_queue = queue.Queue(maxsize=20000)
    stop_event = threading.Event()

    # ── Hilo Consumidor (La Inteligencia Artificial) ──
    def consumer_thread():
        nonlocal total_flows, total_alerts
        records = []
        
        while not stop_event.is_set():
            try:
                # Extrae el flujo; si no hay, espera 1 segundo
                flow_data = flow_queue.get(timeout=1.0)
                records.append(flow_data)
            except queue.Empty:
                pass
            
            # Procesar el lote si llegamos al tamaño, o si la cola está vacía pero hay registros pendientes
            if len(records) >= BATCH_SIZE or (len(records) > 0 and flow_queue.empty()):
                df_batch = pd.DataFrame(records)
                n_alerts = analyze_batch(df_batch, predictor)
                total_flows += len(records)
                total_alerts += n_alerts
                records = []

        # Al detener, procesar los que quedaron colgados
        if records:
            df_batch = pd.DataFrame(records)
            n_alerts = analyze_batch(df_batch, predictor)
            total_flows += len(records)
            total_alerts += n_alerts

    consumer = threading.Thread(target=consumer_thread, daemon=True)
    consumer.start()

    # ── Hilo Principal (El Recolector / NFStream) ──
    try:
        # Timeouts super agresivos para tener flujos "en vivo" rápido
        streamer = nfstream.NFStreamer(
            source=iface,
            statistical_analysis=True,
            idle_timeout=2,       # Si hay silencio 2s, cierra el flujo
            active_timeout=5,     # Si el ataque es continuo, córtalo cada 5s y pásalo
        )
        
        logger.info("⏳ Esperando a que terminen los flujos de red...")
        
        # Puertos de infraestructura a ignorar en captura en vivo
        IGNORE_PORTS = {22, 123, 1514, 1515}

        for flow in streamer:
            # Descartar ruido de SSH, NTP y agente Wazuh
            if flow.src_port in IGNORE_PORTS or flow.dst_port in IGNORE_PORTS:
                continue

            record = {}
            for nf_col, unsw_col in NFSTREAM_TO_UNSW.items():
                val = getattr(flow, nf_col, 0) or 0
                record[unsw_col] = val
            record["dur"] = record.get("dur", 0) / 1000.0
            
            for col in ["sload", "dload", "ct_srv_dst", "ct_state_ttl",
                        "service", "state", "ct_dst_src_ltm"]:
                record.setdefault(col, 0)
                
            try:
                flow_queue.put(record, block=False)
            except queue.Full:
                logger.warning("⚠️ Cola de flujos llena (la IA no da abasto). Perdiendo flujo.")

    except KeyboardInterrupt:
        logger.info("\\n⛔ Detenido por el usuario")
    except Exception as e:
        logger.error(f"Error crítico en captura: {e}")
    finally:
        stop_event.set()
        consumer.join(timeout=2)
        logger.info(f"   Resumen: {total_flows} flujos | {total_alerts} alertas")


def list_interfaces() -> None:
    """Lista las interfaces de red disponibles."""
    print("\nInterfaces de red disponibles:")
    try:
        import subprocess
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if ": " in line and "@" not in line and "link/" not in line:
                print(f"  {line.split(': ')[1].split('@')[0]}")
    except Exception:
        print("  (No se pudieron listar — usa 'ip link show' manualmente)")


# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Flow Monitor — Ensemble Anomaly Detection + Wazuh")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--iface",       help="Interfaz de red a capturar (ej: virbr0)")
    group.add_argument("--pcap",        help="Archivo .pcap para modo test")
    group.add_argument("--list-ifaces", action="store_true",
                       help="Listar interfaces disponibles")
    parser.add_argument("--threshold",  type=float, default=SCORE_THRESHOLD,
                        help=f"Umbral de alerta (default: {SCORE_THRESHOLD})")
    parser.add_argument("--models-dir", type=Path, default=None,
                        help="Directorio de modelos (default: ./models)")

    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)

    if not args.iface and not args.pcap:
        parser.print_help()
        print("\n⚠️  Especifica --iface o --pcap\n")
        sys.exit(1)

    # ── Cargar predictor ──────────────────────────────────────────────────
    models_dir = args.models_dir or SCRIPT_DIR / "models"
    if not (models_dir / "meta.json").exists():
        print(f"\n❌ No se encontraron modelos en {models_dir}")
        print("   Ejecuta primero: python model_trainer.py\n")
        sys.exit(1)

    SCORE_THRESHOLD = args.threshold
    predictor = EnsemblePredictor(models_dir=models_dir)
    predictor.load_models()

    # ── Ejecutar modo correspondiente ─────────────────────────────────────
    if args.pcap:
        run_pcap_mode(args.pcap, predictor)
    else:
        run_iface_mode(args.iface, predictor)

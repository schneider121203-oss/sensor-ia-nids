"""
============================================================================
flow_monitor.py — Monitor v3 conservado para pruebas de reproducibilidad
============================================================================
Captura tráfico de red usando nfstream, genera features de flujo,
aplica el ensemble y escribe alertas JSON que Wazuh lee en tiempo real.

Producción FISI usa flow_monitor_v4.py mediante el servicio systemd.

Uso:
    # Captura real de la interfaz de red virtual (VMs)
    sudo python flow_monitor.py --iface enp0s8

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
LOG_DIR      = Path(os.environ.get("ENSEMBLE_LOG_DIR", "/var/log/ensemble"))
ALERT_LOG    = LOG_DIR / "alerts.json"
FLOW_LOG     = Path(os.environ.get("ENSEMBLE_FLOW_LOG", LOG_DIR / "flows.json"))
MONITOR_LOG  = LOG_DIR / "flow_monitor.log"

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    """Configura logs solo al ejecutar el monitor, nunca al importarlo."""
    log_handlers = [logging.StreamHandler(sys.stdout)]
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_handlers.insert(0, logging.FileHandler(MONITOR_LOG))
    except OSError as exc:
        print(f"ADVERTENCIA: no se puede escribir en {LOG_DIR}: {exc}", file=sys.stderr)
        print("El monitor registrará solamente en la consola.", file=sys.stderr)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=log_handlers,
    )

# ── Importar predictor ─────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from ensemble_predictor import EnsemblePredictor
from nfstream_extractor import FirstTTLPlugin, NFStreamFeatureExtractor

# ── Mapeo nfstream → columnas UNSW-NB15 ───────────────────────────────────
# La conversion se centraliza en un extractor compartido por PCAP e interfaz.
CAPTURE_DURATION  = 60      # segundos por ventana de captura
BATCH_INTERVAL    = 60      # segundos entre ciclos (en modo iface)
BATCH_SIZE        = 100     # máximo de flujos por inferencia
BATCH_MAX_WAIT    = 2.0     # latencia máxima antes de cerrar un micro-lote
INFRASTRUCTURE_PORTS = {1514, 1515}  # transporte interno de Wazuh


def should_ignore_flow(flow) -> bool:
    """Excluye solo Wazuh; SSH y NTP deben seguir siendo observables."""
    return (
        int(getattr(flow, "src_port", 0) or 0) in INFRASTRUCTURE_PORTS
        or int(getattr(flow, "dst_port", 0) or 0) in INFRASTRUCTURE_PORTS
    )


def nfstream_to_df(streamer) -> pd.DataFrame:
    """Convierte PCAP y captura viva mediante el mismo extractor."""
    records = []
    extractor = NFStreamFeatureExtractor()
    for flow in streamer:
        if should_ignore_flow(flow):
            continue
        records.append(extractor.extract(flow))
    return pd.DataFrame(records)


def write_json_line(path: Path, event: dict) -> None:
    """Escribe evidencia NDJSON; conserva todos los flujos y las alertas."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as file_handle:
        file_handle.write(json.dumps(event, default=str) + "\n")


def write_alert(alert: dict) -> None:
    """Escribe una alerta JSON al log que lee Wazuh."""
    write_json_line(ALERT_LOG, alert)


def analyze_batch(df_raw: pd.DataFrame, predictor: EnsemblePredictor,
                  threshold: float, flow_log: Path = FLOW_LOG,
                  run_id: str | None = None) -> int:
    """
    Analiza un batch de flujos y escribe alertas para los anómalos.
    Devuelve el número de alertas generadas.
    """
    if df_raw.empty:
        return 0

    results    = predictor.predict(df_raw)
    effective_run_id = run_id or os.environ.get("ENSEMBLE_RUN_ID", "unassigned")
    results["run_id"] = effective_run_id
    anomalies  = results[results["is_anomaly"] == 1]
    n_alerts   = 0

    # Persistir todos los flujos, incluidos los benignos/no alertados. El
    # manifiesto experimental aporta la etiqueta de ground truth por ventana.
    for _, row in results.iterrows():
        observation = row.to_dict()
        observation.update({
            "source": "ensemble_flow",
            "observed_at": datetime.now().astimezone().isoformat(),
            "model_version": predictor.meta.get("model_version", "unknown"),
            "threshold": float(threshold),
            "run_id": effective_run_id,
        })
        write_json_line(flow_log, observation)

    for _, row in anomalies.iterrows():
        score = float(row["ensemble_score"])
        if score < threshold:
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


def run_pcap_mode(pcap_path: str, predictor: EnsemblePredictor,
                  flow_log: Path, run_id: str | None) -> None:
    """Modo test: analiza un archivo pcap completo."""
    logger.info(f"📂 Modo PCAP: {pcap_path}")
    streamer = nfstream.NFStreamer(
        source=pcap_path,
        statistical_analysis=True,
        udps=[FirstTTLPlugin()],
    )
    df_raw   = nfstream_to_df(streamer)
    logger.info(f"   Flujos capturados: {len(df_raw)}")
    n = analyze_batch(
        df_raw, predictor, float(predictor.meta["threshold"]), flow_log, run_id
    )
    logger.info(f"   Alertas generadas: {n}")


def run_iface_mode(iface: str, predictor: EnsemblePredictor,
                   batch_size: int = BATCH_SIZE,
                   batch_max_wait: float = BATCH_MAX_WAIT,
                   flow_log: Path = FLOW_LOG, run_id: str | None = None) -> None:
    """Modo producción: captura continua en la interfaz especificada (Multithreading)."""
    logger.info(f"🔴 Iniciando captura en interfaz: {iface}")
    threshold = float(predictor.meta["threshold"])
    logger.info(f"   Umbral calibrado del modelo: {threshold:.6f}")
    logger.info(f"   Alertas → {ALERT_LOG}")
    logger.info("   Ctrl+C para detener\\n")

    total_flows = 0
    total_alerts = 0
    flow_queue = queue.Queue(maxsize=20000)
    stop_event = threading.Event()
    extractor = NFStreamFeatureExtractor()

    # ── Hilo Consumidor (La Inteligencia Artificial) ──
    def consumer_thread():
        nonlocal total_flows, total_alerts
        records = []
        batch_started_at = None

        while not stop_event.is_set() or not flow_queue.empty():
            try:
                flow_data = flow_queue.get(timeout=0.25)
                records.append(flow_data)
                if batch_started_at is None:
                    batch_started_at = time.monotonic()
            except queue.Empty:
                pass

            batch_full = len(records) >= batch_size
            batch_expired = (
                records and batch_started_at is not None
                and time.monotonic() - batch_started_at >= batch_max_wait
            )
            if batch_full or batch_expired:
                df_batch = pd.DataFrame(records)
                n_alerts = analyze_batch(
                    df_batch, predictor, threshold, flow_log, run_id
                )
                total_flows += len(records)
                total_alerts += n_alerts
                records = []
                batch_started_at = None

        # Al detener, procesar los que quedaron colgados
        if records:
            df_batch = pd.DataFrame(records)
            n_alerts = analyze_batch(
                df_batch, predictor, threshold, flow_log, run_id
            )
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
            udps=[FirstTTLPlugin()],
            idle_timeout=2,       # Si hay silencio 2s, cierra el flujo
            active_timeout=5,     # Si el ataque es continuo, córtalo cada 5s y pásalo
        )
        
        logger.info("⏳ Esperando a que terminen los flujos de red...")
        
        for flow in streamer:
            if should_ignore_flow(flow):
                continue
            record = extractor.extract(flow)
                
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
    configure_logging()
    parser = argparse.ArgumentParser(
        description="Flow Monitor — Ensemble Anomaly Detection + Wazuh")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--iface",       help="Interfaz de red a capturar (ej: enp0s8)")
    group.add_argument("--pcap",        help="Archivo .pcap para modo test")
    group.add_argument("--list-ifaces", action="store_true",
                       help="Listar interfaces disponibles")
    parser.add_argument("--models-dir", type=Path, default=None,
                        help="Directorio de modelos (default: ./models)")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                        help=f"Flujos máximos por micro-lote (default: {BATCH_SIZE})")
    parser.add_argument("--batch-max-wait", type=float, default=BATCH_MAX_WAIT,
                        help=f"Espera máxima del micro-lote en segundos (default: {BATCH_MAX_WAIT})")
    parser.add_argument("--flow-log", type=Path, default=FLOW_LOG,
                        help="Archivo NDJSON para todos los flujos observados")
    parser.add_argument("--run-id", default=os.environ.get("ENSEMBLE_RUN_ID"),
                        help="Identificador del experimento para correlacionar evidencia")

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

    predictor = EnsemblePredictor(models_dir=models_dir)
    predictor.load_models()

    # ── Ejecutar modo correspondiente ─────────────────────────────────────
    if args.pcap:
        run_pcap_mode(args.pcap, predictor, args.flow_log, args.run_id)
    else:
        if args.batch_size < 1 or args.batch_max_wait <= 0:
            parser.error("--batch-size debe ser >= 1 y --batch-max-wait debe ser > 0")
        run_iface_mode(
            args.iface, predictor, args.batch_size, args.batch_max_wait,
            args.flow_log, args.run_id,
        )

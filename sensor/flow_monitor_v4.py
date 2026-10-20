"""Monitor de inferencia v4-native con ordenamiento temporal y evidencia NDJSON."""

from __future__ import annotations

import argparse
import heapq
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import nfstream
import pandas as pd
import psutil

from ensemble_predictor import EnsemblePredictor
from nfstream_native_extractor import FirstTTLPlugin, NFStreamNativeExtractor


LOGGER = logging.getLogger("flow_monitor_v4")
STOP = threading.Event()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_line(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


def analyze(records: list[dict], predictor: EnsemblePredictor, run_id: str,
            flow_log: Path, alert_log: Path) -> tuple[int, int]:
    if not records:
        return 0, 0
    results = predictor.predict(pd.DataFrame(records))
    threshold = float(predictor.meta["threshold"])
    observed_ms = int(time.time() * 1000)
    alerts = 0
    for _, row in results.iterrows():
        event = row.to_dict()
        event.update({
            "source": "ensemble_flow_v4",
            "run_id": run_id,
            "model_version": predictor.meta["model_version"],
            "threshold": threshold,
            "observed_at": utc_now(),
            "detection_latency_ms": max(0, observed_ms - int(row["event_time_ms"])),
        })
        write_json_line(flow_log, event)
        if int(row["is_anomaly"]) == 1:
            alert = predictor.format_alert(event, float(row["ensemble_score"]))
            alert["run_id"] = run_id
            alert["event_time_ms"] = int(row["event_time_ms"])
            alert["detection_latency_ms"] = event["detection_latency_ms"]
            write_json_line(alert_log, alert)
            alerts += 1
    return len(records), alerts


def resource_sampler(path: Path, interval_seconds: float = 2.0) -> None:
    process = psutil.Process(os.getpid())
    process.cpu_percent(None)
    while not STOP.wait(interval_seconds):
        memory = process.memory_info()
        write_json_line(path, {
            "timestamp": utc_now(),
            "cpu_percent": process.cpu_percent(None),
            "rss_bytes": memory.rss,
            "vms_bytes": memory.vms,
        })


def raw_flow_producer(source: str, output: queue.Queue, live: bool,
                      bpf_filter: str | None,
                      include_ips: set[str] | None) -> None:
    try:
        streamer = nfstream.NFStreamer(
            source=source,
            statistical_analysis=True,
            udps=[FirstTTLPlugin()],
            idle_timeout=2 if live else 120,
            active_timeout=5 if live else 1800,
            bpf_filter=bpf_filter,
        )
        extractor = NFStreamNativeExtractor()
        for flow in streamer:
            if STOP.is_set():
                break
            raw = extractor.extract_raw(flow)
            if include_ips and not ({raw["src_ip"], raw["dst_ip"]} & include_ips):
                continue
            output.put(raw)
    except Exception as exc:  # se reenvía al consumidor para salida no-cero
        output.put(exc)
    finally:
        output.put(None)


def run_monitor(source: str, live: bool, predictor: EnsemblePredictor, run_id: str,
                output_dir: Path, duration_seconds: int,
                ordering_delay_ms: int, batch_size: int,
                bpf_filter: str | None = None,
                include_ips: set[str] | None = None,
                alert_log_path: Path | None = None) -> dict:
    flow_log = output_dir / "flows.ndjson"
    alert_log = alert_log_path or output_dir / "alerts.json"
    resource_log = output_dir / "resource_samples.ndjson"
    raw_queue: queue.Queue = queue.Queue(maxsize=20000)
    producer = threading.Thread(
        target=raw_flow_producer,
        args=(source, raw_queue, live, bpf_filter, include_ips), daemon=True,
    )
    sampler = threading.Thread(target=resource_sampler, args=(resource_log,), daemon=True)
    producer.start()
    sampler.start()

    context_extractor = NFStreamNativeExtractor()
    pending: list[tuple[int, int, dict]] = []
    ready: list[dict] = []
    newest_event_ms = 0
    newest_wall_monotonic = time.monotonic()
    sequence = flows = alerts = 0
    started = time.monotonic()
    producer_done = False

    def flush_ready(watermark: int) -> None:
        nonlocal flows, alerts
        while pending and pending[0][0] <= watermark:
            _, _, raw = heapq.heappop(pending)
            ready.append(context_extractor.enrich_context(raw))
            if len(ready) >= batch_size:
                n_flows, n_alerts = analyze(ready.copy(), predictor, run_id, flow_log, alert_log)
                flows += n_flows
                alerts += n_alerts
                ready.clear()

    while not STOP.is_set():
        if duration_seconds and time.monotonic() - started >= duration_seconds:
            STOP.set()
            break
        try:
            item = raw_queue.get(timeout=0.25)
            if isinstance(item, Exception):
                raise item
            if item is None:
                producer_done = True
            else:
                event_ms = int(item["event_time_ms"])
                newest_event_ms = max(newest_event_ms, event_ms)
                newest_wall_monotonic = time.monotonic()
                heapq.heappush(pending, (event_ms, sequence, item))
                sequence += 1
        except queue.Empty:
            pass
        elapsed_without_flow_ms = int((time.monotonic() - newest_wall_monotonic) * 1000)
        watermark = newest_event_ms + elapsed_without_flow_ms - ordering_delay_ms
        flush_ready(watermark)
        if ready and (len(ready) >= batch_size or elapsed_without_flow_ms >= ordering_delay_ms):
            n_flows, n_alerts = analyze(ready.copy(), predictor, run_id, flow_log, alert_log)
            flows += n_flows
            alerts += n_alerts
            ready.clear()
        if producer_done and raw_queue.empty():
            break

    flush_ready(sys.maxsize)
    if ready:
        n_flows, n_alerts = analyze(ready, predictor, run_id, flow_log, alert_log)
        flows += n_flows
        alerts += n_alerts
    STOP.set()
    summary = {
        "run_id": run_id,
        "model_version": predictor.meta["model_version"],
        "threshold": predictor.meta["threshold"],
        "flows": flows,
        "alerts": alerts,
        "started_at": datetime.fromtimestamp(time.time() - (time.monotonic() - started), timezone.utc).isoformat(),
        "finished_at": utc_now(),
    }
    (output_dir / "monitor_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--iface")
    source.add_argument("--pcap")
    parser.add_argument("--models-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--alert-log", type=Path, default=None,
                        help="Ruta estable consumida por Wazuh; por defecto output-dir/alerts.json")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--duration-seconds", type=int, default=0)
    parser.add_argument("--ordering-delay-ms", type=int, default=6000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--device", choices=("cpu", "auto", "cuda"), default="cpu",
                        help="Dispositivo de inferencia; producción usa cpu")
    parser.add_argument("--bpf-filter", default=None,
                        help="Filtro BPF para aislar los hosts del experimento")
    parser.add_argument("--include-ip", action="append", default=[],
                        help="Conserva flujos que involucren esta IP; puede repetirse")
    args = parser.parse_args()
    if args.duration_seconds < 0 or args.ordering_delay_ms < 0 or args.batch_size < 1:
        parser.error("duración/delay deben ser >=0 y batch-size >=1")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _s, _f: STOP.set())
    STOP.clear()
    predictor = EnsemblePredictor(args.models_dir, device=args.device)
    predictor.load_models()
    summary = run_monitor(
        args.iface or args.pcap, bool(args.iface), predictor, args.run_id,
        args.output_dir, args.duration_seconds, args.ordering_delay_ms, args.batch_size,
        args.bpf_filter, set(args.include_ip) or None, args.alert_log,
    )
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()

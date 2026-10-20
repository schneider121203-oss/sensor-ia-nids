"""Recolector NDJSON para construir el dataset benigno NFStream de v4."""

from __future__ import annotations

import argparse
import heapq
import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

import nfstream

from nfstream_native_extractor import FirstTTLPlugin, NFStreamNativeExtractor


stop_requested = False


def request_stop(_signum, _frame) -> None:
    global stop_requested
    stop_requested = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Recolector NFStream nativo v4")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--iface")
    source.add_argument("--pcap")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", default="benign_native_collection")
    parser.add_argument("--max-flows", type=int, default=0, help="0 significa sin límite")
    parser.add_argument("--ordering-delay-ms", type=int, default=6000,
                        help="Margen para ordenar cierres NFStream fuera de orden")
    args = parser.parse_args()
    if args.max_flows < 0:
        parser.error("--max-flows debe ser >= 0")
    if args.ordering_delay_ms < 0:
        parser.error("--ordering-delay-ms debe ser >= 0")

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    extractor = NFStreamNativeExtractor()
    stream = nfstream.NFStreamer(
        source=args.iface or args.pcap,
        statistical_analysis=True,
        udps=[FirstTTLPlugin()],
        idle_timeout=2 if args.iface else 120,
        active_timeout=5 if args.iface else 1800,
    )
    collected = 0
    sequence = 0
    newest_event_time_ms = 0
    pending: list[tuple[int, int, dict]] = []

    def write_record(output, record: dict) -> None:
        nonlocal collected
        contextual = extractor.enrich_context(record)
        contextual.update({
            "dataset_version": "v4-native",
            "run_id": args.run_id,
            "scenario": args.scenario,
            "capture_label": "benign",
            "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        output.write(json.dumps(contextual, ensure_ascii=False) + "\n")
        collected += 1

    with args.output.open("a", encoding="utf-8") as output:
        for flow in stream:
            if stop_requested or (args.max_flows and collected >= args.max_flows):
                break
            row = extractor.extract_raw(flow)
            newest_event_time_ms = max(newest_event_time_ms, int(row["event_time_ms"]))
            heapq.heappush(pending, (int(row["event_time_ms"]), sequence, row))
            sequence += 1
            watermark = newest_event_time_ms - args.ordering_delay_ms
            while pending and pending[0][0] <= watermark:
                _, _, next_row = heapq.heappop(pending)
                write_record(output, next_row)
        while pending:
            _, _, next_row = heapq.heappop(pending)
            write_record(output, next_row)
    print(json.dumps({"run_id": args.run_id, "flows": collected, "output": str(args.output)}))


if __name__ == "__main__":
    main()

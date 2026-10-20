"""Reconstruye los contadores v4 a partir de flujos crudos ordenados por tiempo.

No sobrescribe la evidencia original: produce un NDJSON cronológico derivado.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "sensor"))

from feature_contract_v4_native import TimeWindowFlowContext  # noqa: E402


CONTEXT_COLUMNS = {
    "ct_dst_60s", "ct_src_dport_60s", "ct_dst_sport_60s", "ct_dst_src_60s", "ct_src_60s",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line]
    rows.sort(key=lambda row: int(row["event_time_ms"]))
    context = TimeWindowFlowContext()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as output:
        for row in rows:
            for column in CONTEXT_COLUMNS:
                row.pop(column, None)
            metadata = {key: row[key] for key in ("src_ip", "dst_ip", "sport", "dport")}
            row.update(context.enrich(metadata, int(row["event_time_ms"])))
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"input_rows": len(rows), "output": str(args.output)}))


if __name__ == "__main__":
    main()

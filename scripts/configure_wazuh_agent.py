#!/usr/bin/env python3
"""Configura manager y localfile JSON sin duplicar bloques de Wazuh."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
from pathlib import Path

START = "  <!-- SENSOR_IA_NIDS_START -->"
END = "  <!-- SENSOR_IA_NIDS_END -->"


def configure(content: str, manager: str, alert_log: str) -> str:
    client = re.search(r"(<client>.*?</client>)", content, flags=re.DOTALL)
    if not client:
        raise ValueError("ossec.conf no contiene un bloque <client>")
    updated_client, count = re.subn(
        r"(<address>)[^<]+(</address>)",
        rf"\g<1>{manager}\g<2>",
        client.group(1),
        count=1,
    )
    if count != 1:
        raise ValueError("el bloque <client> no contiene <address>")
    content = content[:client.start(1)] + updated_client + content[client.end(1):]

    block = (
        f"{START}\n"
        "  <localfile>\n"
        "    <log_format>json</log_format>\n"
        f"    <location>{alert_log}</location>\n"
        "  </localfile>\n"
        f"{END}\n"
    )
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END) + r"\n?", re.DOTALL)
    content, found = pattern.subn(block, content, count=1)
    if not found:
        close = content.rfind("</ossec_config>")
        if close < 0:
            raise ValueError("ossec.conf no contiene </ossec_config>")
        content = content[:close] + block + content[close:]
    return content


def remove_localfile(content: str) -> str:
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END) + r"\n?", re.DOTALL)
    return pattern.sub("", content)


def atomic_write(path: Path, content: str) -> None:
    stat = path.stat()
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    os.chown(temporary, stat.st_uid, stat.st_gid)
    os.chmod(temporary, stat.st_mode)
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manager")
    parser.add_argument("--alert-log")
    parser.add_argument("--remove-localfile", action="store_true")
    args = parser.parse_args()
    original = args.config.read_text(encoding="utf-8")
    backup = args.config.with_suffix(args.config.suffix + ".sensor-ia-nids.bak")
    if not backup.exists():
        shutil.copy2(args.config, backup)
    if args.remove_localfile:
        updated = remove_localfile(original)
    else:
        if not args.manager or not args.alert_log:
            parser.error("--manager y --alert-log son obligatorios")
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", args.manager):
            parser.error("manager inválido")
        updated = configure(original, args.manager, args.alert_log)
    if updated != original:
        atomic_write(args.config, updated)
        print(f"Configuración actualizada: {args.config}")
    else:
        print("Configuración ya estaba en el estado solicitado")


if __name__ == "__main__":
    main()

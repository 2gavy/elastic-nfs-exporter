#!/usr/bin/env python3
"""Notify Tines when an exporter manifest reaches a terminal state."""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


LOG = logging.getLogger("elastic_export_callback_watcher")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def post_callback(url: str, payload: dict) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        response.read()


def main() -> int:
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    export_dir = Path(env("NFS_EXPORT_DIR", "/exports"))
    callback_url = env("TINES_CALLBACK_URL")
    display_root = env("NFS_DISPLAY_PATH", str(export_dir)).rstrip("/")
    interval = max(2.0, float(env("WATCH_INTERVAL_SECONDS", "10")))
    if not callback_url:
        raise RuntimeError("TINES_CALLBACK_URL is required")

    LOG.info("Watching %s for completed export manifests", export_dir)
    while True:
        for manifest_path in sorted(export_dir.glob("exp-*.json")):
            marker = export_dir / f".{manifest_path.stem}.callback-sent"
            if marker.exists():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if manifest.get("status") not in {"complete", "failed"}:
                continue
            payload = dict(manifest)
            filename = str(payload.get("filename") or "")
            payload["nfs_path"] = f"{display_root}/{filename}" if filename else ""
            try:
                post_callback(callback_url, payload)
                marker.write_text(str(time.time()), encoding="utf-8")
                LOG.info("Notified Tines for %s (%s)", payload.get("job_id"), payload.get("status"))
            except (urllib.error.URLError, OSError):
                LOG.warning("Tines callback failed for %s; will retry", payload.get("job_id"), exc_info=True)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Stream Elasticsearch Discover results into ZIP-packaged CSV files on NFS."""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import logging
import os
import queue
import re
import shutil
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


LOG = logging.getLogger("elastic_nfs_exporter")
REQUEST_LINE = re.compile(r"(?:POST|GET)\s+/([^?\s]+?)/(?:_async_search|_search)(?:\?[^\s]*)?", re.I)
SAFE_INDEX = re.compile(r"[A-Za-z0-9_.*?,:-]+")
SAFE_EXPORT_NAME = re.compile(r"[^A-Za-z0-9._-]+")
UTF8_BOM = b"\xef\xbb\xbf"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def artifact_base_name(export_name: Any, job_id: str) -> str:
    requested = str(export_name or "").strip()
    if requested.lower().endswith(".zip"):
        requested = requested[:-4]
    safe = SAFE_EXPORT_NAME.sub("-", requested).strip("-._")
    safe = re.sub(r"[-_.]{2,}", "-", safe)[:80].rstrip("-._")
    if not safe:
        return job_id
    return f"{safe}-{job_id.rsplit('-', 1)[-1]}"


def display_path(root: str, filename: str) -> str:
    """Return the analyst-facing NFS/SMB path without changing the mounted path."""
    cleaned = str(root or "").strip()
    if not cleaned:
        return ""
    if cleaned.startswith("\\\\"):
        return cleaned.rstrip("\\") + "\\" + filename
    return cleaned.rstrip("/") + "/" + filename


def parse_discover_request(raw: str) -> tuple[str, dict[str, Any]]:
    text = str(raw or "").strip()
    first_brace = text.find("{")
    if first_brace < 0:
        raise ValueError("The pasted request does not contain a JSON body")
    prefix = text[:first_brace]
    match = REQUEST_LINE.search(prefix)
    if not match:
        raise ValueError("Expected a Discover request ending in /_async_search or /_search")
    index_pattern = urllib.parse.unquote(match.group(1))
    if not SAFE_INDEX.fullmatch(index_pattern):
        raise ValueError("The request contains an unsupported index expression")
    body = json.loads(text[first_brace:])
    if not isinstance(body, dict):
        raise ValueError("The request JSON body must be an object")
    return index_pattern, body


def flatten(value: Any, prefix: str = "", output: dict[str, Any] | None = None) -> dict[str, Any]:
    result = output if output is not None else {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flatten(child, path, result)
    elif prefix:
        result[prefix] = value
    return result


def cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    elif isinstance(value, (dict, tuple)):
        value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    text = str(value)
    if env("CSV_SAFE_FOR_SPREADSHEETS", "true").lower() == "true" and text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


class ElasticClient:
    def __init__(self) -> None:
        self.base_url = env("ELASTICSEARCH_URL").rstrip("/")
        self.api_key = env("ELASTICSEARCH_API_KEY")
        if not self.base_url or not self.api_key:
            raise RuntimeError("ELASTICSEARCH_URL and ELASTICSEARCH_API_KEY are required")

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        attempts = max(1, int(env("ELASTICSEARCH_RETRY_ATTEMPTS", "6")))
        delay = max(0.1, float(env("ELASTICSEARCH_RETRY_INITIAL_SECONDS", "1")))
        retryable = {429, 502, 503, 504}
        for attempt in range(1, attempts + 1):
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request(
                self.base_url + path,
                data=data,
                method=method,
                headers={"Authorization": f"ApiKey {self.api_key}", "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=int(env("ELASTICSEARCH_TIMEOUT_SECONDS", "120"))) as response:
                    return json.loads(response.read())
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:2000]
                if exc.code not in retryable or attempt == attempts:
                    raise RuntimeError(f"Elasticsearch {method} {path} failed with HTTP {exc.code}: {detail}") from exc
                LOG.warning(
                    "Elasticsearch returned HTTP %s for %s %s; retrying in %.1fs (%d/%d)",
                    exc.code, method, path, delay, attempt, attempts,
                )
            except urllib.error.URLError as exc:
                if attempt == attempts:
                    raise RuntimeError(f"Elasticsearch {method} {path} failed after {attempts} attempts: {exc}") from exc
                LOG.warning(
                    "Elasticsearch connection failed for %s %s; retrying in %.1fs (%d/%d)",
                    method, path, delay, attempt, attempts,
                )
            time.sleep(delay)
            delay = min(delay * 2, float(env("ELASTICSEARCH_RETRY_MAX_SECONDS", "30")))
        raise RuntimeError("Elasticsearch retry loop exited unexpectedly")


def normalize_search(body: dict[str, Any], pit_id: str) -> dict[str, Any]:
    allowed = {
        "query", "fields", "runtime_mappings", "script_fields", "docvalue_fields",
        "version", "_source", "stored_fields", "terminate_after", "min_score", "sort",
    }
    search = {key: value for key, value in body.items() if key in allowed}
    page_size = max(100, min(int(env("ELASTICSEARCH_PAGE_SIZE", "5000")), 10000))
    search["size"] = page_size
    search["track_total_hits"] = env("CALCULATE_TOTAL_HITS", "true").lower() == "true"
    search["pit"] = {"id": pit_id, "keep_alive": env("ELASTICSEARCH_PIT_KEEP_ALIVE", "1h")}
    normalized_sort = []
    for item in search.get("sort") or []:
        if isinstance(item, dict) and "_doc" in item:
            normalized_sort.append({"_shard_doc": item["_doc"]})
        elif item == "_doc":
            normalized_sort.append("_shard_doc")
        else:
            normalized_sort.append(item)
    if not any((item == "_shard_doc") or (isinstance(item, dict) and "_shard_doc" in item) for item in normalized_sort):
        normalized_sort.append({"_shard_doc": "asc"})
    search["sort"] = normalized_sort
    search.pop("search_after", None)
    return search


def requested_patterns(body: dict[str, Any]) -> list[str]:
    patterns = []
    for entry in body.get("fields") or []:
        if isinstance(entry, str):
            patterns.append(entry)
        elif isinstance(entry, dict) and entry.get("field"):
            patterns.append(str(entry["field"]))
    return patterns or ["*"]


def ordered_headers(field_names: list[str]) -> list[str]:
    priority = ["_index", "_id", "@timestamp", "message", "event.kind", "event.category", "event.action"]
    available = set(field_names)
    headers = [name for name in priority if name in available or name.startswith("_")]
    headers.extend(sorted(available.difference(headers)))
    return headers


def total_hits(response: dict[str, Any]) -> int | None:
    total = (response.get("hits") or {}).get("total")
    if isinstance(total, int):
        return total
    if isinstance(total, dict) and total.get("value") is not None:
        return int(total["value"])
    return None


def progress_snapshot(
    job_id: str,
    index_pattern: str,
    record_count: int,
    page_count: int,
    total_records: int | None,
    started: float,
) -> dict[str, Any]:
    elapsed = max(0.001, time.monotonic() - started)
    rate = record_count / elapsed
    percent = None
    eta = None
    if total_records is not None:
        percent = 100.0 if total_records == 0 else min(100.0, record_count * 100.0 / total_records)
        if rate > 0:
            eta = max(0.0, (total_records - record_count) / rate)
    return {
        "job_id": job_id,
        "status": "running",
        "index_pattern": index_pattern,
        "record_count": record_count,
        "total_records": total_records,
        "page_count": page_count,
        "percent_complete": round(percent, 2) if percent is not None else None,
        "records_per_second": round(rate, 2),
        "elapsed_seconds": round(elapsed, 1),
        "eta_seconds": round(eta, 1) if eta is not None else None,
        "updated_at": utc_now(),
    }


def progress_bar(percent: float | None, width: int = 20) -> str:
    if percent is None:
        return "[progress unavailable]"
    filled = max(0, min(width, round(width * percent / 100.0)))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


class ExportWorker:
    def __init__(self) -> None:
        self.export_dir = Path(env("NFS_EXPORT_DIR", "/exports"))
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.callback_url = env("TINES_CALLBACK_URL")
        self.download_base_url = env("DOWNLOAD_BASE_URL").rstrip("/")
        self.nfs_display_path = env("NFS_DISPLAY_PATH", str(self.export_dir))
        self.jobs: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=int(env("MAX_QUEUED_JOBS", "20")))
        self.status: dict[str, dict[str, Any]] = {}
        self._restore_jobs()
        threading.Thread(target=self._run, name="export-worker", daemon=True).start()

    def _restore_jobs(self) -> None:
        for manifest_path in sorted(self.export_dir.glob("exp-*.json")):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job_id = str(manifest.get("job_id") or manifest_path.stem)
            self.status[job_id] = manifest
            if manifest.get("status") == "complete":
                shutil.rmtree(self.export_dir / f".{job_id}.parts", ignore_errors=True)
            if manifest.get("status") not in {"queued", "running"}:
                continue
            if not isinstance(manifest.get("body"), dict) or not manifest.get("index_pattern"):
                continue
            self.jobs.put_nowait(
                {
                    "job_id": job_id,
                    "index_pattern": manifest["index_pattern"],
                    "body": manifest["body"],
                    "submitted_at": manifest.get("submitted_at") or utc_now(),
                    "export_name": manifest.get("export_name") or "",
                    "artifact_base": manifest.get("artifact_base") or job_id,
                }
            )
            LOG.info("Restored export %s from its last committed checkpoint", job_id)

    def submit(self, raw_request: str, export_name: Any = "") -> dict[str, Any]:
        index_pattern, body = parse_discover_request(raw_request)
        job_id = f"exp-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        requested_export_name = str(export_name or "").strip()[:200]
        job = {
            "job_id": job_id,
            "index_pattern": index_pattern,
            "body": body,
            "submitted_at": utc_now(),
            "export_name": requested_export_name,
            "artifact_base": artifact_base_name(requested_export_name, job_id),
        }
        self.status[job_id] = {
            **job,
            "status": "queued",
            "phase": "collecting",
            "record_count": 0,
            "page_count": 0,
            "search_after": None,
            "csv_filenames": [],
            "current_part_number": 1,
            "current_part_rows": 0,
            "current_part_committed_bytes": 0,
        }
        atomic_json(self.export_dir / f"{job_id}.json", self.status[job_id])
        self.jobs.put_nowait(job)
        LOG.info(
            "QUEUED job_id=%s export_name=%s index=%s status_path=/jobs/%s",
            job_id,
            requested_export_name or "(automatic)",
            index_pattern,
            job_id,
        )
        return self.status[job_id]

    def _run(self) -> None:
        while True:
            job = self.jobs.get()
            try:
                self._export(job)
            except Exception as exc:  # noqa: BLE001 - worker must report every failure
                LOG.exception("Export %s failed", job["job_id"])
                previous = self.status.get(job["job_id"], {})
                result = {**previous, "job_id": job["job_id"], "status": "failed", "error": str(exc), "completed_at": utc_now()}
                self.status[job["job_id"]] = result
                atomic_json(self.export_dir / f"{job['job_id']}.json", result)
                self._callback(result)
            finally:
                self.jobs.task_done()

    def _export(self, job: dict[str, Any]) -> None:
        started = time.monotonic()
        job_id = job["job_id"]
        manifest_path = self.export_dir / f"{job_id}.json"
        manifest = dict(self.status.get(job_id) or {})
        manifest.update(
            {
                "job_id": job_id,
                "index_pattern": job["index_pattern"],
                "body": job["body"],
                "export_name": manifest.get("export_name") or job.get("export_name") or "",
                "artifact_base": manifest.get("artifact_base") or job.get("artifact_base") or job_id,
                "submitted_at": manifest.get("submitted_at") or job.get("submitted_at") or utc_now(),
                "status": "running",
                "phase": manifest.get("phase") or "collecting",
                "started_at": manifest.get("started_at") or utc_now(),
                "resumed_at": utc_now() if manifest.get("record_count", 0) else None,
            }
        )
        self.status[job_id] = manifest
        atomic_json(manifest_path, manifest)
        LOG.info(
            "%s job_id=%s artifact=%s records_from_checkpoint=%s pages_from_checkpoint=%s",
            "RESUMING" if manifest.get("record_count", 0) else "STARTING",
            job_id,
            manifest.get("artifact_base") or job_id,
            manifest.get("record_count", 0),
            manifest.get("page_count", 0),
        )
        LOG.info(
            "PROGRESS job_id=%s %s 0.00%% | %s/? records | ETA calculating",
            job_id,
            progress_bar(0.0),
            f"{int(manifest.get('record_count') or 0):,}",
        )

        if manifest["phase"] == "assembling":
            self._assemble(job, manifest, started)
            return

        elastic = ElasticClient()
        encoded_index = urllib.parse.quote(job["index_pattern"], safe="*,:-._")
        keep_alive_value = env("ELASTICSEARCH_PIT_KEEP_ALIVE", "1h")
        keep_alive = urllib.parse.quote(keep_alive_value)
        pit_id = str(manifest.get("pit_id") or "")
        if not pit_id:
            pit = elastic.request("POST", f"/{encoded_index}/_pit?keep_alive={keep_alive}&ignore_unavailable=true")
            pit_id = str(pit["id"])
            manifest["pit_id"] = pit_id
            self.status[job_id] = manifest
            atomic_json(manifest_path, manifest)
        search = normalize_search(job["body"], pit_id)
        if manifest.get("search_after") is not None:
            search["search_after"] = manifest["search_after"]
        headers = list(manifest.get("headers") or [])
        if not headers:
            patterns = requested_patterns(job["body"])
            caps = elastic.request(
                "POST",
                f"/{encoded_index}/_field_caps?include_unmapped=true&ignore_unavailable=true",
                {"fields": patterns},
            )
            headers = ordered_headers(list((caps.get("fields") or {}).keys()))
        record_count = int(manifest.get("record_count") or 0)
        page_count = int(manifest.get("page_count") or 0)
        total_records = manifest.get("total_records")
        if total_records is not None:
            total_records = int(total_records)
            search["track_total_hits"] = False
        max_records = max(0, int(env("MAX_RECORDS", "0")))
        page_delay = max(0.0, float(env("EXPORT_PAGE_DELAY_SECONDS", "0.5")))
        csv_rows_per_file = max(1, int(env("CSV_ROWS_PER_FILE", "200000")))
        truncated = bool(manifest.get("truncated", False))
        csv_filenames = list(manifest.get("csv_filenames") or [])
        current_part_number = int(manifest.get("current_part_number") or (len(csv_filenames) + 1))
        current_part_rows = int(manifest.get("current_part_rows") or 0)
        committed_bytes = int(manifest.get("current_part_committed_bytes") or 0)
        part_dir = self.export_dir / f".{job_id}.parts"
        part_dir.mkdir(parents=True, exist_ok=True)
        text_file: Any = None
        binary_file: Any = None
        writer: Any = None
        collection_complete = False
        artifact_base = str(manifest.get("artifact_base") or job_id)

        def current_names() -> tuple[str, Path, Path]:
            name = f"{artifact_base}-part-{current_part_number:04d}.csv"
            return name, part_dir / f".{name}.partial", part_dir / name

        def open_current_part() -> None:
            nonlocal text_file, binary_file, writer
            _, partial_path, final_part_path = current_names()
            if not partial_path.exists() and final_part_path.exists():
                os.replace(final_part_path, partial_path)
            binary_file = partial_path.open("r+b") if partial_path.exists() else partial_path.open("w+b")
            binary_file.truncate(committed_bytes)
            binary_file.seek(committed_bytes)
            if committed_bytes == 0:
                binary_file.write(UTF8_BOM)
            text_file = __import__("io").TextIOWrapper(binary_file, encoding="utf-8", newline="")
            writer = csv.writer(text_file)
            if committed_bytes == 0:
                writer.writerow(headers)

        def commit_open_part() -> int:
            text_file.flush()
            os.fsync(binary_file.fileno())
            return binary_file.tell()

        def close_open_part() -> None:
            nonlocal text_file, binary_file, writer
            if text_file is not None:
                text_file.close()
            text_file = None
            binary_file = None
            writer = None

        try:
            while True:
                response = elastic.request("POST", "/_search", search)
                pit_id = str(response.get("pit_id") or pit_id)
                if total_records is None:
                    total_records = total_hits(response)
                    if max_records and total_records is not None:
                        total_records = min(total_records, max_records)
                    search["track_total_hits"] = False
                hits = ((response.get("hits") or {}).get("hits") or [])
                if not hits:
                    break
                if text_file is None:
                    open_current_part()
                for hit in hits:
                    if max_records and record_count >= max_records:
                        truncated = True
                        break
                    values = flatten(hit.get("_source") or {})
                    values.update(hit.get("fields") or {})
                    values["_index"] = hit.get("_index")
                    values["_id"] = hit.get("_id")
                    writer.writerow([cell(values.get(key)) for key in headers])
                    record_count += 1
                    current_part_rows += 1
                page_count += 1
                committed_bytes = commit_open_part()
                search_after = hits[-1]["sort"]

                if current_part_rows >= csv_rows_per_file:
                    name, partial_path, final_part_path = current_names()
                    close_open_part()
                    os.replace(partial_path, final_part_path)
                    csv_filenames.append(name)
                    current_part_number += 1
                    current_part_rows = 0
                    committed_bytes = 0

                progress = progress_snapshot(
                    job_id, job["index_pattern"], record_count, page_count, total_records, started
                )
                manifest.update(
                    {
                        **progress,
                        "body": job["body"],
                        "phase": "collecting",
                        "headers": headers,
                        "pit_id": pit_id,
                        "search_after": search_after,
                        "csv_filenames": csv_filenames,
                        "current_part_number": current_part_number,
                        "current_part_rows": current_part_rows,
                        "current_part_committed_bytes": committed_bytes,
                        "csv_rows_per_file": csv_rows_per_file,
                        "truncated": truncated,
                    }
                )
                self.status[job_id] = manifest
                atomic_json(manifest_path, manifest)
                LOG.info(
                    "PROGRESS job_id=%s %s %s%% | %s/%s records | %.1f records/s | ETA %ss",
                    job_id,
                    progress_bar(progress["percent_complete"]),
                    progress["percent_complete"] if progress["percent_complete"] is not None else "?",
                    f"{record_count:,}",
                    f"{total_records:,}" if total_records is not None else "?",
                    progress["records_per_second"],
                    progress["eta_seconds"] if progress["eta_seconds"] is not None else "?",
                )
                if max_records and record_count >= max_records:
                    truncated = True
                    break
                search["pit"] = {"id": pit_id, "keep_alive": keep_alive_value}
                search["search_after"] = search_after
                if page_delay:
                    time.sleep(page_delay)

            if text_file is None and not csv_filenames:
                open_current_part()
                committed_bytes = commit_open_part()
            if text_file is not None:
                name, partial_path, final_part_path = current_names()
                commit_open_part()
                close_open_part()
                os.replace(partial_path, final_part_path)
                csv_filenames.append(name)
            manifest.update(
                {
                    "status": "running",
                    "phase": "assembling",
                    "record_count": record_count,
                    "total_records": total_records,
                    "page_count": page_count,
                    "search_after": search.get("search_after"),
                    "csv_filenames": csv_filenames,
                    "current_part_rows": 0,
                    "current_part_committed_bytes": 0,
                    "truncated": truncated,
                    "updated_at": utc_now(),
                }
            )
            self.status[job_id] = manifest
            atomic_json(manifest_path, manifest)
            collection_complete = True
        finally:
            if text_file is not None:
                close_open_part()
            if collection_complete:
                try:
                    elastic.request("DELETE", "/_pit", {"id": pit_id})
                except Exception:
                    LOG.warning("Could not close PIT for %s", job_id, exc_info=True)

        self._assemble(job, manifest, started)

    def _assemble(self, job: dict[str, Any], manifest: dict[str, Any], started: float) -> None:
        job_id = job["job_id"]
        manifest_path = self.export_dir / f"{job_id}.json"
        artifact_base = str(manifest.get("artifact_base") or job.get("artifact_base") or job_id)
        filename = f"{artifact_base}.zip"
        partial_path = self.export_dir / f".{filename}.partial"
        final_path = self.export_dir / filename
        part_dir = self.export_dir / f".{job_id}.parts"
        csv_filenames = list(manifest.get("csv_filenames") or [])
        if not csv_filenames:
            raise RuntimeError("No committed CSV parts are available for ZIP assembly")
        if partial_path.exists():
            partial_path.unlink()
        with zipfile.ZipFile(
            partial_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=1,
            allowZip64=True,
        ) as archive:
            for csv_filename in csv_filenames:
                part_path = part_dir / csv_filename
                if not part_path.is_file():
                    raise RuntimeError(f"Committed CSV part is missing: {csv_filename}")
                archive.write(part_path, arcname=csv_filename)
        os.replace(partial_path, final_path)

        sha256 = hashlib.sha256()
        with final_path.open("rb") as completed_file:
            for chunk in iter(lambda: completed_file.read(1024 * 1024), b""):
                sha256.update(chunk)

        record_count = int(manifest.get("record_count") or 0)
        total_records = manifest.get("total_records")
        result = {
            "job_id": job_id,
            "status": "complete",
            "index_pattern": job["index_pattern"],
            "export_name": manifest.get("export_name") or "",
            "artifact_base": artifact_base,
            "record_count": int(manifest.get("record_count") or 0),
            "total_records": total_records,
            "page_count": int(manifest.get("page_count") or 0),
            "percent_complete": 100.0 if total_records is not None else None,
            "records_per_second": round(record_count / max(0.001, time.monotonic() - started), 2),
            "eta_seconds": 0.0 if total_records is not None else None,
            "truncated": bool(manifest.get("truncated", False)),
            "max_records": max(0, int(env("MAX_RECORDS", "0"))),
            "filename": filename,
            "csv_filename": csv_filenames[0],
            "csv_filenames": csv_filenames,
            "csv_part_count": len(csv_filenames),
            "csv_rows_per_file": int(manifest.get("csv_rows_per_file") or env("CSV_ROWS_PER_FILE", "200000")),
            "file_path": str(final_path),
            "nfs_path": display_path(
                getattr(self, "nfs_display_path", str(self.export_dir)),
                filename,
            ),
            "compressed_bytes": final_path.stat().st_size,
            "sha256": sha256.hexdigest(),
            "download_url": f"{self.download_base_url}/{urllib.parse.quote(filename)}" if self.download_base_url else "",
            "completed_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        atomic_json(manifest_path, result)
        self.status[job_id] = result
        LOG.info(
            "COMPLETED job_id=%s filename=%s records=%s csv_parts=%s duration_seconds=%s",
            job_id,
            filename,
            record_count,
            len(csv_filenames),
            result["duration_seconds"],
        )
        LOG.info(
            "PROGRESS job_id=%s %s 100.00%% | %s/%s records | ETA 0s",
            job_id,
            progress_bar(100.0),
            f"{record_count:,}",
            f"{int(total_records):,}" if total_records is not None else f"{record_count:,}",
        )
        self._callback(result)
        shutil.rmtree(part_dir)

    def _callback(self, result: dict[str, Any]) -> None:
        if not self.callback_url:
            return
        request = urllib.request.Request(
            self.callback_url,
            data=json.dumps(result).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response.read()
        except Exception:
            LOG.warning("Tines callback failed for %s", result["job_id"], exc_info=True)


class _TextWriter:
    """Minimal UTF-8 text adapter that does not close its binary stream."""

    def __init__(self, binary: Any) -> None:
        import io

        self.wrapper = io.TextIOWrapper(binary, encoding="utf-8", newline="", write_through=True)

    def __enter__(self) -> Any:
        return self.wrapper

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.wrapper.flush()
        self.wrapper.detach()


WORKER: ExportWorker | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ElasticNFSExporter/1.0"

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = env("EXPORT_API_TOKEN")
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(expected) and hmac.compare_digest(expected, supplied)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path.startswith("/jobs/"):
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            job_id = self.path.rsplit("/", 1)[-1]
            status = WORKER.status.get(job_id) if WORKER else None
            self._json(HTTPStatus.OK if status else HTTPStatus.NOT_FOUND, status or {"error": "job not found"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/exports":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > int(env("MAX_REQUEST_BYTES", "2097152")):
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length))
            raw_request = payload.get("request") or payload.get("discover_inspector_request")
            export_name = payload.get("export_name") or payload.get("report_name") or ""
            result = WORKER.submit(raw_request, export_name) if WORKER else None
            self._json(HTTPStatus.ACCEPTED, result or {"error": "worker unavailable"})
        except queue.Full:
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "export queue is full"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        request_line = str(args[0]) if args else ""
        if request_line.startswith("GET /jobs/") or request_line.startswith("GET /health"):
            LOG.debug("%s - %s", self.client_address[0], format % args)
            return
        LOG.info("%s - %s", self.client_address[0], format % args)


def main() -> int:
    global WORKER
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    WORKER = ExportWorker()
    address = (env("LISTEN_ADDRESS", "0.0.0.0"), int(env("PORT", "8080")))
    LOG.info("Starting exporter on %s:%d", *address)
    ThreadingHTTPServer(address, Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

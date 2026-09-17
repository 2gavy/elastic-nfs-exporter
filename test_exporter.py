import hashlib
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import exporter
from exporter import (
    ExportWorker,
    UTF8_BOM,
    _TextWriter,
    artifact_base_name,
    cell,
    display_path,
    flatten,
    parse_discover_request,
    progress_bar,
    progress_snapshot,
    total_hits,
)


class ExporterTests(unittest.TestCase):
    def test_parse_full_discover_request(self):
        index, body = parse_discover_request(
            'POST /shared-data-cluster:logs-*/_async_search?wait_for_completion_timeout=200ms\n'
            '{"query":{"match_all":{}},"sort":["_doc"]}'
        )
        self.assertEqual(index, "shared-data-cluster:logs-*")
        self.assertEqual(body["query"], {"match_all": {}})

    def test_flatten(self):
        self.assertEqual(flatten({"host": {"name": "server01"}}), {"host.name": "server01"})

    def test_spreadsheet_formula_is_escaped(self):
        os.environ["CSV_SAFE_FOR_SPREADSHEETS"] = "true"
        self.assertEqual(cell("=cmd()"), "'=cmd()")

    def test_export_name_is_safe_readable_and_unique(self):
        job_id = "exp-20260818T000000Z-deadbeef"
        self.assertEqual(
            artifact_base_name("Security Alerts 2026-08-01 to 2026-08-18.zip", job_id),
            "Security-Alerts-2026-08-01-to-2026-08-18-deadbeef",
        )
        self.assertEqual(artifact_base_name("../", job_id), job_id)

    def test_customer_facing_share_paths(self):
        self.assertEqual(
            display_path(r"\\fileserver\security-exports", "alerts.zip"),
            r"\\fileserver\security-exports\alerts.zip",
        )
        self.assertEqual(
            display_path("/mnt/security-exports", "alerts.zip"),
            "/mnt/security-exports/alerts.zip",
        )

    def test_callback_is_marked_and_not_sent_twice(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return b"accepted"

        with tempfile.TemporaryDirectory() as directory:
            worker = ExportWorker.__new__(ExportWorker)
            worker.export_dir = exporter.Path(directory)
            worker.callback_url = "https://tenant.tines.com/webhook/path/secret"
            worker.nfs_display_path = r"\\fileserver\security-exports"
            worker.callback_lock = exporter.threading.Lock()
            result = {
                "job_id": "exp-callback",
                "status": "complete",
                "filename": "alerts.zip",
            }
            with patch("exporter.urllib.request.urlopen", return_value=Response()) as send:
                worker._callback(result)
                worker._callback(result)
            self.assertEqual(send.call_count, 1)
            self.assertTrue((worker.export_dir / ".exp-callback.callback-sent").is_file())
            payload = exporter.json.loads(send.call_args.args[0].data)
            self.assertEqual(
                payload["nfs_path"],
                r"\\fileserver\security-exports\alerts.zip",
            )

    def test_zip_stream(self):
        with tempfile.NamedTemporaryFile(suffix=".zip") as raw:
            with zipfile.ZipFile(raw, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                with archive.open("export.csv", mode="w", force_zip64=True) as csv_entry:
                    with _TextWriter(csv_entry) as text:
                        text.write("header\nvalue\n")
            raw.seek(0)
            stored = raw.read()
            self.assertEqual(len(hashlib.sha256(stored).hexdigest()), 64)
            raw.seek(0)
            with zipfile.ZipFile(raw) as archive:
                self.assertEqual(archive.read("export.csv").decode(), "header\nvalue\n")

    def test_progress_metrics(self):
        self.assertEqual(total_hits({"hits": {"total": {"value": 4000, "relation": "eq"}}}), 4000)
        snapshot = progress_snapshot("job", "logs-*", 1000, 1, 4000, exporter.time.monotonic() - 10)
        self.assertEqual(snapshot["percent_complete"], 25.0)
        self.assertGreater(snapshot["records_per_second"], 0)
        self.assertGreater(snapshot["eta_seconds"], 0)
        self.assertEqual(progress_bar(50), "[##########----------]")

    def test_field_caps_uses_body_and_export_stops_at_ceiling(self):
        class FakeElastic:
            def __init__(self):
                self.calls = []
                self.search_calls = 0

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if "_pit" in path and method == "POST":
                    return {"id": "pit-1"}
                if "_field_caps" in path:
                    return {"fields": {"@timestamp": {}, "message": {}}}
                if path == "/_search":
                    self.search_calls += 1
                    index = self.search_calls - 1
                    return {
                        "pit_id": "pit-1",
                        "hits": {
                            "total": {"value": 3, "relation": "eq"},
                            "hits": [] if self.search_calls > 2 else [
                                {"_index": "logs-test", "_id": str(index), "_source": {"message": f"row-{index}"}, "sort": [index]}
                            ],
                        },
                    }
                return {}

        fake = FakeElastic()
        original = exporter.ElasticClient
        os.environ["MAX_RECORDS"] = "2"
        os.environ["CSV_ROWS_PER_FILE"] = "1"
        try:
            exporter.ElasticClient = lambda: fake
            with tempfile.TemporaryDirectory() as directory:
                worker = ExportWorker.__new__(ExportWorker)
                worker.export_dir = exporter.Path(directory)
                worker.download_base_url = ""
                worker.status = {"job-1": {"status": "queued"}}
                worker._callback = lambda result: None
                worker._export(
                    {
                        "job_id": "job-1",
                        "index_pattern": "logs-*",
                        "body": {"query": {"match_all": {}}, "fields": ["@timestamp", "message"]},
                    }
                )
                manifest = worker.status["job-1"]
                self.assertEqual(manifest["record_count"], 2)
                self.assertTrue(manifest["truncated"])
                self.assertEqual(manifest["filename"], "job-1.zip")
                self.assertEqual(manifest["csv_filename"], "job-1-part-0001.csv")
                self.assertEqual(manifest["csv_part_count"], 2)
                with zipfile.ZipFile(manifest["file_path"]) as archive:
                    first_csv = archive.read("job-1-part-0001.csv")
                    self.assertTrue(first_csv.startswith(UTF8_BOM))
                    csv_text = first_csv.decode("utf-8-sig")
                self.assertIn("row-0", csv_text)
                with zipfile.ZipFile(manifest["file_path"]) as archive:
                    second_csv = archive.read("job-1-part-0002.csv")
                    self.assertTrue(second_csv.startswith(UTF8_BOM))
                    second_csv_text = second_csv.decode("utf-8-sig")
                self.assertIn("row-1", second_csv_text)
                caps_call = next(call for call in fake.calls if "_field_caps" in call[1])
                self.assertNotIn("fields=", caps_call[1])
                self.assertEqual(caps_call[2], {"fields": ["@timestamp", "message"]})
        finally:
            exporter.ElasticClient = original
            os.environ.pop("MAX_RECORDS", None)
            os.environ.pop("CSV_ROWS_PER_FILE", None)

    def test_running_checkpoint_is_restored_to_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            export_dir = exporter.Path(directory)
            checkpoint = {
                "job_id": "exp-resume",
                "status": "running",
                "phase": "collecting",
                "index_pattern": "logs-*",
                "body": {"query": {"match_all": {}}},
                "record_count": 1000,
                "search_after": [123],
            }
            (export_dir / "exp-resume.json").write_text(exporter.json.dumps(checkpoint), encoding="utf-8")
            worker = ExportWorker.__new__(ExportWorker)
            worker.export_dir = export_dir
            worker.jobs = exporter.queue.Queue(maxsize=2)
            worker.status = {}
            worker._restore_jobs()
            restored = worker.jobs.get_nowait()
            self.assertEqual(restored["job_id"], "exp-resume")
            self.assertEqual(worker.status["exp-resume"]["search_after"], [123])

    def test_export_resumes_from_committed_page_with_same_pit(self):
        class ResumableElastic:
            def __init__(self, fail_after_first_page=False):
                self.fail_after_first_page = fail_after_first_page
                self.deleted_pit = False
                self.opened_pit = False

            def request(self, method, path, body=None):
                if "_pit" in path and method == "POST":
                    self.opened_pit = True
                    return {"id": "pit-resume"}
                if "_field_caps" in path:
                    return {"fields": {"message": {}}}
                if path == "/_search":
                    after = body.get("search_after")
                    if after is None:
                        return {
                            "pit_id": "pit-resume",
                            "hits": {
                                "total": {"value": 2, "relation": "eq"},
                                "hits": [{"_index": "logs-test", "_id": "0", "_source": {"message": "row-0"}, "sort": [0]}],
                            },
                        }
                    if after == [0] and self.fail_after_first_page:
                        raise RuntimeError("simulated disconnect")
                    if after == [0]:
                        return {
                            "pit_id": "pit-resume",
                            "hits": {
                                "hits": [{"_index": "logs-test", "_id": "1", "_source": {"message": "row-1"}, "sort": [1]}]
                            },
                        }
                    return {"pit_id": "pit-resume", "hits": {"hits": []}}
                if path == "/_pit" and method == "DELETE":
                    self.deleted_pit = True
                    return {"succeeded": True}
                return {}

        original = exporter.ElasticClient
        os.environ["EXPORT_PAGE_DELAY_SECONDS"] = "0"
        try:
            with tempfile.TemporaryDirectory() as directory:
                job = {
                    "job_id": "exp-resume",
                    "index_pattern": "logs-*",
                    "body": {"query": {"match_all": {}}, "fields": ["message"]},
                    "submitted_at": exporter.utc_now(),
                }
                first_client = ResumableElastic(fail_after_first_page=True)
                exporter.ElasticClient = lambda: first_client
                first_worker = ExportWorker.__new__(ExportWorker)
                first_worker.export_dir = exporter.Path(directory)
                first_worker.download_base_url = ""
                first_worker.status = {"exp-resume": {"status": "queued"}}
                first_worker._callback = lambda result: None
                with self.assertRaisesRegex(RuntimeError, "simulated disconnect"):
                    first_worker._export(job)
                checkpoint = exporter.json.loads(
                    (exporter.Path(directory) / "exp-resume.json").read_text(encoding="utf-8")
                )
                self.assertEqual(checkpoint["record_count"], 1)
                self.assertEqual(checkpoint["search_after"], [0])
                self.assertEqual(checkpoint["pit_id"], "pit-resume")
                self.assertFalse(first_client.deleted_pit)

                second_client = ResumableElastic()
                exporter.ElasticClient = lambda: second_client
                second_worker = ExportWorker.__new__(ExportWorker)
                second_worker.export_dir = exporter.Path(directory)
                second_worker.download_base_url = ""
                second_worker.status = {"exp-resume": checkpoint}
                second_worker._callback = lambda result: None
                second_worker._export(job)
                result = second_worker.status["exp-resume"]
                self.assertEqual(result["record_count"], 2)
                self.assertFalse(second_client.opened_pit)
                self.assertTrue(second_client.deleted_pit)
                with zipfile.ZipFile(result["file_path"]) as archive:
                    contents = archive.read(result["csv_filename"]).decode("utf-8-sig")
                self.assertEqual(contents.count("row-0"), 1)
                self.assertEqual(contents.count("row-1"), 1)
        finally:
            exporter.ElasticClient = original
            os.environ.pop("EXPORT_PAGE_DELAY_SECONDS", None)


if __name__ == "__main__":
    unittest.main()

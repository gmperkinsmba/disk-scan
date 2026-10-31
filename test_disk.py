import hashlib
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import disk


class DiskEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "scope"
        self.root.mkdir()
        self.state = tempfile.TemporaryDirectory()
        self.addCleanup(self.state.cleanup)
        self.state_dir = Path(self.state.name) / "state"
        self.settings = self.state_dir / "settings.json"
        self.history = self.state_dir / "history.json"
        self._patchers = [
            patch.object(disk, "STATE_DIR", self.state_dir),
            patch.object(disk, "SETTINGS_FILE", self.settings),
            patch.object(disk, "HISTORY_FILE", self.history),
        ]
        for item in self._patchers:
            item.start()
            self.addCleanup(item.stop)

    def test_exact_duplicate_is_hash_based_and_name_conflict_is_separate(self):
        (self.root / "one.bin").write_bytes(b"same bytes")
        (self.root / "renamed.dat").write_bytes(b"same bytes")
        (self.root / "left").mkdir()
        (self.root / "right").mkdir()
        (self.root / "left" / "config.json").write_bytes(b"left")
        (self.root / "right" / "config.json").write_bytes(b"right")
        result = disk.scan(self.root)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["duplicates"]), 1)
        self.assertEqual(set(result["duplicates"][0]["paths"]), {"one.bin", "renamed.dat"})
        self.assertEqual(len(result["same_name_different_content"]), 1)
        self.assertEqual(result["same_name_different_content"][0]["name"], "config.json")

    def test_growth_compares_sizes_after_successive_complete_scans(self):
        log = self.root / "activity.log"
        log.write_bytes(b"one")
        first = disk.scan(self.root)
        self.assertTrue(first["complete"])
        log.write_bytes(b"one plus")
        second = disk.scan(self.root)
        self.assertEqual(second["growth"][0]["growth_bytes"], 5)
        self.assertEqual(second["growth"][0]["path"], "activity.log")

    def test_symlink_root_and_nested_symlink_are_not_followed(self):
        target = Path(self.temp.name).resolve() / "target"
        target.mkdir()
        (target / "secret.txt").write_text("outside")
        link = self.root / "linked"
        link.symlink_to(target, target_is_directory=True)
        result = disk.scan(self.root)
        self.assertNotIn("linked/secret.txt", {row["path"] for row in result["files"]})
        root_link = Path(self.temp.name).resolve() / "scope-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            disk.scan(root_link)

    def test_scanning_does_not_change_fixture_bytes(self):
        (self.root / "data.bin").write_bytes(b"keep this exact content")
        before = (self.root / "data.bin").read_bytes()
        disk.scan(self.root)
        self.assertEqual((self.root / "data.bin").read_bytes(), before)

    def test_relative_exclusions_stay_inside_selected_scope(self):
        hidden = self.root / "private"
        hidden.mkdir()
        (hidden / "record.txt").write_text("excluded")
        (self.root / "visible.txt").write_text("included")
        result = disk.scan(self.root, exclusions=["private"])
        self.assertEqual({row["path"] for row in result["files"]}, {"visible.txt"})
        with self.assertRaises(ValueError):
            disk.validate_exclusions(["../outside"])
        with self.assertRaises(ValueError):
            disk.validate_exclusions(["/etc"])

    def test_count_and_byte_limits_mark_scan_incomplete_without_history_update(self):
        (self.root / "a").write_bytes(b"aa")
        (self.root / "b").write_bytes(b"bb")
        count_result = disk.scan(self.root, limits={"max_files": 1, "max_bytes": 100, "max_seconds": 5})
        self.assertFalse(count_result["complete"])
        self.assertIn("file limit", count_result["incomplete_reasons"])
        byte_result = disk.scan(self.root, limits={"max_files": 20, "max_bytes": 1, "max_seconds": 5})
        self.assertFalse(byte_result["complete"])
        self.assertIn("byte limit", byte_result["incomplete_reasons"])
        self.assertEqual(byte_result["history_status"], "not updated because scan was incomplete")

    def test_time_limit_is_enforced_inside_file_read(self):
        (self.root / "large").write_bytes(b"x" * (disk.CHUNK_SIZE * 2))
        ticks = iter([0.0, 0.0, 0.0, 2.0])
        with patch.object(disk.time, "monotonic", side_effect=lambda: next(ticks, 2.0)):
            result = disk.scan(self.root, limits={"max_files": 10, "max_bytes": 10_000_000, "max_seconds": 1})
        self.assertFalse(result["complete"])
        self.assertIn("time limit", result["incomplete_reasons"])

    def test_plan_recheck_marks_grown_duplicate_stale_with_bounded_read(self):
        (self.root / "a").write_bytes(b"same")
        (self.root / "b").write_bytes(b"same")
        result = disk.scan(self.root, limits={"max_files": 10, "max_bytes": 1000, "max_seconds": 5})
        (self.root / "b").write_bytes(b"same" * 1000)
        plan = disk.draft_plan(self.root, result, [{"sha256": result["duplicates"][0]["sha256"], "retain": "a"}])
        self.assertEqual(plan["entries"][0]["recheck_status"], "stale")
        self.assertIn("byte or time limit", plan["entries"][0]["reason"])
        self.assertFalse(plan["deletion_performed"])

    def test_draft_plan_never_performs_deletion(self):
        for name in ("a", "b"):
            (self.root / name).write_bytes(b"same")
        result = disk.scan(self.root)
        plan = disk.draft_plan(self.root, result, [{"sha256": hashlib.sha256(b"same").hexdigest(), "retain": "a"}])
        self.assertEqual(plan["entries"][0]["proposed_duplicates"], ["b"])
        self.assertFalse(plan["deletion_performed"])

    def test_http_state_boundary_and_absence_of_delete_route(self):
        server = disk.make_server(self.root, 0)
        server.request_token = "unit-test-token"
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/?desktop=1", headers={"Host": f"127.0.0.1:{port}"})
        page = connection.getresponse()
        markup = page.read().decode()
        self.assertEqual(page.status, 200)
        self.assertIn('data-token="unit-test-token"', markup)
        self.assertIn('src="/app.js"', markup)
        self.assertNotIn("<script>window.", markup)
        self.assertIn("script-src 'self'", page.getheader("Content-Security-Policy"))
        connection.close()

        def post(path, headers):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            connection.request("POST", path, body=json.dumps({}), headers={"Content-Type": "application/json", **headers})
            response = connection.getresponse()
            body = response.read()
            connection.close()
            return response.status, body

        authority = f"127.0.0.1:{port}"
        self.assertEqual(post("/api/config", {"Host": f"evil.test:{port}"})[0], 403)
        self.assertEqual(post("/api/config", {"Host": authority})[0], 403)
        self.assertEqual(post("/api/config", {"Host": authority, "Origin": f"http://evil.test:{port}", "X-Disk-Evidence-Request": "unit-test-token"})[0], 403)
        headers = {"Host": authority, "Origin": f"http://{authority}", "X-Disk-Evidence-Request": "unit-test-token"}
        self.assertEqual(post("/api/delete", headers)[0], 404)


if __name__ == "__main__":
    unittest.main()

"""Desktop security and owned backend lifecycle checks without opening a UI."""
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import disk
from build_desktop import write_notices
from desktop_policy import navigation_policy


class DesktopTests(unittest.TestCase):
    def test_notices_contain_verified_text_and_exclude_binary_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "notices.txt"
            write_notices(destination)
            notices = destination.read_text(encoding="utf-8")
        self.assertNotIn("\x00", notices)
        self.assertNotIn("copying.cpython-312-darwin.so.dSYM", notices)
        self.assertIn("The BSD License (BSD)", notices)
        self.assertIn("Metadata note: Package metadata says MIT", notices)
        self.assertIn("Source archive SHA-256:", notices)
        self.assertIn("Python runtime 3.12.14", notices)

    def test_make_server_skips_reverse_dns_lookup(self):
        with patch("socket.getfqdn", side_effect=AssertionError("Reverse DNS must not block startup")):
            server = disk.make_server(port=0)
        try:
            self.assertEqual(server.server_name, "127.0.0.1")
            self.assertGreater(server.server_port, 0)
        finally:
            server.server_close()

    def test_navigation_boundary(self):
        origin = "http://127.0.0.1:49125/"
        for url in [origin, origin + "app.js"]:
            self.assertEqual(navigation_policy(url, origin, False, False), "allow")
        self.assertEqual(navigation_policy("blob:" + origin + "export", origin, False, True), "download")
        for url in ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,hello", "http://127.0.0.1:49126/", "http://127.0.0.1.evil.test:49125/", "http://user@127.0.0.1:49125/", "blob:https://evil.test/export"]:
            self.assertEqual(navigation_policy(url, origin, False, False), "cancel")
        self.assertEqual(navigation_policy("https://example.com", origin, True, False), "external")
        self.assertEqual(navigation_policy("https://example.com", origin, False, False), "cancel")
        self.assertEqual(navigation_policy("file:///etc/passwd", origin, True, False), "cancel")

    def test_ephemeral_listener_host_boundary_and_shutdown(self):
        server = disk.make_server(port=0)
        port = server.server_port
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with urlopen(f"http://127.0.0.1:{port}/", timeout=3) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(HTTPError) as failure:
                urlopen(Request(f"http://127.0.0.1:{port}/", headers={"Host": "evil.test"}), timeout=3)
            self.assertEqual(failure.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(server.fileno(), -1)


if __name__ == "__main__":
    unittest.main()

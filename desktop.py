#!/usr/bin/env python3
"""Native macOS shell for Disk Scan."""
from __future__ import annotations

import threading

import disk
import webview
from webview.menu import Menu, MenuAction
from desktop_policy import install_policy


def run() -> None:
    server = disk.make_server(port=0)
    server_thread = threading.Thread(target=server.serve_forever, name="disk-evidence-http", daemon=True)
    server_thread.start()
    url = f"http://127.0.0.1:{server.server_port}/?desktop=1"
    window = None

    def select_folder(_window=None):
        if window is None:
            return
        selected = window.create_file_dialog(webview.FOLDER_DIALOG)
        if selected:
            root = disk.checked_root(selected[0])
            with server.state_lock:
                server.scan_root = root
                server.is_demo = False
                server.last_scan = None
                server.last_plan = None
            window.load_url(url)

    def use_demo(_window=None):
        demo_root = disk.STATE_DIR / "demo"
        disk.seed_demo(demo_root)
        root = disk.checked_root(demo_root)
        with server.state_lock:
            server.scan_root = root
            server.is_demo = True
            server.last_scan = None
            server.last_plan = None
        if window is not None:
            window.load_url(url)

    menu = [
        Menu(
            "Folder",
            [
                MenuAction("Choose Folder…", select_folder),
                MenuAction("Use Synthetic Demo", use_demo),
            ],
        )
    ]
    try:
        window = webview.create_window(
            "Disk Scan",
            url,
            width=1080,
            height=760,
            min_size=(800, 580),
            menu=menu,
        )
        install_policy(url)
        webview.start()
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)


if __name__ == "__main__":
    try:
        run()
    except Exception:
        import AppKit

        alert = AppKit.NSAlert.alloc().init()
        alert.setMessageText_("Disk Scan could not start")
        alert.setInformativeText_("The local app failed to open. Restart Disk Scan and try again.")
        alert.addButtonWithTitle_("OK")
        alert.runModal()
        raise SystemExit(1)

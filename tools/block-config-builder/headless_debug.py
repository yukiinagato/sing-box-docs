#!/usr/bin/env python3
"""Headless debug helper for block-config-builder.

This script starts a local HTTP server from repo root, opens the tool page in
Playwright Chromium (headless by default), collects browser console errors, and
optionally writes a screenshot for quick CI/Codex diagnostics.
"""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Debug block-config-builder in headless browser")
    parser.add_argument("--port", type=int, default=8765, help="Local HTTP server port (default: 8765)")
    parser.add_argument(
        "--path",
        default="tools/block-config-builder/index.html",
        help="Page path relative to repo root",
    )
    parser.add_argument(
        "--wait-ms",
        type=int,
        default=3000,
        help="Extra wait time after page load, in milliseconds",
    )
    parser.add_argument(
        "--screenshot",
        default="artifacts/block-config-builder-headless.png",
        help="Output screenshot path; empty string disables screenshot",
    )
    return parser.parse_args()


class QuietRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        # Keep Codex logs readable.
        return


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]

    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        print(
            "ERROR: Playwright is not installed. Run: \n"
            "  python -m pip install playwright\n"
            "  python -m playwright install chromium",
            file=sys.stderr,
        )
        return 2

    handler_cls = lambda *h_args, **h_kwargs: QuietRequestHandler(*h_args, directory=str(repo_root), **h_kwargs)

    with socketserver.TCPServer(("127.0.0.1", args.port), handler_cls) as httpd:
        httpd.allow_reuse_address = True
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        url = f"http://127.0.0.1:{args.port}/{args.path.lstrip('/')}"
        console_errors: List[str] = []
        page_errors: List[str] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1600, "height": 1000})
                page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
                page.on("pageerror", lambda err: page_errors.append(str(err)))

                response = page.goto(url, wait_until="networkidle", timeout=60_000)
                if response is None:
                    print("ERROR: No response when opening page", file=sys.stderr)
                    browser.close()
                    return 3
                if response.status >= 400:
                    print(f"ERROR: HTTP status {response.status}", file=sys.stderr)
                    browser.close()
                    return 4

                time.sleep(max(args.wait_ms, 0) / 1000)

                title = page.title()
                print(f"Opened: {url}")
                print(f"Page title: {title}")

                if args.screenshot:
                    target = repo_root / args.screenshot
                    target.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(target), full_page=True)
                    print(f"Screenshot: {target}")

                browser.close()
        finally:
            httpd.shutdown()

    if page_errors:
        print("\nPage errors:")
        for err in page_errors:
            print(f"  - {err}")

    if console_errors:
        print("\nConsole errors:")
        for err in console_errors:
            print(f"  - {err}")

    if page_errors or console_errors:
        return 1

    print("No page/console errors detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

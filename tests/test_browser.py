"""
Real-browser smoke test (Playwright driving Edge or Chrome).

Starts tests/browser/serve_fixture.py on a free port and runs tests/browser/ui_smoke.js against it.
It is skipped automatically when Node.js, the npm dependencies (run `npm ci` in tests/browser) or a
Chromium-based browser are not available, so the normal `pytest` run never fails for that reason.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BROWSER_DIR = HERE / "browser"

BROWSER_CANDIDATES = [
    os.environ.get("BROWSER_EXE", ""),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _find_browser():
    return next((p for p in BROWSER_CANDIDATES if p and Path(p).exists()), None)


@unittest.skipUnless(shutil.which("node"), "Node.js not installed")
@unittest.skipUnless((BROWSER_DIR / "node_modules" / "playwright-core").exists(), "run `npm ci` in tests/browser first")
@unittest.skipUnless(_find_browser(), "no Edge/Chrome found (set BROWSER_EXE)")
class BrowserSmokeTest(unittest.TestCase):
    def test_ui_smoke(self):
        port = _free_port()
        env = dict(os.environ, WINSENTINEL_TEST_FIXTURE="1", PYTHONDONTWRITEBYTECODE="1")
        # Server log goes to a file: an undrained pipe fills up after enough requests and blocks the server
        log = tempfile.NamedTemporaryFile(prefix="winsentinel-fixture-", suffix=".log", delete=False)
        server = subprocess.Popen([sys.executable, str(BROWSER_DIR / "serve_fixture.py"), str(port)],
                                  env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=1)
                    break
                except Exception:
                    if server.poll() is not None:
                        log.flush()
                        self.fail("fixture server exited: " + Path(log.name).read_text(errors="replace")[-500:])
                    time.sleep(0.3)
            else:
                self.fail("fixture server did not start")

            result = subprocess.run(
                ["node", "ui_smoke.js"], cwd=BROWSER_DIR, capture_output=True, text=True, timeout=180,
                env=dict(os.environ, BASE_URL=f"http://127.0.0.1:{port}", BROWSER_EXE=_find_browser()),
            )
            self.assertEqual(result.returncode, 0, "browser checks failed:\n" + result.stdout + result.stderr)
        finally:
            log.close()
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    unittest.main()

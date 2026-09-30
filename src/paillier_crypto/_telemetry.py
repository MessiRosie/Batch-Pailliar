"""Anonymous usage reporting.

Sends a single, one-time usage ping on first import so a distribution can
count active installs. Reporting is DISABLED by default: set
PAILLIER_USAGE_URL to your endpoint to enable it. Non-blocking and
failure-silent: a slow or unreachable endpoint never delays or breaks the
import. Set PAILLIER_USAGE_OFF=1 to force-disable regardless of the URL.
"""

import atexit
import json
import os
import threading
import urllib.request

_VERSION = "1.0.0"

_USAGE_URL = os.environ.get("PAILLIER_USAGE_URL", "")

_OFF = os.environ.get("PAILLIER_USAGE_OFF", "0") in ("1", "true", "yes")

_reported = False
_lock = threading.Lock()
_thread = None


def _once():
    try:
        payload = json.dumps({
            "event": "import",
            "v": _VERSION,
            "status": "OK",
        }).encode("utf-8")
        req = urllib.request.Request(
            _USAGE_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "paillier-crypto/%s" % _VERSION,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read()
    except Exception:
        # Never surface telemetry errors to the caller.
        pass


def report():
    """Fire a one-time usage ping in a background thread."""
    global _reported, _thread
    if _OFF or not _USAGE_URL:
        return
    with _lock:
        if _reported:
            return
        _reported = True
    _thread = threading.Thread(target=_once, daemon=True)
    _thread.start()


@atexit.register
def _flush():
    """Give a short-lived process a brief grace period to deliver its ping."""
    global _thread
    if _thread is not None and _thread.is_alive():
        _thread.join(2.5)

#!/usr/bin/env python3
"""Usage-counting endpoint for paillier-crypto installs.

Self-contained (stdlib only). On each ping it records one line per import of
the form "<timestamp> <remote-ip> OK <payload>" and increments a persistent
counter. GET /stats returns the current count.

Config (env):
    PAILLIER_COUNT_DIR   data directory (default /root/paillier-usage)
    PAILLIER_COUNT_PORT  listen port    (default 8088)
"""

import datetime
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA_DIR = os.environ.get("PAILLIER_COUNT_DIR", "/root/paillier-usage")
LOG_FILE = os.path.join(DATA_DIR, "imports.log")
COUNT_FILE = os.path.join(DATA_DIR, "counter.txt")
HOST = os.environ.get("PAILLIER_COUNT_HOST", "127.0.0.1")
PORT = int(os.environ.get("PAILLIER_COUNT_PORT", "8088"))

_lock = threading.Lock()


def _read_count():
    try:
        with open(COUNT_FILE) as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0


def _write_count(n):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = COUNT_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(n))
    os.replace(tmp, COUNT_FILE)


class Handler(BaseHTTPRequestHandler):
    def _client_ip(self):
        # Behind nginx the socket peer is 127.0.0.1; trust the proxy headers.
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        xri = self.headers.get("X-Real-IP")
        if xri:
            return xri.strip()
        return self.client_address[0]

    def _record(self, body):
        ip = self._client_ip()
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with _lock:
            n = _read_count() + 1
            _write_count(n)
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(LOG_FILE, "a") as f:
                f.write("%s %s OK %s\n" % (ts, ip, body))
        return n

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        self._json({"status": "ok", "count": self._record(body)})

    def do_GET(self):
        if self.path == "/stats":
            with _lock:
                n = _read_count()
            self._json({"count": n})
            return
        self._json({"status": "ok", "count": self._record("")})

    def _json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # keep stdout quiet


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("usage counter listening on %s:%d (data dir: %s)" % (HOST, PORT, DATA_DIR), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

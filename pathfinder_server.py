#!/usr/bin/env python3
"""
pathfinder_server.py

Slice 0 implementation of Pathfinder light HTTP server exposing GET /api/health.
Fails closed with HTTP 503 when .sequence/state.db is missing or corrupt.
"""

import http.server
import json
import os
import sqlite3

BOUND_IP = "127.0.0.1"
SERVER_PORT = 8765


class PathfinderRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler for Pathfinder Slice 0.
    """

    def log_message(self, format, *args):
        # Suppress standard http.server logging during tests
        pass

    def do_GET(self):
        if self.path == "/api/health":
            self._handle_health()
        else:
            self._send_json_response(404, {"status": "not_found"})

    def _handle_health(self):
        state_db_path = os.path.join(os.getcwd(), ".sequence", "state.db")

        if not os.path.isfile(state_db_path):
            self._send_json_response(
                503,
                {"status": "error", "detail": ".sequence/state.db missing"},
            )
            return

        try:
            conn = sqlite3.connect(f"file:{state_db_path}?mode=ro", uri=True)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT count(*) FROM sqlite_master;")
                cursor.fetchone()
            finally:
                conn.close()
        except (sqlite3.Error, Exception):
            self._send_json_response(
                503,
                {"status": "error", "detail": ".sequence/state.db corrupt or unreadable"},
            )
            return

        self._send_json_response(200, {"status": "ok"})

    def _send_json_response(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = http.server.HTTPServer((BOUND_IP, SERVER_PORT), PathfinderRequestHandler)
    print(f"Pathfinder server listening on http://{BOUND_IP}:{SERVER_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

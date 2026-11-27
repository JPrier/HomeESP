#!/usr/bin/env python3
"""Development webhook sink: records POSTed notifications to a JSONL file (loopback only)."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = sys.argv[2] if len(sys.argv) > 2 else "webhook.jsonl"

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = min(int(self.headers.get("Content-Length", 0)), 65536)
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps({"received": time.time(), "path": self.path, "body": body}) + "\n")
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 18090), H).serve_forever()

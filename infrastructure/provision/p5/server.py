#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = "/opt/p5"
CSS_PATH = os.path.join(BASE_DIR, "user.css")
FLAG_PATH = "/home/ctfadmin/flags/flag_p5.txt"
SOLVED_PATH = os.path.join(BASE_DIR, "solved")

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Admin Panel</title>
  <style>
    #flag {{ display: none; }}
  </style>
  <link rel="stylesheet" href="/user.css" />
</head>
<body>
  <h1>Admin Panel</h1>
  <p>Restricted area.</p>
  <div id="flag" data-flag="{flag}">FLAG</div>
</body>
</html>
"""

INDEX_TEMPLATE = """<!doctype html>
<html>
<head><meta charset="utf-8" /><title>P5</title></head>
<body>
  <h1>P5 CSS Challenge</h1>
  <p>Submit CSS to be loaded on the admin page.</p>
  <form method="POST" action="/submit">
    <textarea name="css" rows="12" cols="80"></textarea><br />
    <button type="submit">Submit CSS</button>
  </form>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, content, content_type="text/html; charset=utf-8", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, INDEX_TEMPLATE.encode())
            return
        if path == "/admin":
            try:
                with open(FLAG_PATH, "r", encoding="utf-8") as f:
                    flag = f.read().strip()
            except FileNotFoundError:
                flag = "MISSING"
            html = HTML_TEMPLATE.format(flag=flag).encode()
            self._send(200, html, extra_headers={"Cache-Control": "no-store"})
            return
        if path == "/user.css":
            if os.path.exists(CSS_PATH):
                with open(CSS_PATH, "rb") as f:
                    data = f.read()
            else:
                data = b"/* no css */"
            self._send(200, data, "text/css; charset=utf-8", extra_headers={"Cache-Control": "no-store"})
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/submit":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 8192:
            self._send(413, b"payload too large", "text/plain; charset=utf-8")
            return
        body = self.rfile.read(length)
        form = parse_qs(body.decode("utf-8", errors="ignore"))
        css = form.get("css", [""])[0].encode("utf-8")
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(CSS_PATH, "wb") as f:
            f.write(css)
        with open(SOLVED_PATH, "w", encoding="utf-8") as f:
            f.write("ok\n")
        self._send(200, b"ok", "text/plain; charset=utf-8")


def main():
    server = HTTPServer(("127.0.0.1", 5005), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

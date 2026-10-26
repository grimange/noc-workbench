#!/usr/bin/env python3
"""Actual process/HTTP/PostgreSQL lifecycle smoke, called by test-m0."""
import http.cookiejar
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

project = sys.argv[1]
compose = ["docker", "compose", "-p", project, "-f", "deployments/compose.yaml"]
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
origin = f"http://127.0.0.1:{port}"
env = dict(os.environ, NOC_LISTEN=f"127.0.0.1:{port}", NOC_BASE_URL=origin,
           NOC_STARTUP_TIMEOUT="3s")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
log = tempfile.TemporaryFile(mode="w+")
process = None


def request(path, data=None, csrf=None):
    headers = {}
    if data is not None:
        data = urllib.parse.urlencode(data).encode()
        headers["Origin"] = origin
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(origin + path, data, headers)
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def start():
    global process
    process = subprocess.Popen([env["NOC_SMOKE_BINARY"]], env=env, stdout=log, stderr=log)
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("application exited during startup")
        try:
            if request("/healthz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(.1)
    raise AssertionError("startup timed out")


def stop():
    global process
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=7) == 0, "unclean shutdown"
    process = None


def token(html):
    return re.search(r'name="csrf" value="([a-f0-9]{64})"', html)[1]


try:
    start()
    assert request("/healthz") == (200, '{"status":"ok"}')
    status, html = request("/")
    assert status == 200 and "Local operator sign in" in html
    assert request("/settings", {"label": "unauthorized"})[0] == 401
    assert request("/login", {"password": "synthetic-smoke-password"})[0] == 403
    csrf = token(request("/login")[1])
    assert request("/login", {"csrf": csrf, "password": "wrong"})[0] == 401
    status, html = request("/login", {"csrf": csrf, "password": "synthetic-smoke-password"})
    assert status == 200 and "Workspace settings" in html
    csrf = token(html)
    assert request("/settings", {"label": "forged"})[0] == 403
    assert request("/settings", {"label": "synthetic persisted workspace"}, csrf)[0] == 200
    assert "synthetic persisted workspace" in request("/")[1]
    assert request("/static/app.css")[0] == 200
    subprocess.run(compose + ["stop", "db"], check=True, stdout=subprocess.DEVNULL)
    assert request("/healthz")[0] == 503
    assert request("/")[0] == 503
    stop()
    failed = subprocess.run([env["NOC_SMOKE_BINARY"]], env=env, stdout=log, stderr=log, timeout=6)
    assert failed.returncode != 0, "unavailable database accepted at startup"
    subprocess.run(compose + ["up", "-d", "--wait"], check=True, stdout=subprocess.DEVNULL)
    start()
    status, html = request("/")
    assert status == 200 and "synthetic persisted workspace" in html, "state/session lost after restart"
    csrf = token(html)
    assert request("/logout", {"csrf": csrf})[0] == 200
    assert "Local operator sign in" in request("/")[1]
    stop()
    bad = dict(env, NOC_LISTEN="0.0.0.0:8080")
    assert subprocess.run([env["NOC_SMOKE_BINARY"]], env=bad, stdout=log, stderr=log, timeout=5).returncode != 0
    log.seek(0)
    output = log.read()
    for secret in [env["NOC_DB_PASSWORD"], env["NOC_DATABASE_URL"], env["NOC_PASSWORD_HASH"], "synthetic-smoke-password"]:
        assert secret not in output, "credential in process logs"
    assert '"msg":"application stopped"' in output
    print("PASS: process startup, health/HTML/assets, login failure/success, auth/CSRF, DB outage, bounded failure, app+DB restart persistence, logout, invalid config, graceful shutdown and sanitized logs")
finally:
    stop()
    log.close()

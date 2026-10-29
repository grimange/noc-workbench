#!/usr/bin/env python3
"""Actual process/HTTP/PostgreSQL lifecycle smoke, called by test-m0."""
import json
import pathlib
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
    assert status == 200 and "Dashboard" in html
    csrf = token(html)
    assert request("/settings", {"label": "forged"})[0] == 403
    assert request("/settings", {"label": "synthetic persisted workspace"}, csrf)[0] == 410
    original_label = subprocess.check_output(compose + ["exec", "-T", "db", "psql", "-U", "noc_workbench", "-d", "noc_workbench", "-Atc", "SELECT note FROM operator_setting WHERE id=1"], text=True).strip()
    assert request("/static/app.css")[0] == 200
    # A real HTTP inventory write must survive both application and DB restarts.
    status, html = request("/customers", {"csrf": csrf, "display_name": "Synthetic lifecycle customer",
        "short_code": "SMOKE", "notes": "Synthetic fixture only", "status": "active"})
    assert status == 200 and "Synthetic lifecycle customer" in html
    customer_path = re.search(r'href="(/customers/[a-f0-9-]+/edit)"', html)[1].removesuffix("/edit")
    status, html = request(customer_path + "/environments", {"csrf": csrf,
        "name": "Synthetic lab", "kind": "lab", "status": "active"})
    assert status == 200 and "Synthetic lab" in html
    environment_path = re.search(r'href="(/customers/[a-f0-9-]+/environments/[a-f0-9-]+/edit)"', html)[1].removesuffix("/edit")
    topology = environment_path + "/topology"
    topology_paths = []
    def create_topology(kind, fields):
        status, page = request(topology + "/" + kind + "/new", dict(fields, csrf=csrf))
        assert status == 200 and "Topology saved." in page, "topology write failed: " + kind
        path = re.search(r'href="([^"?]+/topology/{kind}/[a-f0-9-]+/edit)"'.replace("{kind}", kind), page)[1].removesuffix("/edit")
        topology_paths.append(path)
        return path.rsplit("/", 1)[1]
    cluster_id = create_topology("clusters", {"name": "Synthetic lifecycle cluster", "type": "generic", "lifecycle": "active"})
    asset_id = create_topology("assets", {"name": "Synthetic lifecycle host", "kind": "server", "lifecycle": "active"})
    create_topology("endpoints", {"asset_id": asset_id, "protocol": "ssh", "host": "192.0.2.10", "port": "22", "status": "active"})
    create_topology("memberships", {"cluster_id": cluster_id, "asset_id": asset_id, "role": "web"})
    service_id = create_topology("services", {"cluster_id": cluster_id, "name": "Synthetic lifecycle service", "service_type": "web", "lifecycle": "active"})
    instance_id = create_topology("instances", {"service_id": service_id, "name": "Synthetic lifecycle instance", "lifecycle": "active"})
    create_topology("bindings", {"service_instance_id": instance_id, "asset_id": asset_id, "binding_role": "primary"})
    quick = "/workspace/clusters/" + cluster_id
    assert request(quick, {"operation": "pin", "csrf": csrf})[0] == 410
    for fields in [{"operation": "note.save", "body": "Synthetic persisted runbook", "visibility": "private"}, {"operation": "link.save", "label": "Synthetic RTM", "url": "https://rtm.example.invalid/", "type": "rtm", "pinned": "on"}]:
        assert request(quick, dict(fields, csrf=csrf))[0] == 200
    # The complete synthetic interchange must persist through database restart/restore.
    example = pathlib.Path("internal/interchange/example.json").read_text()
    payload = {"csrf": csrf, "document": example, "operation": "preview"}
    assert request("/inventory/interchange", payload)[0] == 200
    before_import = json.loads(request("/inventory/interchange?download=sanitized")[1])
    payload["operation"] = "import"
    assert request("/inventory/interchange", payload)[0] == 200
    after_import = request("/inventory/interchange?download=sanitized")[1]
    assert len(json.loads(after_import)["records"]) > len(before_import["records"])
    assert request("/inventory/interchange", payload)[0] == 200
    assert request("/inventory/interchange?download=sanitized")[1] == after_import
    # Schema-heavy integration runs can leave a large checkpoint on slower local
    # disks. Keep a bounded graceful shutdown instead of forcing crash recovery.
    subprocess.run(compose + ["stop", "--timeout", "180", "db"], check=True, stdout=subprocess.DEVNULL, timeout=200)
    # Loss of the dedicated single-process ownership session now terminates
    # execution fail-closed; systemd restarts after PostgreSQL restoration.
    assert process.wait(timeout=7) != 0, "ownership loss must fail closed"
    stop()
    failed = subprocess.run([env["NOC_SMOKE_BINARY"]], env=env, stdout=log, stderr=log, timeout=6)
    assert failed.returncode != 0, "unavailable database accepted at startup"
    subprocess.run(compose + ["up", "-d"], check=True, stdout=subprocess.DEVNULL, timeout=30)
    container = subprocess.check_output(compose + ["ps", "-q", "db"], text=True, timeout=10).strip()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        state = subprocess.check_output(["docker", "inspect", "--format", "{{.State.Status}} {{.State.Health.Status}}", container], text=True, timeout=10).strip()
        if state == "running healthy":
            break
        assert state in ("running starting", "running unhealthy"), "test database exited during restart"
        time.sleep(1)
    else:
        raise AssertionError("test database restart readiness exceeded 180 seconds")
    start()
    status, html = request("/")
    assert status == 200 and "Dashboard" in html, "state/session lost after restart"
    assert "Synthetic lifecycle customer" in request(customer_path)[1], "customer lost after restart"
    assert "Synthetic lab" in request(environment_path)[1], "environment lost after restart"
    for path in topology_paths:
        assert request(path)[0] == 200, "topology lost after app/database restart"
    status, quick_html = request(quick)
    assert status == 200 and "Synthetic persisted runbook" in quick_html and "Synthetic RTM" in quick_html, "notes/links lost after restart"
    workspace_html = request("/workspace?q=runbook")[1]
    assert "Servers" in workspace_html, "legacy search redirect lost after restart"
    assert request("/inventory/interchange?download=sanitized")[1] == after_import, "interchange restart lost topology"
    # Prove the release backup format restores using only this disposable cluster.
    container = subprocess.check_output(compose + ["ps", "-q", "db"], text=True).strip()
    dbtools = ["docker", "exec", container]
    subprocess.run(dbtools + ["createdb", "-U", "noc_workbench", "nw_restore_smoke"], check=True)
    with tempfile.TemporaryFile() as backup:
        subprocess.run(dbtools + ["pg_dump", "-U", "noc_workbench", "-d", "noc_workbench", "-Fc"], stdout=backup, check=True)
        backup.seek(0)
        subprocess.run(["docker", "exec", "-i", container, "pg_restore", "-U", "noc_workbench", "-d", "nw_restore_smoke", "--exit-on-error"], stdin=backup, check=True)
    restored = subprocess.check_output(dbtools + ["psql", "-X", "-U", "noc_workbench", "-d", "nw_restore_smoke", "-Atc", "SELECT (SELECT count(*) FROM schema_migration),(SELECT count(*) FROM customer),(SELECT count(*) FROM environment),(SELECT note FROM operator_setting WHERE id=1),(SELECT count(*) FROM workspace_pin),(SELECT count(*) FROM operator_note),(SELECT count(*) FROM external_link),(SELECT count(*) FROM workspace_principal)"], text=True).strip()
    assert restored == "20|3|3|" + original_label + "|0|1|1|1", "database backup restore mismatch"
    restored_count = subprocess.check_output(dbtools + ["psql", "-X", "-U", "noc_workbench", "-d", "nw_restore_smoke", "-Atc", "SELECT count(*) FROM service_instance_host"], text=True).strip()
    assert int(restored_count) == 8, "imported host bindings lost in restore"
    subprocess.run(dbtools + ["dropdb", "-U", "noc_workbench", "nw_restore_smoke"], check=True)
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
    print("PASS: process startup, health/HTML/assets, login failure/success, auth/CSRF, DB outage, bounded failure, app+DB restart session/customer/environment/topology/notes/links persistence and retired UI boundaries, interchange idempotency/restart and database backup/restore, logout, invalid config, graceful shutdown and sanitized logs")
finally:
    stop()
    log.close()

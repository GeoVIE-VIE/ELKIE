#!/usr/bin/env python3
"""
Cisco Lab Web UI — Flask app with topology viewer + web terminal.

Top pane:  Interactive topology (vis.js) — click device to console
Bottom pane: xterm.js terminal connected to device console via websocket

Auth: Flask-Login with bcrypt, rate limiting, account lockout, CSRF tokens.
"""

import json
import os
import sys
import time
import threading
import telnetlib
import hashlib
import secrets
import functools
import logging
from collections import defaultdict

from flask import (
    Flask, render_template, jsonify, request, redirect,
    url_for, session, abort, make_response,
)
from flask_socketio import SocketIO, emit, disconnect as ws_disconnect

sys.path.insert(0, "/opt/cisco-lab")
from lab_manager import LabManager
from lab_scenarios import ScenarioEngine, SCENARIOS

# --- App setup ---
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # 24h
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# --- Auth logger for fail2ban ---
auth_logger = logging.getLogger("cisco-lab-auth")
auth_handler = logging.FileHandler("/var/log/cisco-lab-auth.log")
auth_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
auth_logger.addHandler(auth_handler)
auth_logger.setLevel(logging.INFO)

# --- API rate limiter ---
_api_hits = defaultdict(list)  # ip -> [timestamps]
_api_hits_lock = threading.Lock()
API_RATE_LIMIT = 60       # requests per window
API_RATE_WINDOW = 60      # seconds


def _check_api_rate(ip):
    """Return True if request is allowed."""
    now = time.time()
    with _api_hits_lock:
        hits = _api_hits[ip]
        # Prune old entries
        _api_hits[ip] = [t for t in hits if now - t < API_RATE_WINDOW]
        if len(_api_hits[ip]) >= API_RATE_LIMIT:
            return False
        _api_hits[ip].append(now)
        return True


# Active telnet sessions per websocket sid
telnet_sessions = {}

# Boot status tracking per device name
# Values: "stopped", "starting", "bios", "bootloader", "loading_ios", "initializing", "ready"
boot_status = {}
boot_status_lock = threading.Lock()


def _monitor_boot(node_name, console_port):
    """Background thread — watches console until IOS prompt, auto-skips dialogs."""

    with boot_status_lock:
        boot_status[node_name] = "booting"

    try:
        tn = telnetlib.Telnet("127.0.0.1", int(console_port), timeout=10)
    except Exception:
        return

    deadline = time.time() + 360  # 6 min max
    buffer = b""
    sent_no = False
    ready = False

    try:
        while time.time() < deadline:
            # Poke console
            try:
                tn.write(b"\r\n")
            except Exception:
                break

            time.sleep(3)

            try:
                chunk = tn.read_very_eager()
            except EOFError:
                break
            except Exception:
                chunk = b""

            if not chunk:
                continue

            buffer += chunk
            # Only look at recent output
            tail = buffer[-1000:].lower()

            # Auto-skip initial config dialog
            if not sent_no and b"initial configuration dialog" in tail:
                time.sleep(1)
                try:
                    tn.write(b"no\r\n")
                except Exception:
                    break
                sent_no = True
                time.sleep(3)
                continue

            # Auto-skip terminate autoinstall
            if b"terminate autoinstall" in tail:
                try:
                    tn.write(b"\r\n")
                except Exception:
                    break
                time.sleep(3)
                continue

            # Auto-skip "Press RETURN to get started"
            if b"press return" in tail:
                try:
                    tn.write(b"\r\n")
                except Exception:
                    break
                time.sleep(2)
                continue

            # Check for IOS prompt — look for common prompts at end of output
            last_line = chunk.decode(errors="replace").strip().split("\n")[-1].strip()
            if last_line.endswith("#") or last_line.endswith(">"):
                ready = True
                break

            # Also check for login prompt (NX-OS)
            if b"login:" in tail[-100:]:
                ready = True
                break

        if ready:
            with boot_status_lock:
                boot_status[node_name] = "ready"

            # Bootstrap: enable, terminal length 0, no shut all GigE interfaces
            try:
                tn.write(b"\r\nenable\r\n")
                time.sleep(1)
                tn.write(b"terminal length 0\r\n")
                time.sleep(0.5)
                tn.write(b"configure terminal\r\n")
                time.sleep(0.5)
                for i in range(4):
                    tn.write(f"interface GigabitEthernet{i+1}\r\n".encode())
                    time.sleep(0.3)
                    tn.write(b"no shutdown\r\n")
                    time.sleep(0.3)
                tn.write(b"end\r\n")
                time.sleep(0.5)
            except Exception:
                pass

        tn.close()
    except Exception:
        try:
            tn.close()
        except Exception:
            pass

    # If we timed out but got lots of output, it might be ready
    if not ready and buffer:
        last = buffer[-100:].decode(errors="replace").strip()
        if last.endswith("#") or last.endswith(">"):
            with boot_status_lock:
                boot_status[node_name] = "ready"


# Track which devices have active monitors
_active_monitors = set()
_active_monitors_lock = threading.Lock()


def start_boot_monitor(node_name, console_port):
    """Start a background boot monitor for a device (prevents duplicates)."""
    with _active_monitors_lock:
        if node_name in _active_monitors:
            return
        _active_monitors.add(node_name)

    def run():
        try:
            _monitor_boot(node_name, console_port)
        finally:
            with _active_monitors_lock:
                _active_monitors.discard(node_name)

    t = threading.Thread(target=run, daemon=True)
    t.start()

# --- Auth system ---
USERS_FILE = "/opt/cisco-lab/web_users.json"
LOCKOUT_FILE = "/opt/cisco-lab/auth_lockout.json"
MAX_ATTEMPTS = 5          # lock after this many failures
LOCKOUT_SECONDS = 900     # 15 minute lockout
ATTEMPT_WINDOW = 300      # count failures within 5 min window


def _hash_password(password, salt=None):
    """Hash password with PBKDF2-HMAC-SHA256, 600k iterations."""
    if salt is None:
        salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000)
    return salt, dk.hex()


def _load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            pass
    return {}


def _save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def _load_lockout():
    if os.path.exists(LOCKOUT_FILE):
        try:
            with open(LOCKOUT_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            pass
    return {}


def _save_lockout(data):
    with open(LOCKOUT_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _check_rate_limit(identifier):
    """Check if identifier (IP or username) is locked out. Returns (allowed, seconds_remaining)."""
    lockout = _load_lockout()
    now = time.time()
    entry = lockout.get(identifier, {})

    # Check hard lockout
    locked_until = entry.get("locked_until", 0)
    if now < locked_until:
        return False, int(locked_until - now)

    # Clean old attempts outside the window
    attempts = [t for t in entry.get("attempts", []) if now - t < ATTEMPT_WINDOW]
    entry["attempts"] = attempts
    lockout[identifier] = entry
    _save_lockout(lockout)

    if len(attempts) >= MAX_ATTEMPTS:
        # Lock them out
        entry["locked_until"] = now + LOCKOUT_SECONDS
        entry["attempts"] = []
        lockout[identifier] = entry
        _save_lockout(lockout)
        return False, LOCKOUT_SECONDS

    return True, 0


def _record_failure(identifier):
    """Record a failed login attempt."""
    lockout = _load_lockout()
    now = time.time()
    entry = lockout.get(identifier, {"attempts": [], "locked_until": 0})
    entry["attempts"] = [t for t in entry.get("attempts", []) if now - t < ATTEMPT_WINDOW]
    entry["attempts"].append(now)
    lockout[identifier] = entry
    _save_lockout(lockout)
    remaining = MAX_ATTEMPTS - len(entry["attempts"])
    return max(remaining, 0)


def _clear_failures(identifier):
    """Clear failures after successful login."""
    lockout = _load_lockout()
    lockout.pop(identifier, None)
    _save_lockout(lockout)


def _create_default_admin():
    """Create default admin if no users exist."""
    users = _load_users()
    if not users:
        salt, hashed = _hash_password("CiscoLab2026!")
        users["admin"] = {
            "password_hash": hashed,
            "salt": salt,
            "role": "admin",
            "created": time.time(),
            "must_change": True,
        }
        _save_users(users)
        print("Default admin created: admin / CiscoLab2026!")
        print("CHANGE THIS PASSWORD on first login!")


def login_required(f):
    """Decorator to require authentication."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin role."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "Not authenticated"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def _generate_csrf():
    """Generate or retrieve CSRF token for current session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _check_csrf():
    """Validate CSRF token on state-changing requests."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    token = request.headers.get("X-CSRF-Token") or (request.json or {}).get("_csrf")
    return token == session.get("csrf_token")


def get_lab():
    """Get a fresh LabManager instance."""
    return LabManager()


# --- Auth Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("authenticated"):
            return redirect(url_for("index"))
        return render_template("login.html")

    # POST — handle login
    # Rate limit by IP
    client_ip = request.remote_addr
    allowed, wait = _check_rate_limit(client_ip)
    if not allowed:
        auth_logger.warning(f"LOGIN_LOCKED ip={client_ip} lockout={wait}s")
        return jsonify({
            "ok": False,
            "error": f"Too many attempts. Try again in {wait // 60} minutes.",
        }), 429

    data = request.json or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400

    # Rate limit by username too
    allowed, wait = _check_rate_limit(f"user:{username}")
    if not allowed:
        return jsonify({
            "ok": False,
            "error": f"Account locked. Try again in {wait // 60} minutes.",
        }), 429

    # Constant-time-ish lookup
    users = _load_users()
    user = users.get(username)

    # Simulate work even if user doesn't exist (timing attack prevention)
    if not user:
        _hash_password(password, "fakesalt" * 4)
        remaining = _record_failure(client_ip)
        _record_failure(f"user:{username}")
        auth_logger.warning(f"LOGIN_FAIL user={username} ip={client_ip} reason=no_such_user")
        time.sleep(0.5)
        return jsonify({
            "ok": False,
            "error": f"Invalid credentials. {remaining} attempts remaining.",
        }), 401

    # Verify password
    salt = user["salt"]
    _, computed = _hash_password(password, salt)
    if not secrets.compare_digest(computed, user["password_hash"]):
        remaining = _record_failure(client_ip)
        _record_failure(f"user:{username}")
        auth_logger.warning(f"LOGIN_FAIL user={username} ip={client_ip} reason=bad_password")
        time.sleep(0.5)
        return jsonify({
            "ok": False,
            "error": f"Invalid credentials. {remaining} attempts remaining.",
        }), 401

    # Success
    _clear_failures(client_ip)
    _clear_failures(f"user:{username}")
    auth_logger.info(f"LOGIN_OK user={username} ip={client_ip}")
    session.permanent = True
    session["authenticated"] = True
    session["username"] = username
    session["role"] = user.get("role", "user")
    session["login_time"] = time.time()
    session["csrf_token"] = secrets.token_hex(32)
    session["login_ip"] = client_ip

    must_change = user.get("must_change", False)
    return jsonify({"ok": True, "must_change": must_change})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.json or {}
    current = data.get("current", "")
    new_pass = data.get("new_password", "")

    if len(new_pass) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400

    users = _load_users()
    username = session["username"]
    user = users.get(username)
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 400

    # Verify current password
    _, computed = _hash_password(current, user["salt"])
    if not secrets.compare_digest(computed, user["password_hash"]):
        return jsonify({"ok": False, "error": "Current password is incorrect."}), 401

    # Set new password
    salt, hashed = _hash_password(new_pass)
    user["salt"] = salt
    user["password_hash"] = hashed
    user["must_change"] = False
    user["changed_at"] = time.time()
    users[username] = user
    _save_users(users)

    return jsonify({"ok": True})


@app.route("/api/auth/users", methods=["GET"])
@admin_required
def list_auth_users():
    users = _load_users()
    result = []
    for name, u in users.items():
        result.append({
            "username": name,
            "role": u.get("role", "user"),
            "created": u.get("created"),
            "must_change": u.get("must_change", False),
        })
    return jsonify({"users": result})


@app.route("/api/auth/users", methods=["POST"])
@admin_required
def create_auth_user():
    if not _check_csrf():
        return jsonify({"error": "CSRF validation failed"}), 403

    data = request.json or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
    if role not in ("user", "admin"):
        return jsonify({"ok": False, "error": "Role must be 'user' or 'admin'."}), 400

    users = _load_users()
    if username in users:
        return jsonify({"ok": False, "error": f"User '{username}' already exists."}), 400

    salt, hashed = _hash_password(password)
    users[username] = {
        "password_hash": hashed,
        "salt": salt,
        "role": role,
        "created": time.time(),
        "must_change": True,
    }
    _save_users(users)
    return jsonify({"ok": True})


@app.route("/api/auth/users/<username>", methods=["DELETE"])
@admin_required
def delete_auth_user(username):
    if not _check_csrf():
        return jsonify({"error": "CSRF validation failed"}), 403

    users = _load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if username == session.get("username"):
        return jsonify({"ok": False, "error": "Cannot delete yourself."}), 400

    del users[username]
    _save_users(users)
    return jsonify({"ok": True})


@app.route("/api/auth/status")
def auth_status():
    return jsonify({
        "authenticated": session.get("authenticated", False),
        "username": session.get("username"),
        "role": session.get("role"),
        "csrf": _generate_csrf(),
    })


# --- Security headers ---
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --- Security middleware ---
@app.before_request
def security_checks():
    # Skip for static/login
    if request.path in ("/login", "/api/auth/status") and request.method == "GET":
        return

    # API rate limiter
    client_ip = request.remote_addr
    if request.path.startswith("/api/"):
        if not _check_api_rate(client_ip):
            auth_logger.warning(f"RATE_LIMIT ip={client_ip} path={request.path}")
            return jsonify({"error": "Rate limit exceeded. Slow down."}), 429

    # Session IP binding — invalidate if IP changed
    if session.get("authenticated"):
        login_ip = session.get("login_ip")
        if login_ip and login_ip != client_ip:
            username = session.get("username", "?")
            auth_logger.warning(f"SESSION_HIJACK user={username} login_ip={login_ip} current_ip={client_ip}")
            session.clear()
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Session expired. Please log in again."}), 401
            return redirect(url_for("login"))

    # CSRF on state-changing API calls
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not session.get("authenticated"):
            return  # let login_required handle it
        if not _check_csrf():
            return jsonify({"error": "CSRF validation failed"}), 403


# --- Web Routes ---

@app.route("/")
@login_required
def index():
    return render_template("index.html", csrf_token=_generate_csrf())


@app.route("/api/topology")
@login_required
def api_topology():
    """Return nodes and links for vis.js."""
    lab = get_lab()
    nodes = lab._get_nodes()
    links = lab._get_links()

    # Auto-start boot monitors for running devices that don't have one
    for n in nodes:
        if n["status"] == "started" and n.get("console"):
            name = n["name"]
            with boot_status_lock:
                has_status = name in boot_status
            if not has_status:
                start_boot_monitor(name, n["console"])

    vis_nodes = []
    for n in nodes:
        status = n["status"]
        ram = n.get("properties", {}).get("ram", "?")
        name = n["name"]

        # Get boot status
        with boot_status_lock:
            bstatus = boot_status.get(name, "unknown")
        if status != "started":
            bstatus = "stopped"

        # Color: gray=stopped, orange=booting, green=ready
        if status != "started":
            bg, border = "#95a5a6", "#7f8c8d"
        elif bstatus == "ready":
            bg, border = "#2ecc71", "#27ae60"
        else:
            bg, border = "#f39c12", "#e67e22"

        label = name
        if status == "started" and bstatus != "ready":
            label = f"{name}\n(booting...)"

        vis_nodes.append({
            "id": n["node_id"],
            "label": label,
            "status": status,
            "boot_status": bstatus,
            "console": n.get("console"),
            "ram": ram,
            "color": {
                "background": bg,
                "border": border,
                "highlight": {"background": "#3498db", "border": "#2980b9"},
            },
            "font": {"color": "#ecf0f1", "size": 14, "face": "monospace", "multi": True},
            "shape": "box",
            "borderWidth": 2,
            "shadow": True,
        })

    vis_edges = []
    node_map = {n["node_id"]: n["name"] for n in nodes}
    # Build node type lookup for correct interface naming
    node_type = {}
    for n in nodes:
        adapter_type = n.get("properties", {}).get("adapter_type", "")
        node_type[n["node_id"]] = "csr" if "virtio" in adapter_type else "ios"

    def _adapter_to_iface(node_id, adapter, port):
        """Convert GNS3 adapter/port to IOS interface name."""
        if node_type.get(node_id) == "csr":
            # CSR1000v: adapter 0 = Gi1, adapter 1 = Gi2, etc.
            return f"Gi{adapter + 1}"
        else:
            # IOSv/Nexus: slot/port format
            return f"Gi{adapter}/{port}"

    for link in links:
        ln = link["nodes"]
        if len(ln) == 2:
            a_name = node_map.get(ln[0]["node_id"], "?")
            b_name = node_map.get(ln[1]["node_id"], "?")
            a_if = _adapter_to_iface(ln[0]["node_id"], ln[0]["adapter_number"], ln[0]["port_number"])
            b_if = _adapter_to_iface(ln[1]["node_id"], ln[1]["adapter_number"], ln[1]["port_number"])
            vis_edges.append({
                "from": ln[0]["node_id"],
                "to": ln[1]["node_id"],
                "label": f"{a_if} — {b_if}",
                "color": {"color": "#7f8c8d", "highlight": "#3498db"},
                "font": {"color": "#bdc3c7", "size": 11, "face": "monospace"},
                "width": 2,
                "smooth": {"type": "curvedCW", "roundness": 0.1},
            })

    total_ram = sum(n.get("properties", {}).get("ram", 0) for n in nodes if n["status"] == "started")

    return jsonify({
        "nodes": vis_nodes,
        "edges": vis_edges,
        "stats": {
            "running": sum(1 for n in nodes if n["status"] == "started"),
            "stopped": sum(1 for n in nodes if n["status"] != "started"),
            "links": len(links),
            "ram_used": total_ram,
            "ram_total": 32768,
        }
    })


@app.route("/api/devices", methods=["POST"])
@login_required
def api_add_device():
    data = request.json
    lab = get_lab()
    try:
        result = lab.add_device(data["name"], data["type"])
        return jsonify({"ok": True, "node": result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/devices/<name>/start", methods=["POST"])
@login_required
def api_start_device(name):
    lab = get_lab()
    try:
        lab.start_device(name)
        # Start boot monitor
        node = lab._find_node(name)
        if node and node.get("console"):
            start_boot_monitor(name, node["console"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/devices/<name>/stop", methods=["POST"])
@login_required
def api_stop_device(name):
    lab = get_lab()
    try:
        lab.stop_device(name)
        with boot_status_lock:
            boot_status.pop(name, None)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/devices/<name>", methods=["DELETE"])
@login_required
def api_remove_device(name):
    lab = get_lab()
    try:
        lab.remove_device(name)
        with boot_status_lock:
            boot_status.pop(name, None)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/connect", methods=["POST"])
@login_required
def api_connect():
    data = request.json
    lab = get_lab()
    try:
        lab.connect(data["a"], data["a_if"], data["b"], data["b_if"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/disconnect", methods=["POST"])
@login_required
def api_disconnect():
    data = request.json
    lab = get_lab()
    try:
        lab.disconnect(data["a"], data["a_if"], data["b"], data["b_if"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/snapshot/save", methods=["POST"])
@login_required
def api_snapshot_save():
    lab = get_lab()
    try:
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            lab.vm_snapshot_create("clean")
        return jsonify({"ok": True, "output": f.getvalue()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/snapshot/restore", methods=["POST"])
@login_required
def api_snapshot_restore():
    lab = get_lab()
    try:
        ok = lab.vm_snapshot_restore("clean")
        # Mark all running devices as "ready" since snapshot restores to a booted state
        if ok:
            nodes = lab._get_nodes()
            with boot_status_lock:
                for n in nodes:
                    if n["status"] == "started":
                        boot_status[n["name"]] = "ready"
        return jsonify({"ok": ok})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/snapshot/status")
@login_required
def api_snapshot_status():
    lab = get_lab()
    try:
        # Check if any device has a VM snapshot
        nodes = lab._get_nodes()
        has_snapshot = False
        for node in nodes:
            if node["status"] == "started":
                port = lab._get_qemu_monitor_port(node)
                if port:
                    data = lab._qemu_monitor_cmd(port, "info snapshots")
                    if "clean" in data:
                        has_snapshot = True
                        break
        return jsonify({"has_snapshot": has_snapshot})
    except Exception:
        return jsonify({"has_snapshot": False})


@app.route("/api/progress")
@login_required
def api_progress():
    """Get progress for all users (admin) or current user."""
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    if session.get("role") == "admin":
        return jsonify({"users": engine.get_all_progress()})
    else:
        return jsonify({"users": [engine.get_user_progress()]})


@app.route("/api/scenarios")
@login_required
def api_scenarios():
    lab = get_lab()
    username = session.get("username", "default")
    engine = ScenarioEngine(lab, username=username)
    ud = engine._user_data()
    completed = set(ud.get("completed", []))
    active = engine.state.get("active")

    result = []
    for s in SCENARIOS:
        result.append({
            "id": s["id"],
            "name": s["name"],
            "category": s["category"],
            "difficulty": s["difficulty"],
            "description": s["description"],
            "hint": s.get("hint", ""),
            "completed": s["id"] in completed,
            "active": s["id"] == active,
            "device_count": len(s["devices"]),
        })

    return jsonify({
        "scenarios": result,
        "active": active,
        "completed_count": len(completed),
        "total": len(SCENARIOS),
    })


@app.route("/api/scenarios/<int:sid>/start", methods=["POST"])
@login_required
def api_scenario_start(sid):
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    try:
        engine.deploy(sid)
        # Start boot monitors for all deployed devices
        for node in lab._get_nodes():
            if node["status"] == "started" and node.get("console"):
                start_boot_monitor(node["name"], node["console"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/scenarios/configure", methods=["POST"])
@login_required
def api_scenario_configure():
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    try:
        engine.configure()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/scenarios/check", methods=["POST"])
@login_required
def api_scenario_check():
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    try:
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            engine.check()
        output = f.getvalue()
        passed = "SOLVED" in output
        return jsonify({"ok": True, "passed": passed, "output": output})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/scenarios/hint", methods=["GET"])
@login_required
def api_scenario_hint():
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    if not engine.state.get("active"):
        return jsonify({"hint": "No active scenario."})
    scenario = engine.get_scenario(engine.state["active"])
    return jsonify({"hint": scenario.get("hint", "No hint available.")})


@app.route("/api/scenarios/stop", methods=["POST"])
@login_required
def api_scenario_stop():
    lab = get_lab()
    engine = ScenarioEngine(lab, username=session.get("username", "default"))
    try:
        engine.stop()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# --- WebSocket Terminal ---

@socketio.on("connect")
def handle_ws_connect():
    if not session.get("authenticated"):
        ws_disconnect()


@socketio.on("connect_device")
def handle_connect_device(data):
    if not session.get("authenticated"):
        ws_disconnect()
        return

    sid = request.sid
    port = data.get("port")
    name = data.get("name", "device")
    channel = data.get("channel", name)  # channel = device name

    if not port:
        emit("terminal_output", {"channel": channel, "data": f"\r\nNo console port for {name}\r\n"})
        return

    # Check if already connected to this device
    sessions = telnet_sessions.setdefault(sid, {})
    if channel in sessions:
        # Already connected, just poke it
        try:
            sessions[channel].write(b"\r\n")
        except Exception:
            pass
        return

    try:
        tn = telnetlib.Telnet("127.0.0.1", int(port), timeout=10)
        sessions[channel] = tn
        emit("terminal_output", {"channel": channel, "data": f"\r\nConnected to {name} (port {port})\r\nPress Enter...\r\n"})

        try:
            tn.write(b"\r\n")
        except Exception:
            pass

        def reader():
            while sid in telnet_sessions and channel in telnet_sessions.get(sid, {}):
                try:
                    chunk = tn.read_very_eager()
                    if chunk:
                        socketio.emit("terminal_output", {
                            "channel": channel,
                            "data": chunk.decode(errors="replace"),
                        }, to=sid)
                except EOFError:
                    socketio.emit("terminal_output", {
                        "channel": channel,
                        "data": "\r\n[Device console closed]\r\n",
                    }, to=sid)
                    break
                except OSError:
                    socketio.emit("terminal_output", {
                        "channel": channel,
                        "data": "\r\n[Connection lost]\r\n",
                    }, to=sid)
                    break
                except Exception:
                    break
                time.sleep(0.05)

            # Clean up this channel
            if sid in telnet_sessions:
                telnet_sessions[sid].pop(channel, None)

        t = threading.Thread(target=reader, daemon=True)
        t.start()

    except ConnectionRefusedError:
        emit("terminal_output", {"channel": channel, "data": f"\r\nConnection refused. Is {name} running?\r\n"})
    except TimeoutError:
        emit("terminal_output", {"channel": channel, "data": f"\r\nTimeout. {name} may still be booting.\r\n"})
    except Exception as e:
        emit("terminal_output", {"channel": channel, "data": f"\r\nFailed: {e}\r\n"})


@socketio.on("close_device")
def handle_close_device(data):
    sid = request.sid
    channel = data.get("channel", "")
    sessions = telnet_sessions.get(sid, {})
    tn = sessions.pop(channel, None)
    if tn:
        try:
            tn.close()
        except Exception:
            pass


@socketio.on("terminal_input")
def handle_terminal_input(data):
    if not session.get("authenticated"):
        ws_disconnect()
        return
    sid = request.sid
    channel = data.get("channel", "")
    sessions = telnet_sessions.get(sid, {})
    tn = sessions.get(channel)
    if tn:
        try:
            tn.write(data.get("data", "").encode())
        except Exception:
            pass


@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    sessions = telnet_sessions.pop(sid, {})
    for tn in sessions.values():
        try:
            tn.close()
        except Exception:
            pass


# --- Startup ---
_create_default_admin()

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=25808,
        debug=False,
        allow_unsafe_werkzeug=True,
        ssl_context=(
            "/opt/cisco-lab/web/ssl/cert.pem",
            "/opt/cisco-lab/web/ssl/key.pem",
        ),
    )

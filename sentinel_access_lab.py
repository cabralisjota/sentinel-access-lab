#!/usr/bin/env python3
"""Sentinel Access Lab 0.1: fictional RFID access-control simulation.

Install: python -m pip install Flask
Run:     python sentinel_access_lab.py
Test:    python sentinel_access_lab.py --self-test
Reset the local login password: python sentinel_access_lab.py --reset-password

Open http://127.0.0.1:5002 and use the password printed on first startup.
The database and login configuration live in ~/.sentinel-access-lab by default.
No RFID hardware, workplace connection, card reading or card emulation is used.
"""

import argparse
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
from datetime import timedelta

from flask import Flask, abort, g, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

VERSION = "0.1.0"
BADGES = [
    ("SIM-1001", "Alex Morgan", "employee", "active"),
    ("SIM-1002", "Jordan Lee", "security", "active"),
    ("SIM-1003", "Casey Taylor", "visitor", "active"),
    ("SIM-1004", "Sam Rivera", "employee", "revoked"),
]
DOORS = [
    ("lobby", "Main entrance", ["employee", "security", "visitor"]),
    ("office", "Office floor", ["employee", "security"]),
    ("server", "Server room", ["security"]),
    ("loading", "Loading entrance", ["employee", "security"]),
]


def create_app(data_dir, test_config=None, reset_password=False):
    folder = Path(data_dir).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_file = folder / "login.json"
    fresh_password = None
    if config_file.exists():
        config = json.loads(config_file.read_text())
    else:
        config = {"secret_key": secrets.token_hex(32)}
    if "password_hash" not in config or reset_password:
        fresh_password = secrets.token_urlsafe(15)
        config["password_hash"] = generate_password_hash(
            fresh_password, method="pbkdf2:sha256:600000"
        )
        config["secret_key"] = secrets.token_hex(32)
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(config, output)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config["secret_key"],
        PASSWORD_HASH=config["password_hash"],
        DATABASE=str(folder / "access.db"),
        MAX_CONTENT_LENGTH=32768,
        SESSION_COOKIE_NAME="sentinel_access_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        TRUSTED_HOSTS=["127.0.0.1", "localhost"],
    )
    if test_config:
        app.config.update(test_config)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection:
            connection.close()

    def audit(action, details):
        db().execute(
            "INSERT INTO audit(ts,actor,action,details) VALUES(?,?,?,?)",
            (time.time(), "lab-admin", action, json.dumps(details, sort_keys=True)),
        )

    def open_case(rule, severity, badge_id, door_id, summary, event_ids):
        connection = db()
        found = connection.execute(
            "SELECT id FROM cases WHERE rule=? AND badge_id=? AND door_id=? "
            "AND status IN ('open','investigating') ORDER BY id DESC LIMIT 1",
            (rule, badge_id or "", door_id),
        ).fetchone()
        if found:
            case_id = found["id"]
            connection.execute("UPDATE cases SET last_seen=? WHERE id=?", (time.time(), case_id))
        else:
            cursor = connection.execute(
                "INSERT INTO cases(created,last_seen,rule,severity,badge_id,door_id,summary,status) "
                "VALUES(?,?,?,?,?,?,?,'open')",
                (time.time(), time.time(), rule, severity, badge_id or "", door_id, summary),
            )
            case_id = cursor.lastrowid
            audit("case_created", {"case_id": case_id, "rule": rule})
        connection.executemany(
            "INSERT OR IGNORE INTO case_events(case_id,event_id) VALUES(?,?)",
            [(case_id, event_id) for event_id in event_ids],
        )

    def swipe(badge_id, door_id, after_hours=False, scenario="manual"):
        connection = db()
        badge = connection.execute("SELECT * FROM badges WHERE id=?", (badge_id,)).fetchone()
        door = connection.execute("SELECT * FROM doors WHERE id=?", (door_id,)).fetchone()
        if door is None:
            abort(404, "Door not found")
        result = "DENIED"
        if door["mode"] == "lockdown":
            reason = "Door is in simulated lockdown"
        elif badge is None:
            reason = "Unknown simulated badge"
        elif badge["status"] != "active":
            reason = "Badge is " + badge["status"]
        elif badge["role"] not in json.loads(door["roles"]):
            reason = "Role is not permitted at this door"
        elif after_hours and badge["role"] != "security":
            reason = "After-hours access requires the security role"
        else:
            result, reason = "GRANTED", "Active badge and door policy allow access"
        ts = time.time()
        cursor = connection.execute(
            "INSERT INTO events(ts,kind,badge_id,person,door_id,result,reason,scenario,after_hours) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, "swipe", badge_id, badge["person"] if badge else "Unknown badge", door_id,
             result, reason, scenario, int(after_hours)),
        )
        event_id = cursor.lastrowid
        if result == "DENIED":
            recent = connection.execute(
                "SELECT id FROM events WHERE kind='swipe' AND result='DENIED' "
                "AND badge_id=? AND door_id=? AND ts>=? AND ts<=? ORDER BY id",
                (badge_id, door_id, ts - 60, ts),
            ).fetchall()
            if len(recent) >= 5:
                open_case("DENIED_BURST", "medium", badge_id, door_id,
                          "At least five denied badge attempts at one door within 60 seconds.",
                          [row["id"] for row in recent])
        # Revoked-card use is a separate finding even if another policy denied access first.
        if badge and badge["status"] == "revoked":
            open_case("REVOKED_BADGE", "high", badge_id, door_id,
                      "A simulated revoked badge was presented. Review its event evidence.", [event_id])
        return {"event_id": event_id, "result": result, "reason": reason}

    @app.before_request
    def protect():
        g.nonce = secrets.token_urlsafe(18)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.path.startswith("/api/") and not session.get("admin"):
                abort(401, "Login required")
            token = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf", "")
            expected = session.get("csrf")
            if not expected or not token or not hmac.compare_digest(
                str(token).encode(), str(expected).encode()
            ):
                abort(403, "Refresh the page and try again")
        if request.path.startswith("/api/") and not session.get("admin"):
            abort(401, "Login required")

    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'nonce-" + g.nonce + "'; "
            "style-src 'nonce-" + g.nonce + "'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def error_response(error):
        return jsonify(error=error.description), error.code

    @app.get("/")
    def dashboard():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return render_template_string(HTML, nonce=g.nonce, csrf=session["csrf"],
                                      logged_in=bool(session.get("admin")), error=None)

    @app.post("/login")
    def login():
        now = time.time()
        connection = db()
        # One local administrator; throttle login attempts, including across restarts.
        recent_failures = connection.execute(
            "SELECT count(*) FROM login_failures WHERE ts>?", (now - 60,)
        ).fetchone()[0]
        if recent_failures >= 10:
            abort(429, "Too many attempts. Wait one minute, then refresh.")
        password = request.form.get("password", "")
        if len(password) > 200 or not check_password_hash(app.config["PASSWORD_HASH"], password):
            with connection:
                connection.execute("DELETE FROM login_failures WHERE ts<?", (now - 60,))
                connection.execute("INSERT INTO login_failures(ts) VALUES(?)", (now,))
            return render_template_string(HTML, nonce=g.nonce, csrf=session["csrf"],
                                          logged_in=False, error="Incorrect lab password."), 401
        session.clear()
        session.update(admin=True, csrf=secrets.token_urlsafe(24))
        session.permanent = True
        with connection:
            connection.execute("DELETE FROM login_failures")
            audit("login", {"mode": "local simulation"})
        return render_template_string(HTML, nonce=g.nonce, csrf=session["csrf"],
                                      logged_in=True, error=None)

    @app.post("/api/logout")
    def logout():
        with db():
            audit("logout", {})
        session.clear()
        return jsonify(ok=True)

    def payload():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400, "Expected a JSON object")
        return data

    def text_field(data, key, max_length=80):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > max_length:
            abort(400, "Invalid " + key)
        return value.strip()

    @app.get("/api/state")
    def state():
        connection = db()
        rows = lambda sql: [dict(row) for row in connection.execute(sql)]
        totals = dict(connection.execute(
            "SELECT count(*) AS total, coalesce(sum(result='GRANTED'),0) AS granted, "
            "coalesce(sum(result='DENIED'),0) AS denied, coalesce(sum(kind='forced'),0) AS forced FROM events"
        ).fetchone())
        totals["open_cases"] = connection.execute(
            "SELECT count(*) FROM cases WHERE status!='resolved'"
        ).fetchone()[0]
        return jsonify(
            version=VERSION, mode="fictional simulation", totals=totals,
            badges=rows("SELECT * FROM badges ORDER BY id"),
            doors=rows("SELECT * FROM doors ORDER BY id"),
            events=rows("SELECT * FROM events ORDER BY id DESC LIMIT 150"),
            cases=rows("SELECT c.*, (SELECT count(*) FROM case_events ce WHERE ce.case_id=c.id) "
                       "AS evidence_count FROM cases c ORDER BY id DESC LIMIT 100"),
            audit=rows("SELECT * FROM audit ORDER BY id DESC LIMIT 50"),
            csrf=session["csrf"],
        )

    @app.post("/api/swipe")
    def api_swipe():
        data = payload()
        badge_id = text_field(data, "badge_id", 40)
        door_id = text_field(data, "door_id", 40)
        after_hours = data.get("after_hours", False)
        if not isinstance(after_hours, bool):
            abort(400, "after_hours must be true or false")
        with db():
            result = swipe(badge_id, door_id, after_hours)
            audit("simulate_swipe", {"badge_id": badge_id, "door_id": door_id, **result})
        return jsonify(result)

    @app.post("/api/badges/<badge_id>")
    def update_badge(badge_id):
        data = payload()
        status = text_field(data, "status")
        if status not in ("active", "suspended", "revoked"):
            abort(400, "Invalid badge status")
        connection = db()
        with connection:
            before = connection.execute("SELECT status FROM badges WHERE id=?", (badge_id,)).fetchone()
            if before is None:
                abort(404, "Badge not found")
            connection.execute("UPDATE badges SET status=? WHERE id=?", (status, badge_id))
            audit("badge_status", {"badge_id": badge_id, "before": before["status"], "after": status})
        return jsonify(ok=True)

    @app.post("/api/doors/<door_id>")
    def update_door(door_id):
        data = payload()
        mode = text_field(data, "mode")
        if mode not in ("normal", "lockdown"):
            abort(400, "Invalid door mode")
        with db():
            before = db().execute("SELECT mode FROM doors WHERE id=?", (door_id,)).fetchone()
            if before is None:
                abort(404, "Door not found")
            db().execute("UPDATE doors SET mode=? WHERE id=?", (mode, door_id))
            audit("door_mode", {"door_id": door_id, "before": before["mode"], "after": mode})
        return jsonify(ok=True)

    @app.post("/api/scenarios")
    def scenario():
        name = text_field(payload(), "name")
        if name not in ("routine", "denied_burst", "revoked_badge", "forced_door"):
            abort(400, "Unknown scenario")
        connection = db()
        results = []
        with connection:
            if name == "routine":
                results.append(swipe("SIM-1001", "lobby", scenario=name))
                results.append(swipe("SIM-1002", "server", scenario=name))
                results.append(swipe("SIM-1003", "server", scenario=name))
            elif name == "denied_burst":
                for _ in range(5):
                    results.append(swipe("SIM-UNKNOWN", "office", scenario=name))
            elif name == "revoked_badge":
                # Respect the current badge state; never silently revoke or re-enable a badge.
                results.append(swipe("SIM-1004", "lobby", scenario=name))
            else:
                cursor = connection.execute(
                    "INSERT INTO events(ts,kind,badge_id,person,door_id,result,reason,scenario,after_hours) "
                    "VALUES(?,'forced','','Unattributed','loading','FORCED',?,?,0)",
                    (time.time(), "Synthetic door sensor reported opening without a grant", name),
                )
                open_case("FORCED_DOOR", "high", "", "loading",
                          "Simulated door sensor signal; no badge identity is attributed.", [cursor.lastrowid])
                results.append({"event_id": cursor.lastrowid, "result": "FORCED"})
            audit("run_scenario", {"name": name, "events": len(results)})
        return jsonify(results=results)

    @app.get("/api/cases/<int:case_id>")
    def case_details(case_id):
        connection = db()
        case = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if case is None:
            abort(404, "Case not found")
        evidence = [dict(row) for row in connection.execute(
            "SELECT e.* FROM case_events ce JOIN events e ON e.id=ce.event_id "
            "WHERE ce.case_id=? ORDER BY e.id", (case_id,)
        )]
        notes = [dict(row) for row in connection.execute(
            "SELECT * FROM notes WHERE case_id=? ORDER BY id", (case_id,)
        )]
        return jsonify(case=dict(case), events=evidence, notes=notes)

    @app.post("/api/cases/<int:case_id>")
    def case_update(case_id):
        data = payload()
        status = text_field(data, "status")
        if status not in ("open", "investigating", "resolved"):
            abort(400, "Invalid case status")
        note = data.get("note", "")
        if not isinstance(note, str) or len(note) > 2000:
            abort(400, "Note must be text up to 2000 characters")
        with db():
            before = db().execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
            if before is None:
                abort(404, "Case not found")
            db().execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
            if note.strip():
                db().execute("INSERT INTO notes(case_id,ts,author,note) VALUES(?,?,?,?)",
                             (case_id, time.time(), "lab-admin", note.strip()))
            audit("case_update", {"case_id": case_id, "before": before["status"], "after": status,
                                  "note_added": bool(note.strip())})
        return jsonify(ok=True)

    @app.get("/api/export")
    def export():
        connection = db()
        tables = ("badges", "doors", "events", "cases", "case_events", "notes", "audit")
        result = {table: [dict(row) for row in connection.execute("SELECT * FROM " + table)]
                  for table in tables}
        result["metadata"] = {"version": VERSION, "simulation": True, "exported_at": time.time()}
        with connection:
            audit("export", {"format": "JSON"})
        response = jsonify(result)
        response.headers["Content-Disposition"] = 'attachment; filename="sentinel_access_evidence.json"'
        return response

    with app.app_context():
        connection = db()
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS badges(id TEXT PRIMARY KEY, person TEXT NOT NULL,
                role TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS doors(id TEXT PRIMARY KEY, name TEXT NOT NULL,
                roles TEXT NOT NULL, mode TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
                kind TEXT NOT NULL, badge_id TEXT NOT NULL, person TEXT NOT NULL, door_id TEXT NOT NULL,
                result TEXT NOT NULL, reason TEXT NOT NULL, scenario TEXT NOT NULL, after_hours INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS events_burst ON events(badge_id,door_id,ts);
            CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY AUTOINCREMENT,
                created REAL NOT NULL, last_seen REAL NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
                badge_id TEXT NOT NULL, door_id TEXT NOT NULL, summary TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_events(case_id INTEGER REFERENCES cases(id),
                event_id INTEGER REFERENCES events(id), PRIMARY KEY(case_id,event_id));
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id), ts REAL NOT NULL, author TEXT NOT NULL, note TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS login_failures(ts REAL NOT NULL);
        ''')
        with connection:
            connection.executemany("INSERT OR IGNORE INTO badges VALUES(?,?,?,?)", BADGES)
            connection.executemany("INSERT OR IGNORE INTO doors VALUES(?,?,?,'normal')",
                                   [(key, name, json.dumps(roles)) for key, name, roles in DOORS])
    return app, fresh_password


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Access Lab</title><style nonce="{{ nonce }}">
:root{color-scheme:dark;--bg:#0b1019;--panel:#131d2c;--line:#29364a;--muted:#96a8be;--cyan:#66e3d2;--red:#ff8b96;--gold:#edc67d}
*{box-sizing:border-box}body{background:var(--bg);color:#e9eff7;margin:0;font:14px/1.55 system-ui,sans-serif}main{max-width:1380px;margin:auto;padding:26px}h1{font-size:27px;letter-spacing:-1px;margin:2px 0}h2{font-size:17px;margin:0 0 15px}h3{font-size:14px;margin:0}p{margin:8px 0}.muted,small{color:var(--muted)}.eyebrow{font-size:11px;letter-spacing:2px;color:var(--cyan);font-weight:750}.top,.split,.row,.tools{display:flex;justify-content:space-between;align-items:center;gap:12px}.top{margin-bottom:20px}.row{justify-content:flex-start}.tools{flex-wrap:wrap}.banner{border:1px solid #3d534d;background:#122622;color:#b8e3d3;border-radius:9px;padding:10px 15px;margin:18px 0}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:19px}.stat b{font-size:32px;display:block;color:var(--cyan)}.stat small{font-size:12px}.grid{display:grid;grid-template-columns:1.05fr 1fr;gap:16px;margin-bottom:16px}.full{margin-bottom:16px}.label{display:block;color:var(--muted);font-size:12px;margin:10px 0 5px}input,select,textarea,button,a.btn{font:inherit;border-radius:7px;border:1px solid #405069;padding:9px 11px}input,select,textarea{color:#eaf0fa;background:#0e1724;max-width:100%}input:not([type=checkbox]),select,textarea{width:100%}textarea{resize:vertical;min-height:80px}button,a.btn{cursor:pointer;background:#223449;color:#ecf4fc;text-decoration:none;display:inline-block}button:hover,a.btn:hover{border-color:var(--cyan)}button.primary{background:#74e1cf;color:#0c211f;border-color:#74e1cf;font-weight:700}button.warn{color:var(--red)}button:disabled{opacity:.5;cursor:wait}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}.badge{border:1px solid #40536a;border-radius:30px;display:inline-block;padding:2px 9px;font-size:11px}.good{color:var(--cyan)}.bad{color:var(--red)}.gold{color:var(--gold)}.item{padding:13px 0;border-top:1px solid var(--line)}.item:first-child{border:0}.controls{display:flex;align-items:center;gap:6px;margin-top:8px;flex-wrap:wrap}.controls button{font-size:12px;padding:6px 9px}.scroll{overflow:auto;max-height:430px}table{width:100%;border-collapse:collapse;white-space:nowrap;text-align:left}th{font-size:11px;color:var(--muted);padding:11px 8px;letter-spacing:.6px}td{padding:11px 8px;font-size:12px;border-top:1px solid var(--line)}td.wrap{white-space:normal;min-width:160px}.empty{color:var(--muted);padding:20px 0}#toast{min-height:24px;margin-bottom:8px;color:var(--cyan)}#toast.bad{color:var(--red)}.login{max-width:470px;margin:10vh auto}.login .panel{padding:30px}.login button{margin-top:20px;width:100%}.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}.check{display:flex;align-items:center;gap:8px;margin:16px 0}.scenario{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin:14px 0}dialog{background:var(--panel);color:#e9eff7;border:1px solid #4b657e;border-radius:13px;width:min(860px,95vw);max-height:90vh;padding:25px}dialog::backdrop{background:#000b}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1724;border-radius:8px;padding:14px;font-size:12px}.hidden{display:none}.footer{text-align:center;font-size:11px;color:var(--muted);margin:28px 0 4px}.gap{margin-top:14px}#filter{max-width:320px}#caseNote{margin-bottom:10px}#audit td{white-space:normal;overflow-wrap:anywhere}
@media(max-width:850px){main{padding:16px}.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}.top{align-items:flex-start;flex-wrap:wrap}h1{font-size:24px}.panel{padding:16px}.two{grid-template-columns:1fr}}
</style></head><body>
{% if not logged_in %}
<main class="login"><div class="panel"><div class="eyebrow">SENTINEL / ACCESS LAB</div><h1>Open your simulation.</h1><p class="muted">Fictional badges, policy decisions, and investigation evidence on your local device.</p>
<form method="post" action="/login"><input type="hidden" name="csrf" value="{{ csrf }}"><label class="label" for="password">Lab administrator password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="200"><button class="primary" type="submit">Enter access lab</button></form>
{% if error %}<p class="bad">{{ error }}</p>{% endif %}<p class="muted gap">Use the password printed in Termux on first startup. To set a new one, stop the app and run it with <code>--reset-password</code>.</p></div></main>
{% else %}
<main><header class="top"><div><div class="eyebrow">SENTINEL / ACCESS LAB 0.1</div><h1>Every swipe tells a story.</h1><div class="muted">Monitor access. Investigate patterns. Test your response.</div></div><div class="row"><a class="btn" href="/api/export">Export evidence</a><button id="logout">Sign out</button></div></header>
<div class="banner"><strong>SIMULATION ONLY</strong> · Fictional identities and doors. Every control changes this lab's database. After-hours is a selected test condition.</div>
<div id="toast" role="status" aria-live="polite"></div>
<section class="stats"><div class="stat"><small>ACCESS EVENTS</small><b id="total">0</b></div><div class="stat"><small>GRANTED</small><b id="granted">0</b></div><div class="stat"><small>DENIED</small><b id="denied">0</b></div><div class="stat"><small>OPEN INVESTIGATIONS</small><b id="open_cases">0</b></div></section>
<div class="grid"><section class="panel"><h2>Simulate a badge presentation</h2><form id="swipeForm"><div class="two"><div><label class="label" for="badgeChoice">Fictional badge</label><select id="badgeChoice"></select></div><div><label class="label" for="doorChoice">Door</label><select id="doorChoice"></select></div></div><label class="check"><input type="checkbox" id="afterHours"> Simulate after-hours access</label><button class="primary" type="submit">Present badge</button></form><p class="muted gap">Decision order: door lockdown → known active badge → permitted role → after-hours policy.</p></section>
<section class="panel"><h2>Run an investigation scenario</h2><div class="scenario"><button data-scenario="routine">Routine shift · 3 events</button><button data-scenario="denied_burst">Repeated denials · 5 events</button><button data-scenario="revoked_badge">Revoked badge use · 1 event</button><button data-scenario="forced_door">Forced-door sensor · 1 event</button></div><p class="muted">Rules: 5 denials at one door in 60 seconds; use of a revoked badge; a synthetic forced-door signal. Current badge and door settings still apply.</p><p class="muted">Scenarios run only when clicked. Findings are indicators for investigation.</p></section></div>
<div class="grid"><section class="panel"><h2>Badge controls</h2><div id="badges"></div></section><section class="panel"><h2>Door controls</h2><div id="doors"></div><p class="muted">Lockdown denies all simulated presentations, including the security role. This does not model emergency egress or physical lock hardware.</p></section></div>
<section class="panel full"><div class="tools"><h2>Access event stream</h2><input id="filter" placeholder="Filter badge, person, door, result…" aria-label="Filter access events"></div><div class="scroll"><table><thead><tr><th>TIME</th><th>BADGE / PERSON</th><th>DOOR</th><th>DECISION</th><th>REASON</th></tr></thead><tbody id="events"></tbody></table></div><p class="muted">Latest 150 events. Full history is included in the JSON export. Times use your browser's local time zone.</p></section>
<section class="panel full"><h2>Investigation queue</h2><div id="cases"></div><p class="muted">Each case links to the exact triggering events. Resolve cases after recording your assessment.</p></section>
<section class="panel full"><h2>Administrative audit trail</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>ACTOR</th><th>ACTION</th><th>DETAILS</th></tr></thead><tbody id="audit"></tbody></table></div><p class="muted">Latest 50 actions. Audit records are ordinary SQLite data, not a tamper-resistant log.</p></section>
<div class="footer">SENTINEL ACCESS LAB · LOCAL LEARNING ENVIRONMENT · NO WORKPLACE CONNECTION</div></main>
<dialog id="caseDialog"><div class="split"><h2 id="caseTitle">Investigation</h2><button id="closeDialog">Close</button></div><p id="caseSummary"></p><div id="caseEvidence"></div><h3 class="gap">Analyst notes</h3><div id="caseNotes"></div><form id="caseForm"><label class="label" for="caseStatus">Case status</label><select id="caseStatus"><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><label class="label" for="caseNote">Add an investigation note</label><textarea id="caseNote" maxlength="2000" placeholder="What happened? What evidence supports your assessment?"></textarea><button class="primary" type="submit">Save investigation</button></form></dialog>
<script nonce="{{ nonce }}">
const $=id=>document.getElementById(id);let csrf={{ csrf|tojson }},state=null,activeCase=null,loading=false;
const node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};
const when=ts=>new Date(ts*1000).toLocaleString();
function toast(message,error=false){$('toast').textContent=message;$('toast').className=error?'bad':''}
async function api(path,body){const options={credentials:'same-origin',headers:{}};if(body!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(body)}const response=await fetch(path,options);const data=await response.json();if(response.status===401){location.reload();throw Error('Please sign in again')}if(!response.ok)throw Error(data.error||'Request failed');return data}
async function action(path,body,message){try{const result=await api(path,body);toast(message||result.result+' · '+result.reason);await refresh();return true}catch(error){toast(error.message,true);return false}}
function button(label,handler,cls){const b=node('button',label,cls);b.type='button';b.addEventListener('click',handler);return b}
function fillSelect(id,items){const select=$(id),selected=select.value;select.replaceChildren(...items.map(([value,label])=>{const option=node('option',label);option.value=value;return option}));if(items.some(item=>item[0]===selected))select.value=selected}
function renderControls(){fillSelect('badgeChoice',[...state.badges.map(b=>[b.id,b.id+' · '+b.person]),['SIM-UNKNOWN','SIM-UNKNOWN · Unregistered badge']]);fillSelect('doorChoice',state.doors.map(d=>[d.id,d.name]));const badges=$('badges');badges.replaceChildren();for(const b of state.badges){const item=node('div',undefined,'item'),top=node('div',undefined,'split');top.append(node('strong',b.person),node('span',b.status,b.status==='active'?'badge good':'badge bad'));item.append(top,node('small',b.id+' · '+b.role));const controls=node('div',undefined,'controls');for(const status of ['active','suspended','revoked'])if(status!==b.status)controls.append(button(status==='active'?'Activate':status==='suspended'?'Suspend':'Revoke',()=>action('/api/badges/'+encodeURIComponent(b.id),{status},b.id+' is now '+status),status==='revoked'?'warn':''));item.append(controls);badges.append(item)}const doors=$('doors');doors.replaceChildren();for(const d of state.doors){const item=node('div',undefined,'item'),top=node('div',undefined,'split');top.append(node('strong',d.name),node('span',d.mode,d.mode==='normal'?'badge good':'badge bad'));item.append(top,node('small','Permitted roles: '+JSON.parse(d.roles).join(', ')));const controls=node('div',undefined,'controls'),mode=d.mode==='normal'?'lockdown':'normal';controls.append(button(mode==='lockdown'?'Simulate lockdown':'Restore normal access',()=>action('/api/doors/'+encodeURIComponent(d.id),{mode},d.name+': '+mode),mode==='lockdown'?'warn':''));item.append(controls);doors.append(item)}}
function renderEvents(){if(!state)return;const term=$('filter').value.toLowerCase();const rows=state.events.filter(e=>[e.badge_id,e.person,e.door_id,e.result,e.reason,e.scenario].join(' ').toLowerCase().includes(term));$('events').replaceChildren();for(const e of rows){const tr=node('tr');tr.append(node('td',when(e.ts)),node('td',(e.badge_id||'No badge')+' / '+e.person),node('td',e.door_id));const decision=node('td');decision.append(node('span',e.result,e.result==='GRANTED'?'badge good':'badge bad'));tr.append(decision,node('td',e.reason+(e.after_hours?' · After-hours test':''),'wrap'));$('events').append(tr)}if(!rows.length){const tr=node('tr'),td=node('td','No matching events yet. Present a badge or run a scenario.','empty');td.colSpan=5;tr.append(td);$('events').append(tr)}}
function renderCases(){const root=$('cases');root.replaceChildren();for(const c of state.cases){const item=node('div',undefined,'item'),top=node('div',undefined,'split'),left=node('div');left.append(node('strong','#'+c.id+' · '+c.rule+' · '+c.severity),node('p',(c.badge_id||'No attributed badge')+' → '+c.door_id+' · '+c.status+' · '+c.evidence_count+' evidence events','muted'));top.append(left,button('Investigate',()=>openCase(c.id)));item.append(top);root.append(item)}if(!state.cases.length)root.append(node('p','No cases yet. Run Repeated denials or Forced-door sensor to create one.','empty'))}
function renderAudit(){const root=$('audit');root.replaceChildren();for(const a of state.audit){const tr=node('tr');tr.append(node('td',when(a.ts)),node('td',a.actor),node('td',a.action),node('td',a.details));root.append(tr)}}
async function refresh(){if(loading)return;loading=true;try{state=await api('/api/state');csrf=state.csrf;for(const key of ['total','granted','denied','open_cases'])$(key).textContent=state.totals[key];renderControls();renderEvents();renderCases();renderAudit()}catch(error){toast(error.message,true)}finally{loading=false}}
async function openCase(id){try{const data=await api('/api/cases/'+id);activeCase=id;$('caseTitle').textContent='Case #'+id+' · '+data.case.rule;$('caseSummary').textContent=data.case.summary;$('caseStatus').value=data.case.status;$('caseNote').value='';const evidence=$('caseEvidence');evidence.replaceChildren(node('h3','Event evidence'));for(const e of data.events)evidence.append(node('pre',JSON.stringify(e,null,2)));const notes=$('caseNotes');notes.replaceChildren();for(const n of data.notes)notes.append(node('p',when(n.ts)+' · '+n.author+': '+n.note));if(!data.notes.length)notes.append(node('p','No notes recorded yet.','muted'));if(!$('caseDialog').open)$('caseDialog').showModal()}catch(error){toast(error.message,true)}}
$('swipeForm').addEventListener('submit',event=>{event.preventDefault();action('/api/swipe',{badge_id:$('badgeChoice').value,door_id:$('doorChoice').value,after_hours:$('afterHours').checked})});
document.querySelectorAll('[data-scenario]').forEach(b=>b.addEventListener('click',()=>action('/api/scenarios',{name:b.dataset.scenario},'Scenario complete. Review events and investigations.')));
$('filter').addEventListener('input',renderEvents);$('closeDialog').addEventListener('click',()=>$('caseDialog').close());
$('caseForm').addEventListener('submit',async event=>{event.preventDefault();if(await action('/api/cases/'+activeCase,{status:$('caseStatus').value,note:$('caseNote').value},'Investigation saved.'))await openCase(activeCase)});
$('logout').addEventListener('click',async()=>{try{await api('/api/logout',{});location.reload()}catch(error){toast(error.message,true)}});
refresh();setInterval(refresh,5000);
</script>{% endif %}</body></html>'''


def run_tests():
    import unittest

    class AccessLabTests(unittest.TestCase):
        def setUp(self):
            self.tmp = tempfile.TemporaryDirectory()
            self.app, password = create_app(self.tmp.name, {"TESTING": True})
            self.client = self.app.test_client()
            self.client.get("/")
            with self.client.session_transaction() as login_session:
                token = login_session["csrf"]
            result = self.client.post("/login", data={"password": password, "csrf": token})
            self.assertEqual(result.status_code, 200)
            with self.client.session_transaction() as login_session:
                self.token = login_session["csrf"]

        def tearDown(self):
            self.tmp.cleanup()

        def post(self, path, data):
            response = self.client.post(path, json=data, headers={"X-CSRF-Token": self.token})
            self.assertEqual(response.status_code, 200, response.get_json())
            return response.get_json()

        def state(self):
            return self.client.get("/api/state").get_json()

        def swipe(self, badge="SIM-1001", door="lobby", after_hours=False):
            return self.post("/api/swipe", {"badge_id": badge, "door_id": door,
                                             "after_hours": after_hours})

        def test_role_and_after_hours_policies(self):
            self.assertEqual(self.swipe()["result"], "GRANTED")
            self.assertEqual(self.swipe(door="server")["result"], "DENIED")
            self.assertEqual(self.swipe(after_hours=True)["result"], "DENIED")
            self.assertEqual(self.swipe("SIM-1002", "server", True)["result"], "GRANTED")
            self.assertEqual(self.swipe("SIM-1003", "lobby")["result"], "GRANTED")

        def test_controls_affect_decisions_and_survive_restart(self):
            self.post("/api/badges/SIM-1001", {"status": "suspended"})
            self.assertEqual(self.swipe()["result"], "DENIED")
            self.post("/api/badges/SIM-1001", {"status": "active"})
            self.post("/api/doors/lobby", {"mode": "lockdown"})
            self.assertEqual(self.swipe("SIM-1002")["result"], "DENIED")
            app2, password2 = create_app(self.tmp.name, {"TESTING": True})
            self.assertIsNone(password2)
            with sqlite3.connect(app2.config["DATABASE"]) as connection:
                self.assertEqual(connection.execute("SELECT mode FROM doors WHERE id='lobby'").fetchone()[0],
                                 "lockdown")
                self.assertEqual(connection.execute("SELECT count(*) FROM audit WHERE action='door_mode'")
                                 .fetchone()[0], 1)

        def test_denial_threshold_dedup_and_evidence(self):
            for _ in range(4):
                self.swipe("SIM-UNKNOWN", "office")
            self.assertEqual(len(self.state()["cases"]), 0)
            self.swipe("SIM-UNKNOWN", "office")
            self.swipe("SIM-UNKNOWN", "office")
            cases = self.state()["cases"]
            self.assertEqual(len(cases), 1)
            evidence = self.client.get("/api/cases/" + str(cases[0]["id"])).get_json()
            self.assertEqual(evidence["case"]["rule"], "DENIED_BURST")
            self.assertEqual(len(evidence["events"]), 6)

        def test_denial_window_and_door_separation(self):
            for _ in range(4):
                self.swipe("SIM-UNKNOWN", "office")
            with sqlite3.connect(self.app.config["DATABASE"]) as connection:
                connection.execute("UPDATE events SET ts=ts-61")
            self.swipe("SIM-UNKNOWN", "office")
            for _ in range(4):
                self.swipe("SIM-UNKNOWN", "server")
            self.assertEqual(self.state()["cases"], [])

        def test_revoked_and_forced_cases(self):
            self.swipe("SIM-1004")
            self.post("/api/scenarios", {"name": "forced_door"})
            cases = self.state()["cases"]
            self.assertEqual({c["rule"] for c in cases}, {"REVOKED_BADGE", "FORCED_DOOR"})
            forced = next(c for c in cases if c["rule"] == "FORCED_DOOR")
            self.assertEqual(forced["badge_id"], "")
            self.assertEqual(self.state()["totals"]["granted"], 0)

        def test_case_notes_resolution_and_new_detection(self):
            self.swipe("SIM-1004")
            case_id = self.state()["cases"][0]["id"]
            self.post("/api/cases/" + str(case_id), {"status": "resolved", "note": "Reviewed simulated event."})
            self.assertEqual(self.state()["totals"]["open_cases"], 0)
            details = self.client.get("/api/cases/" + str(case_id)).get_json()
            self.assertEqual(details["notes"][0]["note"], "Reviewed simulated event.")
            self.swipe("SIM-1004")
            self.assertEqual(len(self.state()["cases"]), 2)

        def test_auth_csrf_and_logout(self):
            anonymous = self.app.test_client()
            self.assertEqual(anonymous.get("/api/state").status_code, 401)
            self.assertEqual(anonymous.get("/api/export").status_code, 401)
            self.assertEqual(self.client.post("/api/scenarios", json={"name": "routine"}).status_code, 403)
            self.assertEqual(self.client.post("/api/scenarios", json={"name": "routine"},
                             headers={"X-CSRF-Token": "invalid-\u00e9"}).status_code, 403)
            self.post("/api/logout", {})
            self.assertEqual(self.client.get("/api/state").status_code, 401)

        def test_export_excludes_credentials_and_includes_evidence(self):
            self.post("/api/scenarios", {"name": "denied_burst"})
            result = self.client.get("/api/export")
            data = result.get_json()
            self.assertTrue(data["metadata"]["simulation"])
            self.assertEqual(len(data["events"]), 5)
            self.assertEqual(len(data["case_events"]), 5)
            self.assertNotIn("password_hash", result.get_data(as_text=True))

        def test_validation_and_security_headers(self):
            response = self.client.post("/api/swipe", json={"badge_id": "SIM-1001", "door_id": "lobby",
                                        "after_hours": "false"}, headers={"X-CSRF-Token": self.token})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.client.post("/api/badges/SIM-1001", json={"status": "made-up"},
                             headers={"X-CSRF-Token": self.token}).status_code, 400)
            result = self.client.get("/")
            self.assertIn("frame-ancestors 'none'", result.headers["Content-Security-Policy"])
            self.assertNotIn("<script nonce=\"\">", result.get_data(as_text=True))

        def test_login_throttle(self):
            anonymous = self.app.test_client()
            anonymous.get("/")
            with anonymous.session_transaction() as login_session:
                csrf = login_session["csrf"]
            for _ in range(10):
                self.assertEqual(anonymous.post("/login", data={"password": "wrong", "csrf": csrf}).status_code,
                                 401)
            self.assertEqual(anonymous.post("/login", data={"password": "wrong", "csrf": csrf}).status_code,
                             429)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AccessLabTests)
    return unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default=str(Path.home() / ".sentinel-access-lab"))
    parser.add_argument("--port", type=int, default=5002)
    parser.add_argument("--reset-password", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        raise SystemExit(0 if run_tests() else 1)
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a port from 1024 to 65535")
    app, password = create_app(args.data_dir, reset_password=args.reset_password)
    print("\nSENTINEL ACCESS LAB " + VERSION + " — FICTIONAL SIMULATION", flush=True)
    print("Open http://127.0.0.1:" + str(args.port), flush=True)
    if password:
        print("\nYour new lab login password: " + password, flush=True)
        print("Save it privately. It is shown only when created or reset.\n", flush=True)
    else:
        print("Use your saved lab password. Reset with --reset-password if needed.\n", flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()

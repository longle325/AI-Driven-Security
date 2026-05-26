from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask, jsonify, render_template_string, request

from src.config import ensure_directories, settings
from src.io_utils import write_jsonl

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Local Lab Web</title>
  <style>
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: #f6f3ec; color: #1d2520; }
    main { max-width: 920px; margin: 56px auto; padding: 0 24px; }
    section { background: #fffdf8; border: 1px solid #d9d1c3; border-radius: 8px; padding: 24px; box-shadow: 0 16px 40px rgba(40, 33, 24, .08); }
    h1 { margin: 0 0 12px; font-size: 34px; }
    a, button { border: 1px solid #263b34; background: #263b34; color: white; padding: 10px 14px; border-radius: 6px; text-decoration: none; cursor: pointer; }
    .grid { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
    input { padding: 10px 12px; border: 1px solid #b9ae9d; border-radius: 6px; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Safe Local Lab Web</h1>
      <p>This web app creates benign local request logs for the cyber defense demo. It does not contact external targets.</p>
      <div class="grid">
        <a href="/">Home</a>
        <a href="/profile">Profile</a>
        <a href="/admin">Admin</a>
        <a href="/search?q=SIMULATED_SQLI_MARKER">Safe Web Marker</a>
      </div>
      <form method="post" action="/login" style="margin-top:24px">
        <input name="username" placeholder="student" />
        <input name="password" placeholder="password" type="password" />
        <button type="submit">Login</button>
      </form>
    </section>
  </main>
</body>
</html>
"""


def _log_event(event_type: str, endpoint: str, status_code: int, payload_risk: float = 0.05) -> None:
    ensure_directories()
    source = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    event = {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_ip": source,
        "user_id": request.form.get("username", "lab_user"),
        "event_type": event_type,
        "endpoint": endpoint,
        "http_method": request.method,
        "status_code": status_code,
        "request_count_1m": 8,
        "failed_login_count_5m": 1 if status_code in (401, 403) else 0,
        "unique_ports_1m": 1,
        "status_4xx_count_5m": 1 if 400 <= status_code < 500 else 0,
        "status_5xx_count_5m": 0,
        "payload_risk_score": payload_risk,
        "endpoint_risk_score": 0.8 if endpoint == "/admin" else 0.35,
        "avg_request_interval": 2.5,
        "label": "web_attack" if payload_risk > 0.7 else "normal",
    }
    write_jsonl(settings.events_jsonl, [event], append=True)


@app.route("/")
def index():
    _log_event("request", "/", 200)
    return render_template_string(PAGE)


@app.route("/profile")
def profile():
    _log_event("request", "/profile", 200)
    return jsonify({"profile": "local lab user", "scope": "localhost only"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    risk = 0.85 if "SIMULATED" in q.upper() else 0.1
    _log_event("SIMULATED_WEB_ATTACK_MARKER" if risk > 0.7 else "search", "/search", 400 if risk > 0.7 else 200, risk)
    return jsonify({"query": q, "safe_marker": risk > 0.7})


@app.route("/admin")
def admin():
    _log_event("admin_access_denied", "/admin", 403, 0.25)
    return jsonify({"error": "local lab admin route denied"}), 403


@app.route("/login", methods=["POST"])
def login():
    _log_event("login_failed", "/login", 401, 0.08)
    return jsonify({"error": "invalid local lab credentials"}), 401


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

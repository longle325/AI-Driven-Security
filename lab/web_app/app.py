from __future__ import annotations

from datetime import UTC, datetime
from html import escape
import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

from src.config import EVENTS_JSONL, ensure_project_dirs
from src.feature_engineering import payload_risk_score
from src.io_utils import append_jsonl


PAGE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>AI Cyber Defense Lab</title>
    <style>
      :root { --ink:#111b22; --muted:#60717d; --line:#cad5dc; --paper:#fff; --wash:#f2f6f7; --teal:#0f6f78; --red:#9f1d20; --amber:#a96f0c; }
      * { box-sizing: border-box; }
      body { font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: var(--wash); color: var(--ink); }
      main { max-width: 1120px; margin: 28px auto; padding: 0 18px; }
      .shell { border: 1px solid var(--line); border-radius: 8px; background: var(--paper); overflow: hidden; }
      header { padding: 18px 20px; border-left: 6px solid var(--teal); border-bottom: 1px solid var(--line); }
      h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
      .sub { margin-top: 4px; color: var(--muted); font-size: 14px; }
      nav { display: flex; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--line); background: #f9fbfc; flex-wrap: wrap; }
      nav a { color: #17323b; text-decoration: none; border: 1px solid var(--line); border-radius: 6px; padding: 7px 10px; background: white; font-size: 14px; }
      .content { padding: 20px; }
      .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
      .panel { border: 1px solid var(--line); border-radius: 7px; padding: 14px; background: #fbfcfd; min-height: 120px; }
      .panel b { display:block; font-size: 14px; margin-bottom: 6px; }
      .muted { color: var(--muted); font-size: 13px; }
      input { padding: .65rem; margin: .25rem 0 .7rem; width: min(100%, 24rem); border: 1px solid var(--line); border-radius: 6px; }
      button { padding: .65rem .95rem; background: var(--teal); color: white; border: 0; border-radius: 6px; font-weight: 700; }
      code { background: #eef3f5; padding: .15rem .35rem; border-radius: 4px; }
      .status { display:inline-block; border-radius: 999px; padding: 4px 9px; font-size: 12px; background: #e8f3ef; color: #245d42; border: 1px solid #b8d8ca; }
      .danger { background: #fff0ee; color: var(--red); border-color: #f0b9b3; }
      @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
    </style>
  </head>
  <body>
    <main>
      <section class="shell">
        <header>
          <h1>AI-Driven Cyber Defense Lab</h1>
          <div class="sub">Local telemetry source for controlled defensive monitoring.</div>
        </header>
        <nav>
          <a href="/">Home</a>
          <a href="/login">Login</a>
          <a href="/search">Search</a>
          <a href="/profile">Profile</a>
          <a href="/admin">Admin</a>
        </nav>
        <div class="content">{{ body|safe }}</div>
      </section>
    </main>
  </body>
</html>
"""


def _now() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _events_path(app: Flask) -> Path:
    configured = app.config.get("LAB_EVENTS_PATH", EVENTS_JSONL)
    return Path(configured)


def _source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    raw = (forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or "127.0.0.1"
    if raw in {"127.0.0.1", "::1"}:
        return "172.20.0.10"
    return raw


def _write_event(app: Flask, event: dict[str, Any]) -> None:
    append_jsonl(_events_path(app), [event])


def _event(
    event_type: str,
    endpoint: str,
    status_code: int,
    label: str = "normal",
    **extra: Any,
) -> dict[str, Any]:
    marker = str(extra.get("payload_marker", "SIMULATED_NONE"))
    query = str(extra.get("query", ""))
    risk = extra.get("payload_risk_score", payload_risk_score(marker, query))
    return {
        "timestamp": _now(),
        "source_ip": _source_ip(),
        "user_id": extra.get("user_id", "lab_user"),
        "event_type": event_type,
        "endpoint": endpoint,
        "http_method": request.method,
        "status_code": status_code,
        "request_count_1m": extra.get("request_count_1m", 1),
        "failed_login_count_5m": extra.get("failed_login_count_5m", 0),
        "unique_endpoints_5m": extra.get("unique_endpoints_5m", 1),
        "unique_ports_1m": extra.get("unique_ports_1m", 1),
        "status_4xx_count_5m": extra.get("status_4xx_count_5m", 1 if 400 <= status_code < 500 else 0),
        "status_5xx_count_5m": extra.get("status_5xx_count_5m", 1 if status_code >= 500 else 0),
        "payload_risk_score": risk,
        "avg_request_interval": extra.get("avg_request_interval", 30.0),
        "user_agent": request.headers.get("User-Agent", "lab-browser"),
        "payload_marker": marker,
        "query": query,
        "label": label,
    }


def _page(body: str) -> str:
    return render_template_string(PAGE, body=body)


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    ensure_project_dirs()
    app = Flask(__name__)
    app.config.update(test_config or {})

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "lab-web"})

    @app.get("/")
    def home():
        _write_event(app, _event("page_view", "/", 200))
        return _page(
            """
            <div class="grid">
              <div class="panel"><b>Session Source</b><span class="status">local lab</span><p class="muted">Synthetic user activity is written to JSONL telemetry.</p></div>
              <div class="panel"><b>Detection Surface</b><span class="status">structured logs</span><p class="muted">Login, search, profile, admin, and API events carry model features.</p></div>
              <div class="panel"><b>Boundary</b><span class="status">safe only</span><p class="muted">All risky-looking behavior is represented by simulated markers.</p></div>
            </div>
            """
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return _page(
                """
                <div class="panel">
                <form method="post">
                  <label>Username<br><input name="username" value="demo"></label><br>
                  <label>Password<br><input name="password" type="password"></label><br>
                  <button type="submit">Sign in</button>
                </form>
                <p class="muted">Success credential: <code>demo / demo-pass</code></p>
                </div>
                """
            )

        username = request.form.get("username", "anonymous")
        password = request.form.get("password", "")
        if username == "demo" and password == "demo-pass":
            _write_event(app, _event("login_success", "/login", 200, user_id="demo"))
            return _page("<div class='panel'><span class='status'>login_success</span><p>Authenticated synthetic lab user.</p></div>")

        _write_event(
            app,
            _event(
                "login_failed",
                "/login",
                401,
                label="brute_force",
                user_id=username,
                request_count_1m=12,
                failed_login_count_5m=6,
                status_4xx_count_5m=6,
                avg_request_interval=1.2,
            ),
        )
        return _page("<div class='panel'><span class='status danger'>login_failed</span><p>Failed login event recorded for detection.</p></div>"), 401

    @app.get("/search")
    def search():
        query = request.args.get("q", "quarterly report")
        marker = "SIMULATED_WEB_ATTACK_MARKER" if "SIMULATED_" in query.upper() else "SIMULATED_NONE"
        label = "web_attack" if marker != "SIMULATED_NONE" else "normal"
        status = 400 if label == "web_attack" else 200
        _write_event(
            app,
            _event(
                "search",
                "/search",
                status,
                label=label,
                query=query,
                payload_marker=marker,
                payload_risk_score=0.9 if label == "web_attack" else 0.0,
                status_4xx_count_5m=3 if label == "web_attack" else 0,
            ),
        )
        return _page(
            f"""
            <div class="panel">
              <form method="get">
                <label>Search query<br><input name="q" value="{escape(query)}"></label><br>
                <button type="submit">Run Search</button>
              </form>
              <p><span class="status {'danger' if label == 'web_attack' else ''}">{label}</span></p>
              <p class="muted">Recorded query: <code>{escape(query)}</code></p>
            </div>
            """
        ), status

    @app.get("/profile")
    def profile():
        _write_event(app, _event("page_view", "/profile", 200))
        return _page(
            """
            <div class="grid">
              <div class="panel"><b>User</b><p>lab_user</p><p class="muted">Synthetic identity only.</p></div>
              <div class="panel"><b>Role</b><p>student-analyst</p><p class="muted">No real account data.</p></div>
              <div class="panel"><b>Session</b><span class="status">normal</span><p class="muted">Profile view event recorded.</p></div>
            </div>
            """
        )

    @app.get("/admin")
    def admin():
        if request.headers.get("X-Lab-Admin") == "true":
            _write_event(app, _event("admin_access", "/admin", 200))
            return _page("<div class='panel'><span class='status'>admin_access</span><p>Admin lab page.</p></div>")

        _write_event(
            app,
            _event(
                "admin_access_denied",
                "/admin",
                403,
                label="web_attack",
                status_4xx_count_5m=4,
            ),
        )
        return _page("<div class='panel'><span class='status danger'>admin_access_denied</span><p>Denied admin access event recorded.</p></div>"), 403

    @app.post("/api/events")
    def api_event():
        payload = request.get_json(silent=True) or {}
        _write_event(app, _event("api_request", "/api/events", 200, query=str(payload)[:80]))
        return jsonify({"status": "recorded"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

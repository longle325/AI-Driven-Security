from __future__ import annotations

from datetime import UTC, datetime
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
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #f5f7fb; color: #16202a; }
      main { max-width: 920px; margin: auto; background: white; border: 1px solid #d8dee9; padding: 1.5rem; }
      a { color: #005ea8; margin-right: 1rem; }
      input { padding: .55rem; margin: .25rem 0; width: 18rem; }
      button { padding: .55rem .9rem; background: #0b3d91; color: white; border: 0; }
      code { background: #eef2f7; padding: .15rem .35rem; }
    </style>
  </head>
  <body>
    <main>
      <h1>AI-Driven Cyber Defense Lab</h1>
      <nav>
        <a href="/">Home</a>
        <a href="/login">Login</a>
        <a href="/search">Search</a>
        <a href="/profile">Profile</a>
        <a href="/admin">Admin</a>
      </nav>
      <hr>
      {{ body|safe }}
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
        return _page("<p>Local-only demo application that emits structured security events.</p>")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return _page(
                """
                <form method="post">
                  <label>Username<br><input name="username" value="demo"></label><br>
                  <label>Password<br><input name="password" type="password"></label><br>
                  <button type="submit">Sign in</button>
                </form>
                <p>Demo success credential: <code>demo / demo-pass</code></p>
                """
            )

        username = request.form.get("username", "anonymous")
        password = request.form.get("password", "")
        if username == "demo" and password == "demo-pass":
            _write_event(app, _event("login_success", "/login", 200, user_id="demo"))
            return _page("<p>Login success. This is synthetic lab behavior.</p>")

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
        return _page("<p>Login failed. Event written for defensive detection.</p>"), 401

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
        return _page(f"<p>Search query recorded: <code>{query}</code></p>"), status

    @app.get("/profile")
    def profile():
        _write_event(app, _event("page_view", "/profile", 200))
        return _page("<p>Profile page for a synthetic lab user.</p>")

    @app.get("/admin")
    def admin():
        if request.headers.get("X-Lab-Admin") == "true":
            _write_event(app, _event("admin_access", "/admin", 200))
            return _page("<p>Admin lab page.</p>")

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
        return _page("<p>Admin access denied. Defensive event generated.</p>"), 403

    @app.post("/api/events")
    def api_event():
        payload = request.get_json(silent=True) or {}
        _write_event(app, _event("api_request", "/api/events", 200, query=str(payload)[:80]))
        return jsonify({"status": "recorded"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

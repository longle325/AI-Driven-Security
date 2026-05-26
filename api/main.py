from __future__ import annotations

from fastapi import FastAPI

from api.routes import alerts, detect, health


app = FastAPI(
    title="AI-Driven Cyber Defense Lab API",
    description="Local-only defensive detection API for the AI-SOC lab demo.",
    version="1.0.0",
)

app.include_router(health.router)
app.include_router(detect.router)
app.include_router(alerts.router)

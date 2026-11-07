"""FastAPI application factory. Run with: uvicorn app.main:app --reload"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import Settings, get_settings
from app.db import Database
from app.dataset import store
from app.experiments.runner import ExperimentRunner
from app.llm.registry import ProviderRegistry


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(settings.db_path)
        store.sync_builtin(db, settings.data_dir)
        registry = ProviderRegistry(settings, transport=transport)
        runner = ExperimentRunner(db, registry, settings)
        runner.recover_interrupted()
        app.state.settings, app.state.db, app.state.registry, app.state.runner = settings, db, registry, runner
        yield
        await runner.shutdown()
        db.close()

    app = FastAPI(title="LogJack", version="1.0.0", lifespan=lifespan,
                  description="LLM SOC analysis & prompt-injection resilience testing (isolated simulation).")
    # No cookies/credentials are used, so allow_credentials stays False.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.list_models(settings.cors_origins),
        allow_origin_regex=settings.cors_origin_regex or None,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
        allow_credentials=False,
    )
    app.include_router(router)

    dist = Path(settings.frontend_dist).resolve()
    if settings.serve_frontend and (dist / "index.html").exists():
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                from fastapi import HTTPException
                raise HTTPException(404, "not found")
            target = (dist / path).resolve()
            if path and target.is_file() and dist in target.parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")

    return app


app = create_app()

"""The v1 route table."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import analysis, health, personas

__all__ = ["api_router"]

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(personas.router)
api_router.include_router(analysis.router)

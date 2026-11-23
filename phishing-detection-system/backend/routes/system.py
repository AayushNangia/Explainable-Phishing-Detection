from fastapi import APIRouter

from config import settings
from database.store import get_store
from ml.prediction import load_metrics, registry

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health():
    st = registry.status()
    return {"status": "ok", "storage": get_store().info(), "models": st,
            "demo_mode": not (st["url"]["trained"] and st["email"]["trained"])}


@router.get("/dashboard/stats")
def dashboard_stats():
    return get_store().stats()


@router.get("/models/performance")
def model_performance():
    out = {}
    for t in ("url", "email"):
        m = load_metrics(t)
        out[t] = m if m else {"trained": False, "message": f"No {t} model has been trained. Run: python -m ml.train_{t}_model"}
    return out


@router.get("/settings")
def get_settings():
    return {"storage": get_store().info(), "store_full_input": settings.store_full_input,
            "models": registry.status(), "frontend_origin": settings.frontend_origin,
            "max_url_length": settings.max_url_length, "max_email_chars": settings.max_email_chars}

"""FastAPI entry point:  uvicorn main:app --reload"""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database.store import get_store, metrics_docs
from ml.prediction import registry
from routes import analyze, history, system

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishing")

app = FastAPI(title="Explainable Phishing Detection & Advisory System", version="1.0.0",
              description="Detect → Explain → Advise. Static analysis only: submitted URLs are never fetched.")

origins = [o.strip() for o in settings.frontend_origin.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"])

app.include_router(analyze.router)
app.include_router(history.router)
app.include_router(system.router)


@app.on_event("startup")
def startup():
    store = get_store()
    log.info("Storage: %s", store.info()["label"])
    for t in ("url", "email"):
        registry.load(t)
    try:
        docs = metrics_docs()
        if docs:
            store.save_model_metrics(docs)
    except Exception:
        log.exception("could not sync model metrics")
    st = registry.status()
    if not (st["url"]["trained"] and st["email"]["trained"]):
        log.warning("MODEL NOT TRAINED for: %s — running in DEMO MODE (rules only)",
                    [k for k, v in st.items() if not v["trained"]])

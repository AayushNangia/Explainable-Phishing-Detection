"""Persistence for scans and model metrics.

* MongoDB (PyMongo) when MONGODB_URI is set and reachable  → persistent storage.
* Otherwise a LOCAL FILE MODE (JSON file) — a development fallback. The API reports the active
  mode so the UI can label it; it is never presented as MongoDB.

Privacy: raw e-mail bodies, passwords, OTPs and URL query strings are NOT stored unless
STORE_FULL_INPUT=true. The stored `result` is the analysis output only.
"""
from __future__ import annotations

import copy
import json
import logging
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from config import settings

log = logging.getLogger("phishing.db")
SUMMARY_FIELDS = ["scan_id", "input_type", "input_summary", "classification", "risk_score", "ml_probability", "created_at"]


def _to_record(result: dict, raw_input: dict | None) -> dict:
    stored = copy.deepcopy(result)
    # never persist the message body / highlight text / full URL unless explicitly enabled
    for k in ("highlight_text", "highlights", "display_input"):
        stored.pop(k, None)
    rec = {
        "scan_id": result["scan_id"], "input_type": result["input_type"], "input_summary": result["input_summary"],
        "classification": result["classification"], "risk_score": result["risk_score"],
        "ml_probability": result["ml"]["probability"], "rule_findings": result["rules"]["findings"],
        "explanation_summary": result["explanation_summary"], "advisory": result["advisory"],
        "created_at": result["created_at"], "result": stored,
    }
    if settings.store_full_input and raw_input:
        rec["raw_input"] = raw_input
    return rec


class _Base:
    mode = "local_file"

    def info(self) -> dict:
        return {"mode": self.mode, "persistent": self.mode == "mongodb",
                "label": "MongoDB (persistent)" if self.mode == "mongodb" else "LOCAL FILE MODE (development fallback — not MongoDB)",
                "store_full_input": settings.store_full_input}

    def stats(self) -> dict:
        rows = self._all_summaries()
        urls = [r for r in rows if r["input_type"] == "url"]
        emails = [r for r in rows if r["input_type"] == "email"]
        cnt = lambda rs, c: sum(1 for r in rs if r["classification"] == c)
        dist = Counter(r["classification"] for r in rows)
        days = defaultdict(lambda: {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0})
        today = datetime.now(timezone.utc).date()
        for r in rows:
            d = datetime.fromisoformat(r["created_at"]).date()
            if (today - d).days < 14:
                days[d.isoformat()][r["classification"]] += 1
        activity = [{"date": (today - timedelta(days=i)).isoformat(),
                     **days[(today - timedelta(days=i)).isoformat()]} for i in range(13, -1, -1)]
        recent = sorted(rows, key=lambda r: r["created_at"], reverse=True)[:8]
        return {
            "total_urls": len(urls), "safe_urls": cnt(urls, "SAFE"), "suspicious_urls": cnt(urls, "SUSPICIOUS"),
            "phishing_urls": cnt(urls, "PHISHING"), "total_emails": len(emails),
            "safe_emails": cnt(emails, "SAFE"), "suspicious_emails": cnt(emails, "SUSPICIOUS"), "phishing_emails": cnt(emails, "PHISHING"),
            "risk_distribution": [{"name": c, "value": dist.get(c, 0)} for c in ("SAFE", "SUSPICIOUS", "PHISHING")],
            "activity": activity, "recent": recent, "storage": self.info(),
        }


class LocalStore(_Base):
    mode = "local_file"

    def __init__(self):
        settings.local_store_dir.mkdir(parents=True, exist_ok=True)
        self.path = settings.local_store_dir / "scans.json"
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.write_text("[]")

    def _read(self) -> list[dict]:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            log.exception("corrupt local store; starting empty")
            return []

    def _write(self, rows):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(rows))
        tmp.replace(self.path)

    def insert_scan(self, result, raw_input=None):
        with self._lock:
            rows = self._read()
            rows.append(_to_record(result, raw_input))
            self._write(rows)

    def list_scans(self, classification=None, input_type=None, limit=50, skip=0):
        rows = [r for r in self._read() if (not classification or r["classification"] == classification)
                and (not input_type or r["input_type"] == input_type)]
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        return len(rows), [{k: r.get(k) for k in SUMMARY_FIELDS} for r in rows[skip: skip + limit]]

    def get_scan(self, scan_id):
        return next((r for r in self._read() if r["scan_id"] == scan_id), None)

    def delete_scan(self, scan_id) -> bool:
        with self._lock:
            rows = self._read()
            new = [r for r in rows if r["scan_id"] != scan_id]
            self._write(new)
            return len(new) < len(rows)

    def delete_all(self) -> int:
        with self._lock:
            n = len(self._read())
            self._write([])
            return n

    def _all_summaries(self):
        return [{k: r.get(k) for k in SUMMARY_FIELDS} for r in self._read()]

    def save_model_metrics(self, docs: list[dict]):
        (settings.local_store_dir / "model_metrics.json").write_text(json.dumps(docs, indent=2))


class MongoStore(_Base):
    mode = "mongodb"

    def __init__(self, client):
        self.db = client[settings.mongodb_db]
        self.scans = self.db["scans"]
        self.metrics = self.db["model_metrics"]
        self.scans.create_index("scan_id", unique=True)
        self.scans.create_index([("created_at", -1)])

    def insert_scan(self, result, raw_input=None):
        self.scans.insert_one(_to_record(result, raw_input))

    def list_scans(self, classification=None, input_type=None, limit=50, skip=0):
        q = {}
        if classification:
            q["classification"] = classification
        if input_type:
            q["input_type"] = input_type
        proj = {k: 1 for k in SUMMARY_FIELDS} | {"_id": 0}
        total = self.scans.count_documents(q)
        return total, list(self.scans.find(q, proj).sort("created_at", -1).skip(skip).limit(limit))

    def get_scan(self, scan_id):
        return self.scans.find_one({"scan_id": scan_id}, {"_id": 0})

    def delete_scan(self, scan_id) -> bool:
        return self.scans.delete_one({"scan_id": scan_id}).deleted_count > 0

    def delete_all(self) -> int:
        return self.scans.delete_many({}).deleted_count

    def _all_summaries(self):
        return list(self.scans.find({}, {k: 1 for k in SUMMARY_FIELDS} | {"_id": 0}))

    def save_model_metrics(self, docs):
        for d in docs:
            self.metrics.update_one({"model_name": d["model_name"], "task": d["task"], "evaluation_date": d["evaluation_date"]},
                                    {"$set": d}, upsert=True)


_store: _Base | None = None


def get_store() -> _Base:
    global _store
    if _store is not None:
        return _store
    if settings.mongodb_uri and not settings.force_local_storage:
        try:
            from pymongo import MongoClient
            client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=2500)
            client.admin.command("ping")
            _store = MongoStore(client)
            log.info("Connected to MongoDB database '%s'", settings.mongodb_db)
            return _store
        except Exception as exc:
            log.warning("MongoDB unavailable (%s). Falling back to LOCAL FILE MODE.", exc.__class__.__name__)
    _store = LocalStore()
    return _store


def metrics_docs() -> list[dict]:
    """Flatten the per-model TEST metrics produced by the training scripts into `model_metrics` documents."""
    from ml.prediction import load_metrics
    docs = []
    for task in ("url", "email"):
        m = load_metrics(task)
        if not m:
            continue
        for r in m["models"]:
            t = r["test"]
            docs.append({"task": task, "model_name": r["name"], "dataset_name": m["dataset_name"], "accuracy": t["accuracy"],
                         "precision": t["precision"], "recall": t["recall"], "f1_score": t["f1"], "roc_auc": t["roc_auc"],
                         "evaluation_date": m["evaluation_date"], "split": "test"})
    return docs

from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from database.store import get_store

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def list_history(classification: Literal["SAFE", "SUSPICIOUS", "PHISHING"] | None = None,
                 input_type: Literal["url", "email"] | None = None,
                 limit: int = Query(50, ge=1, le=200), skip: int = Query(0, ge=0)):
    store = get_store()
    total, items = store.list_scans(classification, input_type, limit, skip)
    return {"total": total, "items": items, "storage": store.info()}


@router.get("/{scan_id}")
def get_history(scan_id: str):
    rec = get_store().get_scan(scan_id)
    if not rec:
        raise HTTPException(404, "Scan not found")
    return rec


@router.delete("/{scan_id}")
def delete_history(scan_id: str):
    if not get_store().delete_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}


@router.delete("")
def clear_history():
    return {"deleted_count": get_store().delete_all()}

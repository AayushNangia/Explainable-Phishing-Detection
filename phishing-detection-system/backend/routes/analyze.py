import logging

from fastapi import APIRouter, HTTPException

from database.store import get_store
from ml.url_features import URLValidationError
from schemas import EmailRequest, UrlRequest
from services import hybrid

router = APIRouter(prefix="/api/analyze", tags=["analysis"])
log = logging.getLogger("phishing.api")


def _persist(result: dict, raw: dict) -> None:
    try:
        get_store().insert_scan(result, raw)
        result["saved"] = True
    except Exception:
        log.exception("could not save scan")
        result["saved"] = False


@router.post("/url")
def analyze_url(req: UrlRequest):
    try:
        result = hybrid.analyze_url(req.url)
    except URLValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _persist(result, {"url": result["display_input"]})
    result["storage"] = get_store().info()
    return result


@router.post("/email")
def analyze_email(req: EmailRequest):
    result = hybrid.analyze_email(req.subject, req.body, req.sender)
    _persist(result, {"subject": req.subject, "body": req.body, "sender": req.sender})
    result["storage"] = get_store().info()
    return result

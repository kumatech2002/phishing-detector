"""
routes.py — Flask REST API routes for the phishing detection system.

All endpoints:
    GET  /api/health          — Liveness check
    POST /api/analyze         — Analyse a domain
    GET  /api/history         — Paginated scan history
    GET  /api/history/<id>    — Single scan record
    DELETE /api/history/<id>  — Delete a scan record
    GET  /api/stats           — Dashboard statistics
    GET  /api/model-info      — Model metadata and performance
"""

import logging
from flask import Blueprint, request, jsonify, current_app

log = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _success(data: dict, status: int = 200):
    return jsonify({"ok": True, **data}), status


def _error(message: str, status: int = 400):
    log.warning("API error %d: %s", status, message)
    return jsonify({"ok": False, "error": message}), status


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@api_bp.get("/health")
def health():
    """Liveness + readiness check."""
    from backend.ml.predict import is_model_loaded
    return _success({
        "status": "ok",
        "model_loaded": is_model_loaded(),
    })


@api_bp.post("/analyze")
def analyze():
    """
    Analyse a domain for phishing signals.

    Request body (JSON):
        { "domain": "gtbank-secure-login.com" }

    Response:
        Full prediction result dict.
    """
    body = request.get_json(silent=True)
    if not body:
        return _error("Request body must be JSON with a 'domain' field.")

    domain = body.get("domain", "").strip()

    # Validate
    from backend.ml.predict import validate_domain, predict
    valid, err = validate_domain(domain)
    if not valid:
        return _error(err, 422)

    try:
        result = predict(domain)
    except FileNotFoundError as exc:
        return _error(str(exc), 503)
    except Exception as exc:
        log.exception("Prediction error for domain '%s'", domain)
        return _error("An internal error occurred during analysis.", 500)

    # Persist to history
    try:
        from backend.db.database import save_scan
        scan_id = save_scan(result)
        result["scan_id"] = scan_id
    except Exception:
        log.exception("Failed to save scan to database")
        result["scan_id"] = None

    return _success({"result": result})


@api_bp.get("/history")
def history():
    """Return paginated scan history."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        return _error("Invalid pagination parameters.")

    from backend.db.database import get_history
    data = get_history(page=page, per_page=per_page)
    return _success(data)


@api_bp.get("/history/<int:scan_id>")
def history_item(scan_id: int):
    """Return a single scan record."""
    from backend.db.database import get_scan_by_id
    import json
    record = get_scan_by_id(scan_id)
    if record is None:
        return _error(f"Scan #{scan_id} not found.", 404)
    # Parse features JSON if present
    if record.get("features_json"):
        try:
            record["features"] = json.loads(record.pop("features_json"))
        except Exception:
            record.pop("features_json", None)
    return _success({"record": record})


@api_bp.delete("/history/<int:scan_id>")
def delete_history_item(scan_id: int):
    """Delete a scan record."""
    from backend.db.database import delete_scan
    deleted = delete_scan(scan_id)
    if not deleted:
        return _error(f"Scan #{scan_id} not found.", 404)
    return _success({"deleted": scan_id})


@api_bp.get("/stats")
def stats():
    """Return aggregate dashboard statistics."""
    from backend.db.database import get_stats
    data = get_stats()
    return _success({"stats": data})


@api_bp.get("/model-info")
def model_info():
    """Return model metadata and performance metrics."""
    try:
        from backend.ml.predict import get_model_info
        info = get_model_info()
    except FileNotFoundError as exc:
        return _error(str(exc), 503)
    except Exception:
        log.exception("Failed to load model info")
        return _error("Could not retrieve model information.", 500)
    return _success({"model": info})

"""Backend Flask da plataforma de diagnóstico de risco Piersec."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from analyzer import analyze_workbook
from narrative import enrich_with_narrative
from report import render_executive_report

load_dotenv()

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_DIR / "audit.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("piersec")

app = Flask(__name__, static_folder=str(STATIC), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 80 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_NAME"] = "piersec_session"

ALLOWED_EXT = {".xlsx"}
XLSX_MAGIC = b"PK"
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "analista")
AUTH_PASSWORD_HASH = generate_password_hash(os.environ.get("AUTH_PASSWORD", "piersec-demo"))

_login_fails: dict[str, deque[float]] = defaultdict(deque)
_upload_hits: dict[str, deque[float]] = defaultdict(deque)


def _client_stamp() -> str:
    raw = (request.headers.get("X-Forwarded-For") or request.remote_addr or "0").split(",")[0].strip()
    return hashlib.sha256((app.config["SECRET_KEY"] + "|" + raw).encode()).hexdigest()[:12]


def _audit(event: str, **fields: object) -> None:
    parts = [f"event={event}", f"actor={session.get('uid', '-')}", f"stamp={_client_stamp()}"]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    logger.info(" ".join(parts))


def _rate_ok(bucket: dict[str, deque[float]], limit: int, window_s: float) -> bool:
    now = time.time()
    q = bucket[_client_stamp()]
    while q and now - q[0] > window_s:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def _same_origin() -> bool:
    origin = request.headers.get("Origin") or ""
    referer = request.headers.get("Referer") or ""
    host = request.host_url.rstrip("/")
    if origin:
        return origin.rstrip("/") == host
    if referer:
        return referer.startswith(host)
    return request.method in {"GET", "HEAD", "OPTIONS"}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return jsonify({"error": "Autenticação necessária."}), 401
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _same_origin():
            _audit("csrf_blocked", path=request.path)
            return jsonify({"error": "Origem da requisição rejeitada."}), 403
        return fn(*args, **kwargs)

    return wrapper


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "piersec-risk"})


@app.get("/api/session")
def session_status():
    return jsonify({"authenticated": bool(session.get("uid")), "user": session.get("uid")})


@app.post("/api/login")
def login():
    if not _rate_ok(_login_fails, limit=8, window_s=900):
        _audit("login_rate_limited")
        return jsonify({"error": "Muitas tentativas. Aguarde alguns minutos."}), 429
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    user_ok = hmac.compare_digest(username, AUTH_USERNAME)
    pass_ok = check_password_hash(AUTH_PASSWORD_HASH, password)
    if not (user_ok and pass_ok):
        _audit("login_fail")
        return jsonify({"error": "Credenciais inválidas."}), 401
    session.clear()
    session.permanent = True
    session["uid"] = AUTH_USERNAME
    session["csrf"] = secrets.token_hex(16)
    _audit("login_ok")
    return jsonify({"ok": True, "user": AUTH_USERNAME})


@app.post("/api/logout")
def logout():
    _audit("logout")
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/risk/upload")
@login_required
def upload_risk():
    if not _rate_ok(_upload_hits, limit=6, window_s=600):
        _audit("upload_rate_limited")
        return jsonify({"error": "Limite de análises atingido. Tente mais tarde."}), 429

    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Envie um arquivo .xlsx no campo 'file'."}), 400

    suffix = Path(uploaded.filename).suffix.lower()
    if suffix not in ALLOWED_EXT:
        _audit("upload_reject", reason="ext")
        return jsonify({"error": "Apenas planilhas .xlsx são aceitas."}), 400

    payload = uploaded.read()
    if not payload:
        return jsonify({"error": "Arquivo vazio."}), 400
    if not payload.startswith(XLSX_MAGIC):
        _audit("upload_reject", reason="magic")
        return jsonify({"error": "O arquivo não parece um .xlsx válido."}), 400

    _audit("upload_start", size=len(payload), ext=suffix)

    try:
        result = analyze_workbook(payload, filename="planilha.xlsx")
        result = enrich_with_narrative(result)
        result["analyzedAt"] = datetime.now(timezone.utc).isoformat()
        result["reportHtml"] = render_executive_report(result)
        result.pop("aiContext", None)
    except ImportError:
        logger.exception("dependencia ausente")
        _audit("analyze_fail", reason="import")
        return jsonify({"error": "Dependência ausente para ler .xlsx (openpyxl)."}), 500
    except Exception:
        logger.exception("falha na analise")
        _audit("analyze_fail", reason="parse")
        return jsonify({"error": "Não foi possível processar a planilha. Verifique o formato das abas SIEM/CVE."}), 422

    _audit(
        "analyze_ok",
        score=result.get("finalRiskScore"),
        events=result.get("totalEventsAnalyzed"),
        vulns=result.get("totalVulnerabilitiesFound"),
        sources=",".join(result.get("sources") or []),
        narrative=result.get("narrativeSource"),
    )
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
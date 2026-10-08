"""Backend Flask da plataforma de diagnóstico de risco Piersec."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from analyzer import analyze_workbook

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
ALLOWED_EXT = {".xlsx"}


def _audit(message: str) -> None:
    logger.info(message)


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "piersec-risk"})


@app.post("/api/risk/upload")
def upload_risk():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Envie um arquivo .xlsx no campo 'file'."}), 400

    suffix = Path(uploaded.filename).suffix.lower()
    if suffix not in ALLOWED_EXT:
        return jsonify({"error": "Apenas planilhas .xlsx são aceitas."}), 400

    payload = uploaded.read()
    if not payload:
        return jsonify({"error": "Arquivo vazio."}), 400

    _audit(f"upload size={len(payload)} ext={suffix} sheets_job=start")

    try:
        result = analyze_workbook(payload, filename="planilha.xlsx")
    except Exception:
        logger.exception("falha na analise")
        return jsonify({"error": "Não foi possível processar a planilha. Verifique o formato das abas SIEM/CVE."}), 422

    _audit(
        "analise ok score=%s events=%s vulns=%s sources=%s"
        % (
            result.get("finalRiskScore"),
            result.get("totalEventsAnalyzed"),
            result.get("totalVulnerabilitiesFound"),
            ",".join(result.get("sources") or []),
        )
    )
    result["analyzedAt"] = datetime.now(timezone.utc).isoformat()
    extras = [f"Recomendação: {item}" for item in result.get("recommendations") or []]
    result["justifications"] = list(result.get("justifications") or []) + extras
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

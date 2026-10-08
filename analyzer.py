"""Análise defensiva de planilhas sintéticas do hackathon Piersec.

Converte abas SIEM (CSV em uma coluna) e abas CVE em um score 0-100,
com correlação CIS / MITRE ATT&CK e justificativas em português.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from typing import Any

import pandas as pd

MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
TIMESTAMP_RE = re.compile(
    rf"^({MONTH} \d{{1,2}}, \d{{4}} @ \d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?)[,\s]+(.*)$",
    re.DOTALL,
)

SUSPICIOUS_PATTERNS = (
    (re.compile(r"stop auditd|disable.*audit|checksum changed", re.I), "defesa_prejudicada", 12),
    (re.compile(r"fail(ed|ure)?|falha|denied|blocked|authentication", re.I), "falha_acesso", 3),
    (re.compile(r"privileged command|root;|uid=0", re.I), "privilegio", 8),
    (re.compile(r"brute|password spray|multiple logon", re.I), "forca_bruta", 10),
    (re.compile(r"malware|ransomware|exploit|phishing", re.I), "ameaca", 10),
    (re.compile(r"connection failed", re.I), "conexao_negada", 1),
    (re.compile(r"sshd|ssh", re.I), "acesso_remoto", 2),
)

CIS_MAP = {
    "cve": ("CIS 7", "Gestão contínua de vulnerabilidades"),
    "acesso": ("CIS 6", "Gestão de controle de acesso"),
    "dados": ("CIS 3", "Proteção de dados"),
    "auditoria": ("CIS 8", "Gestão de logs de auditoria"),
    "rede": ("CIS 13", "Monitoramento e defesa de rede"),
}

MITRE_MAP = {
    "defesa_prejudicada": "MITRE T1562 (Impair Defenses)",
    "falha_acesso": "MITRE T1110 / T1078 (Brute Force / Valid Accounts)",
    "privilegio": "MITRE T1548 / T1078 (Privilege Escalation / Valid Accounts)",
    "forca_bruta": "MITRE T1110 (Brute Force)",
    "ameaca": "MITRE T1204 / T1486",
    "conexao_negada": "MITRE T1046 (Network Service Discovery) / bloqueio de tráfego",
    "acesso_remoto": "MITRE T1021 (Remote Services)",
    "cve": "MITRE T1190 / T1203 (Exploit Public-Facing Application / Exploitation for Client Execution)",
}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        text = str(value).strip().strip('"')
        if not text:
            return default
        return int(float(text))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        text = str(value).strip().strip('"')
        if not text:
            return default
        return float(text)
    except (TypeError, ValueError):
        return default


def classify_sheet(name: str) -> str:
    key = name.lower()
    if "cve" in key or "vulnerab" in key:
        return "cve"
    if "fortigate" in key or "firewall" in key:
        return "fortigate"
    if "windows" in key:
        return "windows"
    if key.strip() == "pam" or key.startswith("pam"):
        return "pam"
    if "gworkspace" in key or "google" in key:
        return "gworkspace"
    if "office" in key or "365" in key:
        return "office365"
    return "siem"


def parse_event_row(raw: str, header: list[str]) -> dict[str, str] | None:
    text = str(raw).strip()
    if not text:
        return None
    match = TIMESTAMP_RE.match(text)
    if match:
        timestamp, rest = match.group(1), match.group(2)
        try:
            fields = next(csv.reader(io.StringIO(rest)))
        except csv.Error:
            return None
        keys = header[1:] if header and header[0].lower() == "timestamp" else header
        row = {"timestamp": timestamp}
        for key, value in zip(keys, fields):
            row[key] = value.strip().strip('"')
        return row

    try:
        fields = next(csv.reader(io.StringIO(text)))
    except csv.Error:
        return None
    if len(fields) < 3:
        return None
    return {key: value.strip().strip('"') for key, value in zip(header, fields)}


def _event_from_row(row: dict[str, str], source: str, sheet: str) -> dict[str, Any]:
    description = row.get("rule.description") or row.get("description") or ""
    level = _to_int(row.get("rule.level") or row.get("level"))
    host = (
        row.get("agent.name")
        or row.get("data.srcname")
        or row.get("data.devname")
        or ""
    )
    return {
        "source": source,
        "sheet": sheet,
        "timestamp": row.get("timestamp", ""),
        "host": host,
        "description": description,
        "level": level,
        "rule_id": row.get("rule.id") or row.get("id") or "",
        "user": (
            row.get("data.dstuser")
            or row.get("data.win.eventdata.targetUserName")
            or row.get("data.win.eventdata.subjectUserName")
            or row.get("data.user")
            or row.get("data.office365.MailboxOwnerUPN")
            or row.get("data.office365.UserId")
            or ""
        ),
    }


def load_workbook(file_bytes: bytes) -> dict[str, pd.DataFrame]:
    return pd.read_excel(io.BytesIO(file_bytes), sheet_name=None, engine="openpyxl")


def extract_records(sheets: dict[str, pd.DataFrame]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    vulns: list[dict[str, Any]] = []
    sources: list[str] = []

    for sheet_name, frame in sheets.items():
        kind = classify_sheet(sheet_name)
        sources.append(kind)

        if kind == "cve":
            columns = {str(c).strip().lower(): c for c in frame.columns}
            def col(*names: str) -> str | None:
                for name in names:
                    if name in columns:
                        return columns[name]
                return None

            id_col = col("vulnerability.id", "cve", "id")
            sev_col = col("vulnerability.severity", "severity")
            score_col = col("vulnerability.score.base", "cvss", "score")
            host_col = col("agent.name", "host")
            pkg_col = col("package.name")
            desc_col = col("vulnerability.description", "description")
            os_col = col("host.os.name")

            for _, rec in frame.iterrows():
                vuln_id = str(rec[id_col]).strip() if id_col else ""
                if not vuln_id or vuln_id.lower() == "nan":
                    continue
                vulns.append(
                    {
                        "sheet": sheet_name,
                        "id": vuln_id,
                        "severity": str(rec[sev_col]).strip() if sev_col else "",
                        "score": _to_float(rec[score_col]) if score_col else 0.0,
                        "host": str(rec[host_col]).strip() if host_col else "",
                        "package": str(rec[pkg_col]).strip() if pkg_col else "",
                        "description": str(rec[desc_col]).strip() if desc_col else "",
                        "os": str(rec[os_col]).strip() if os_col else "",
                    }
                )
            continue

        if frame.empty:
            continue
        first_col = str(frame.columns[0])
        header = [part.strip() for part in first_col.split(",")]
        series = frame[frame.columns[0]]
        for raw in series.dropna().astype(str):
            parsed = parse_event_row(raw, header)
            if parsed:
                events.append(_event_from_row(parsed, kind, sheet_name))

    return events, vulns, sorted(set(sources))


def _severity_bucket(value: str, score: float) -> str:
    text = value.lower()
    if "crit" in text or score >= 9.0:
        return "critical"
    if "high" in text or "alta" in text or score >= 7.0:
        return "high"
    if "med" in text or "média" in text or "media" in text or score >= 4.0:
        return "medium"
    if "low" in text or "baixa" in text:
        return "low"
    return "medium"


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Crítico"
    if score >= 60:
        return "Alto"
    if score >= 40:
        return "Moderado"
    if score >= 20:
        return "Baixo"
    return "Mínimo"


def analyze_workbook(file_bytes: bytes, filename: str = "") -> dict[str, Any]:
    sheets = load_workbook(file_bytes)
    events, vulns, sources = extract_records(sheets)

    unique_cves = {item["id"] for item in vulns}
    hosts_vuln = {item["host"] for item in vulns if item["host"] and item["host"].lower() != "nan"}
    sev_counts = Counter(_severity_bucket(item["severity"], item["score"]) for item in vulns)
    unique_by_sev = defaultdict(set)
    hosts_by_sev = defaultdict(set)
    packages = Counter()
    for item in vulns:
        bucket = _severity_bucket(item["severity"], item["score"])
        unique_by_sev[bucket].add(item["id"])
        if item["host"] and item["host"].lower() != "nan":
            hosts_by_sev[bucket].add(item["host"])
        if item.get("package") and item["package"].lower() != "nan":
            packages[item["package"]] += 1

    level_counts = Counter()
    source_counts = Counter()
    desc_counts = Counter()
    flags = Counter()
    high_hosts = set()
    for event in events:
        level_counts[event["level"]] += 1
        source_counts[event["source"]] += 1
        desc = event["description"] or "(sem descrição)"
        desc_counts[desc[:120]] += 1
        if event["level"] >= 8 and event["host"]:
            high_hosts.add(event["host"])
        for pattern, flag, _weight in SUSPICIOUS_PATTERNS:
            if pattern.search(desc):
                flags[flag] += 1

    high_events = sum(count for level, count in level_counts.items() if level >= 8)
    elevated_events = sum(count for level, count in level_counts.items() if level >= 10)
    failed_events = flags["falha_acesso"] + flags["conexao_negada"]

    correlated_hosts = sorted(hosts_by_sev["critical"] & high_hosts)

    n_crit = len(unique_by_sev["critical"])
    n_high = len(unique_by_sev["high"])
    n_med = len(unique_by_sev["medium"])
    n_low = len(unique_by_sev["low"])

    vuln_component = min(
        55.0,
        n_crit * 0.045 + n_high * 0.018 + n_med * 0.006 + n_low * 0.002,
    )
    coverage_hosts = min(12.0, len(hosts_by_sev["critical"]) * 0.08)
    event_ratio = high_events / max(len(events), 1)
    event_component = min(18.0, event_ratio * 90 + min(8.0, elevated_events * 0.4))
    suspicious_component = min(
        12.0,
        flags["defesa_prejudicada"] * 6
        + flags["privilegio"] * 1.5
        + flags["forca_bruta"] * 2
        + flags["ameaca"] * 2
        + min(4.0, failed_events / 4000),
    )
    correlation_component = min(10.0, len(correlated_hosts) * 2.5)
    source_bonus = min(3.0, max(0, len(sources) - 1) * 0.4)

    score = int(round(min(100.0, vuln_component + coverage_hosts + event_component + suspicious_component + correlation_component + source_bonus)))
    if not events and not vulns:
        score = 0

    justifications: list[str] = []
    missing: list[str] = []

    justifications.append(
        f"Fontes padronizadas: {', '.join(sources) or 'nenhuma'}. "
        f"{len(events)} eventos SIEM e {len(vulns)} achados de vulnerabilidade foram normalizados em um modelo comum (RF1/RF2)."
    )

    expected = {"fortigate", "windows", "pam", "cve"}
    present = set(sources)
    if not (present & {"gworkspace", "office365"}):
        missing.append("identidade em nuvem (Google Workspace / Microsoft 365)")
    for item in sorted(expected - present):
        missing.append(item)

    if sev_counts:
        justifications.append(
            f"[{CIS_MAP['cve'][0]} · {CIS_MAP['cve'][1]}] "
            f"{len(unique_cves)} CVE distintas ({n_crit} críticas, {n_high} altas, {n_med} médias) "
            f"em {len(hosts_vuln)} ativos. {MITRE_MAP['cve']}."
        )

    top_packages = ", ".join(f"{name} ({count})" for name, count in packages.most_common(3))
    if top_packages:
        justifications.append(
            f"Pacotes mais afetados: {top_packages}. Priorize atualização nesses componentes para reduzir a superfície de ataque."
        )

    if events:
        top_desc = desc_counts.most_common(3)
        summary = "; ".join(f"{desc} ×{count}" for desc, count in top_desc)
        justifications.append(
            f"[{CIS_MAP['rede'][0]} · {CIS_MAP['acesso'][0]}] "
            f"{len(events)} eventos correlacionados. Nível Wazuh >= 8: {high_events}. "
            f"Principais regras: {summary}."
        )

    if flags["conexao_negada"] or flags["falha_acesso"]:
        justifications.append(
            f"[{CIS_MAP['rede'][0]} · {MITRE_MAP['conexao_negada']}] "
            f"{flags['conexao_negada'] + flags['falha_acesso']} eventos de falha de conexão ou autenticação. "
            f"Pode indicar tentativa de acesso indevido ou política de firewall atuando."
        )

    if flags["defesa_prejudicada"]:
        justifications.append(
            f"[{CIS_MAP['auditoria'][0]} · {MITRE_MAP['defesa_prejudicada']}] "
            f"{flags['defesa_prejudicada']} evidência(s) de desativação de auditoria ou alteração de checksum. "
            f"Isso reduz a capacidade de detecção e deve ser tratado como incidente."
        )

    if flags["privilegio"]:
        justifications.append(
            f"[{CIS_MAP['acesso'][0]} · {MITRE_MAP['privilegio']}] "
            f"{flags['privilegio']} comando(s) privilegiado(s) (ex.: execução como root). "
            f"Validar se a conta de serviço e o horário são esperados."
        )

    if correlated_hosts:
        sample = ", ".join(correlated_hosts[:8])
        extra = "" if len(correlated_hosts) <= 8 else f" (+{len(correlated_hosts) - 8})"
        justifications.append(
            f"[Correlação RF3] {len(correlated_hosts)} ativo(s) com CVE crítica e evento SIEM de alta severidade: {sample}{extra}. "
            f"Combinar falha técnica + atividade anômala eleva o risco operacional."
        )

    cloud_events = source_counts["gworkspace"] + source_counts["office365"]
    if cloud_events:
        justifications.append(
            f"[{CIS_MAP['dados'][0]} · {CIS_MAP['dados'][1]}] "
            f"{cloud_events} eventos de identidade/colaboração em nuvem. "
            f"Revisar tokens, compartilhamentos e caixas de correio com volume atípico (sem expor identificadores pessoais)."
        )

    if missing:
        justifications.append(
            "Limitação (RF7): fontes ou sinais ausentes nesta planilha: " + ", ".join(missing) + "."
        )

    justifications.append(
        f"Score composto 0-100: vulnerabilidades {vuln_component:.1f} + cobertura de ativos {coverage_hosts:.1f} "
        f"+ eventos {event_component:.1f} + comportamentos suspeitos {suspicious_component:.1f} "
        f"+ correlação {correlation_component:.1f}. Classificação: {_risk_level(score)}."
    )

    recommendations = [
        "Aplicar correções nas CVE críticas dos hosts correlacionados antes das demais.",
        "Investigar comandos privilegiados e qualquer parada do serviço de auditoria.",
        "Revisar regras de firewall e falhas repetidas de autenticação por origem.",
        "Gerar o relatório executivo (impressão/PDF) e validar totais contra as abas de origem.",
    ]

    return {
        "finalRiskScore": score,
        "riskLevel": _risk_level(score),
        "totalEventsAnalyzed": len(events),
        "totalVulnerabilitiesFound": len(unique_cves) if unique_cves else len(vulns),
        "justifications": justifications,
        "filename": filename,
        "sources": sources,
        "sheetCount": len(sheets),
        "severityBreakdown": {
            "critical": n_crit,
            "high": n_high,
            "medium": n_med,
            "low": n_low,
            "findings": len(vulns),
        },
        "eventBreakdown": {
            "highOrAbove": high_events,
            "level10OrAbove": elevated_events,
            "bySource": dict(source_counts),
        },
        "correlation": {
            "hostsWithCriticalCveAndHighEvent": correlated_hosts[:20],
        },
        "recommendations": recommendations,
        "confidentiality": "Uso interno · dados sintéticos do hackathon · não contém credenciais",
        "consistency": {
            "eventsPlusVulnRows": len(events) + len(vulns),
            "uniqueCves": len(unique_cves),
            "uniqueVulnHosts": len(hosts_vuln),
        },
    }

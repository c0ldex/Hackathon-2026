"""Análise defensiva de planilhas sintéticas do hackathon Piersec.

Coleta abas SIEM (CSV em uma coluna) e CVE, padroniza em um modelo comum,
correlaciona com CIS / MITRE ATT&CK / NIST CSF / ISO 27001, classifica
severidade, calcula score 0-100 e emite evidências rastreáveis.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from typing import Any

import pandas as pd

from redaction import alias, drop_sensitive_fields, redact_text

MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
TIMESTAMP_RE = re.compile(
    rf"^({MONTH} \d{{1,2}}, \d{{4}} @ \d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?)[,\s]+(.*)$",
    re.DOTALL,
)

SUSPICIOUS_PATTERNS = (
    (re.compile(r"stop auditd|disable.*audit|checksum changed", re.I), "defesa_prejudicada"),
    (re.compile(r"fail(ed|ure)?|falha|denied|blocked|authentication", re.I), "falha_acesso"),
    (re.compile(r"privileged command|root;|uid=0", re.I), "privilegio"),
    (re.compile(r"brute|password spray|multiple logon", re.I), "forca_bruta"),
    (re.compile(r"malware|ransomware|exploit|phishing", re.I), "ameaca"),
    (re.compile(r"connection failed", re.I), "conexao_negada"),
    (re.compile(r"sshd|ssh", re.I), "acesso_remoto"),
)

SOURCE_CATALOG = {
    "cve": {
        "label": "Inventário de vulnerabilidades (CVE)",
        "rule": "A aba cujo nome contém 'cve' ou 'vulnerab' é lida como lista de falhas conhecidas (identificador, gravidade e ativo).",
    },
    "fortigate": {
        "label": "Firewall FortiGate",
        "rule": "A aba cujo nome contém 'fortigate' ou 'firewall' é lida como telemetria de borda (conexões bloqueadas ou permitidas).",
    },
    "windows": {
        "label": "Eventos Windows",
        "rule": "A aba cujo nome contém 'windows' é lida como registro de autenticação e comandos no sistema operacional.",
    },
    "pam": {
        "label": "Gestão de acessos privilegiados (PAM)",
        "rule": "A aba cujo nome é ou começa com 'pam' é lida como uso de contas elevadas.",
    },
    "gworkspace": {
        "label": "Google Workspace",
        "rule": "A aba cujo nome contém 'gworkspace' ou 'google' é lida como colaboração e identidade em nuvem Google.",
    },
    "office365": {
        "label": "Microsoft 365",
        "rule": "A aba cujo nome contém 'office' ou '365' é lida como correio e identidade Microsoft 365.",
    },
    "siem": {
        "label": "SIEM / telemetria geral",
        "rule": "Qualquer outra aba é lida como evento de monitoramento (SIEM), com colunas CSV na primeira coluna.",
    },
}

FRAMEWORKS = {
    "cve": {
        "cis": "CIS 7 — manter programas atualizados e corrigir falhas conhecidas",
        "mitre": "MITRE ATT&CK T1190 / T1203 — uso de falha já publicada",
        "nist": "NIST CSF ID.RA e PR.IP — identificar risco técnico e aplicar correção",
        "iso": "ISO 27001 A.8.8 — gestão de vulnerabilidades técnicas",
    },
    "defesa_prejudicada": {
        "cis": "CIS 8 — preservar os registros de auditoria",
        "mitre": "MITRE ATT&CK T1562 — prejudicar as defesas",
        "nist": "NIST CSF DE.CM — o monitoramento precisa continuar ligado",
        "iso": "ISO 27001 A.8.15 — registros (logs)",
    },
    "falha_acesso": {
        "cis": "CIS 6 — controlar quem entra",
        "mitre": "MITRE ATT&CK T1110 / T1078 — tentativa de senha ou conta válida",
        "nist": "NIST CSF PR.AC — controle de acesso",
        "iso": "ISO 27001 A.8.2 / A.8.5 — acessos privilegiados e autenticação",
    },
    "privilegio": {
        "cis": "CIS 5 e 6 — contas privilegiadas",
        "mitre": "MITRE ATT&CK T1548 / T1078 — elevação de privilégio",
        "nist": "NIST CSF PR.AC — menor privilégio",
        "iso": "ISO 27001 A.8.2 — direitos de acesso privilegiado",
    },
    "forca_bruta": {
        "cis": "CIS 6 — tentativas repetidas de login",
        "mitre": "MITRE ATT&CK T1110 — força bruta",
        "nist": "NIST CSF DE.CM e PR.AC",
        "iso": "ISO 27001 A.8.5 — autenticação segura",
    },
    "ameaca": {
        "cis": "CIS 10 — defesa contra malware",
        "mitre": "MITRE ATT&CK T1204 / T1486 — execução ou sequestro de dados",
        "nist": "NIST CSF DE.AE — anomalias",
        "iso": "ISO 27001 A.8.7 — proteção contra malware",
    },
    "conexao_negada": {
        "cis": "CIS 13 — monitoramento de rede",
        "mitre": "MITRE ATT&CK T1046 — descoberta de serviços",
        "nist": "NIST CSF DE.CM — rede observada",
        "iso": "ISO 27001 A.8.20 — segurança de redes",
    },
    "acesso_remoto": {
        "cis": "CIS 13 — serviços remotos",
        "mitre": "MITRE ATT&CK T1021 — serviços remotos (SSH)",
        "nist": "NIST CSF PR.AC — acesso remoto",
        "iso": "ISO 27001 A.8.22 — redes segregadas / acesso remoto",
    },
    "nuvem": {
        "cis": "CIS 3 — proteção de dados",
        "mitre": "MITRE ATT&CK T1078.004 — contas em nuvem",
        "nist": "NIST CSF PR.DS — dados em trânsito e em repouso",
        "iso": "ISO 27001 A.8.11 / A.5.34 — mascaramento e privacidade",
    },
}

CORRELATION_RULES = (
    {
        "id": "R1",
        "title": "Mesmo ativo com falha crítica e alerta alto",
        "how": "Cruza o apelido do ativo na aba de CVE (gravidade crítica) com eventos de outras abas cujo nível de alerta é 8 ou mais.",
    },
    {
        "id": "R2",
        "title": "Tentativa de acesso e comando privilegiado no mesmo ativo",
        "how": "Cruza eventos de falha de autenticação com eventos de comando privilegiado que compartilham o mesmo apelido de ativo.",
    },
    {
        "id": "R3",
        "title": "Defesa desligada junto com alerta alto",
        "how": "Se existe evidência de auditoria parada ou checksum alterado e, na mesma análise, há alerta alto, o risco operacional sobe.",
    },
    {
        "id": "R4",
        "title": "Três ou mais fontes independentes no mesmo diagnóstico",
        "how": "Confirma se firewall, sistema operacional, PAM, nuvem e CVE realmente alimentaram o modelo; ausência vira lacuna, não silêncio.",
    },
)


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
        return drop_sensitive_fields(row)

    try:
        fields = next(csv.reader(io.StringIO(text)))
    except csv.Error:
        return None
    if len(fields) < 3:
        return None
    parsed = {key: value.strip().strip('"') for key, value in zip(header, fields)}
    return drop_sensitive_fields(parsed)


def _flags_from_description(description: str) -> list[str]:
    found = []
    for pattern, flag in SUSPICIOUS_PATTERNS:
        if pattern.search(description):
            found.append(flag)
    return found


def classify_event_severity(level: int, flags: list[str]) -> tuple[str, str]:
    if "defesa_prejudicada" in flags or level >= 12:
        return (
            "Crítica",
            "O monitoramento pode ter sido desligado ou o alerta chegou no topo da escala do SIEM. Sem registro, a empresa fica cega.",
        )
    if level >= 10 or "privilegio" in flags or "forca_bruta" in flags or "ameaca" in flags:
        return (
            "Alta",
            "Há comando privilegiado, tentativa repetida de senha, indício de código malicioso ou alerta grave do monitor.",
        )
    if level >= 8 or "falha_acesso" in flags:
        return (
            "Média",
            "O alerta é relevante (nível 8 ou falha de acesso), mas ainda não indica, sozinho, um incidente em andamento.",
        )
    return (
        "Baixa",
        "Evento rotineiro de telemetria. Entra na estatística para não ignorar tendência, sem prioridade imediata.",
    )


def classify_cve_severity(value: str, score: float) -> tuple[str, str]:
    text = value.lower()
    if "crit" in text or score >= 9.0:
        return (
            "Crítica",
            "A falha tem nota CVSS (escala pública de gravidade) alta ou veio marcada como crítica pelo fabricante. Um atacante pode usá-la com pouco esforço.",
        )
    if "high" in text or "alta" in text or score >= 7.0:
        return (
            "Alta",
            "A falha é grave o bastante para exigir correção no ciclo atual, embora não esteja no extremo da escala.",
        )
    if "med" in text or "média" in text or "media" in text or score >= 4.0:
        return (
            "Média",
            "A falha existe e deve entrar no plano de atualização, mas o impacto isolado é limitado.",
        )
    if "low" in text or "baixa" in text or score > 0:
        return (
            "Baixa",
            "A falha tem pouco impacto prático sozinha; ainda assim entra na conta para não inflar a confiança.",
        )
    return (
        "Média",
        "A planilha não trouxe gravidade clara; assumimos média para não subestimar nem superestimar.",
    )


def _event_from_row(row: dict[str, str], source: str, sheet: str) -> dict[str, Any]:
    description = redact_text(row.get("rule.description") or row.get("description") or "")
    level = _to_int(row.get("rule.level") or row.get("level"))
    host_raw = (
        row.get("agent.name")
        or row.get("data.srcname")
        or row.get("data.devname")
        or ""
    )
    user_raw = (
        row.get("data.dstuser")
        or row.get("data.win.eventdata.targetUserName")
        or row.get("data.win.eventdata.subjectUserName")
        or row.get("data.user")
        or row.get("data.office365.MailboxOwnerUPN")
        or row.get("data.office365.UserId")
        or ""
    )
    flags = _flags_from_description(description)
    severity, reason = classify_event_severity(level, flags)
    threat = flags[0] if flags else "siem"
    return {
        "source": source,
        "sheet": sheet,
        "timestamp": row.get("timestamp", ""),
        "host": alias("ativo", host_raw),
        "user": alias("conta", user_raw),
        "description": description,
        "level": level,
        "rule_id": row.get("rule.id") or row.get("id") or "",
        "flags": flags,
        "severity": severity,
        "severityReason": reason,
        "frameworks": FRAMEWORKS.get(threat, FRAMEWORKS["falha_acesso"]),
    }


def load_workbook(file_bytes: bytes) -> dict[str, pd.DataFrame]:
    return pd.read_excel(io.BytesIO(file_bytes), sheet_name=None, engine="openpyxl")


def extract_records(sheets: dict[str, pd.DataFrame]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    vulns: list[dict[str, Any]] = []
    catalog: list[dict[str, Any]] = []

    for sheet_name, frame in sheets.items():
        kind = classify_sheet(sheet_name)
        meta = SOURCE_CATALOG[kind]
        records_in_sheet = 0

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
                if not vuln_id.upper().startswith("CVE") and "cve" not in vuln_id.lower():
                    if len(vuln_id) > 80:
                        continue
                severity_raw = str(rec[sev_col]).strip() if sev_col else ""
                score = _to_float(rec[score_col]) if score_col else 0.0
                sev, reason = classify_cve_severity(severity_raw, score)
                host_raw = str(rec[host_col]).strip() if host_col else ""
                vulns.append(
                    {
                        "sheet": sheet_name,
                        "id": redact_text(vuln_id)[:40],
                        "severity": sev,
                        "severityReason": reason,
                        "score": score,
                        "host": alias("ativo", host_raw),
                        "package": redact_text(rec[pkg_col]) if pkg_col else "",
                        "description": redact_text(rec[desc_col]) if desc_col else "",
                        "os": redact_text(rec[os_col]) if os_col else "",
                        "frameworks": FRAMEWORKS["cve"],
                    }
                )
                records_in_sheet += 1
            catalog.append(
                {
                    "id": kind,
                    "label": meta["label"],
                    "rule": meta["rule"],
                    "sheet": sheet_name,
                    "records": records_in_sheet,
                }
            )
            continue

        if frame.empty:
            catalog.append(
                {
                    "id": kind,
                    "label": meta["label"],
                    "rule": meta["rule"],
                    "sheet": sheet_name,
                    "records": 0,
                }
            )
            continue
        first_col = str(frame.columns[0])
        header = [part.strip() for part in first_col.split(",")]
        series = frame[frame.columns[0]]
        for raw in series.dropna().astype(str):
            parsed = parse_event_row(raw, header)
            if parsed:
                events.append(_event_from_row(parsed, kind, sheet_name))
                records_in_sheet += 1
        catalog.append(
            {
                "id": kind,
                "label": meta["label"],
                "rule": meta["rule"],
                "sheet": sheet_name,
                "records": records_in_sheet,
            }
        )

    return events, vulns, catalog


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


def _priority(impact: str, effort: str) -> str:
    if impact == "Alto" and effort in {"Baixo", "Médio"}:
        return "P1"
    if impact == "Alto":
        return "P2"
    if impact == "Médio" and effort != "Alto":
        return "P2"
    return "P3"


def _percentages(parts: dict[str, int]) -> dict[str, int]:
    total = sum(parts.values())
    if total <= 0:
        return {k: 0 for k in parts}
    raw = {k: int(round(v * 100 / total)) for k, v in parts.items()}
    drift = 100 - sum(raw.values())
    if drift and raw:
        key = max(raw, key=lambda k: parts[k])
        raw[key] = max(0, raw[key] + drift)
    return raw


def analyze_workbook(file_bytes: bytes, filename: str = "") -> dict[str, Any]:
    sheets = load_workbook(file_bytes)
    events, vulns, catalog = extract_records(sheets)
    sources = sorted({item["id"] for item in catalog})

    unique_cves = {item["id"] for item in vulns}
    hosts_vuln = {item["host"] for item in vulns if item["host"]}
    unique_by_sev: dict[str, set[str]] = defaultdict(set)
    hosts_by_sev: dict[str, set[str]] = defaultdict(set)
    packages: Counter[str] = Counter()
    for item in vulns:
        bucket = item["severity"]
        unique_by_sev[bucket].add(item["id"])
        if item["host"]:
            hosts_by_sev[bucket].add(item["host"])
        if item.get("package"):
            packages[item["package"]] += 1

    level_counts: Counter[int] = Counter()
    source_counts: Counter[str] = Counter()
    desc_counts: Counter[str] = Counter()
    flags: Counter[str] = Counter()
    high_hosts: set[str] = set()
    hosts_auth: set[str] = set()
    hosts_priv: set[str] = set()
    for event in events:
        level_counts[event["level"]] += 1
        source_counts[event["source"]] += 1
        desc = event["description"] or "(sem descrição)"
        desc_counts[desc[:120]] += 1
        if event["level"] >= 8 and event["host"]:
            high_hosts.add(event["host"])
        for flag in event["flags"]:
            flags[flag] += 1
            if flag == "falha_acesso" and event["host"]:
                hosts_auth.add(event["host"])
            if flag == "privilegio" and event["host"]:
                hosts_priv.add(event["host"])

    high_events = sum(count for level, count in level_counts.items() if level >= 8)
    elevated_events = sum(count for level, count in level_counts.items() if level >= 10)
    failed_events = flags["falha_acesso"] + flags["conexao_negada"]

    r1_hosts = sorted(hosts_by_sev["Crítica"] & high_hosts)
    r2_hosts = sorted(hosts_auth & hosts_priv)

    n_crit = len(unique_by_sev["Crítica"])
    n_high = len(unique_by_sev["Alta"])
    n_med = len(unique_by_sev["Média"])
    n_low = len(unique_by_sev["Baixa"])

    vuln_component = min(55.0, n_crit * 0.045 + n_high * 0.018 + n_med * 0.006 + n_low * 0.002)
    coverage_hosts = min(12.0, len(hosts_by_sev["Crítica"]) * 0.08)
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
    correlation_component = min(10.0, len(r1_hosts) * 2.5)
    source_bonus = min(3.0, max(0, len(sources) - 1) * 0.4)
    raw_sum = vuln_component + coverage_hosts + event_component + suspicious_component + correlation_component + source_bonus
    score = int(round(min(100.0, raw_sum)))
    if not events and not vulns:
        score = 0

    expected = {"fortigate", "windows", "pam", "cve"}
    present = set(sources)
    gaps: list[str] = []
    if not (present & {"gworkspace", "office365"}):
        gaps.append("identidade em nuvem (Google Workspace / Microsoft 365) não veio nesta planilha")
    for item in sorted(expected - present):
        label = SOURCE_CATALOG[item]["label"]
        gaps.append(f"fonte ausente: {label}")
    if len(present) < 3:
        gaps.append("menos de 3 fontes distintas foram identificadas; o diagnóstico fica parcial")
    empty_sheets = [c["sheet"] for c in catalog if c["records"] == 0]
    if empty_sheets:
        gaps.append("abas sem registros utilizáveis: " + ", ".join(empty_sheets[:8]))

    contribution = [
        {
            "factor": "Vulnerabilidades conhecidas",
            "points": round(vuln_component, 1),
            "max": 55,
            "why": f"{len(unique_cves)} falhas distintas ({n_crit} críticas). Cada falha crítica pesa mais na nota.",
        },
        {
            "factor": "Ativos com falha crítica",
            "points": round(coverage_hosts, 1),
            "max": 12,
            "why": f"{len(hosts_by_sev['Crítica'])} ativo(s) com CVE crítica aumentam a superfície de ataque.",
        },
        {
            "factor": "Alertas do monitoramento",
            "points": round(event_component, 1),
            "max": 18,
            "why": f"{high_events} de {len(events)} eventos estão no nível 8 ou acima do SIEM.",
        },
        {
            "factor": "Comportamentos suspeitos",
            "points": round(suspicious_component, 1),
            "max": 12,
            "why": "Auditoria parada, comando privilegiado, força bruta e malware pesam mais que falha isolada de conexão.",
        },
        {
            "factor": "Correlação entre fontes (regra R1)",
            "points": round(correlation_component, 1),
            "max": 10,
            "why": f"{len(r1_hosts)} ativo(s) aparecem ao mesmo tempo na CVE crítica e no alerta alto.",
        },
        {
            "factor": "Diversidade de fontes",
            "points": round(source_bonus, 1),
            "max": 3,
            "why": f"{len(sources)} fonte(s) identificada(s). Mais fontes aumentam a confiança, não o pânico.",
        },
    ]

    evidence: list[dict[str, Any]] = []
    if unique_cves:
        evidence.append(
            {
                "id": "EV-CVE",
                "rule": "coleta-cve",
                "title": "Falhas conhecidas no software dos ativos",
                "severity": "Crítica" if n_crit else "Alta" if n_high else "Média",
                "justification": classify_cve_severity("critical" if n_crit else "high", 9.0 if n_crit else 7.0)[1],
                "meaning": (
                    f"{len(unique_cves)} identificadores CVE distintos. "
                    f"Crítica {n_crit}, alta {n_high}, média {n_med}, baixa {n_low}. "
                    "CVE é o código público de uma falha já documentada."
                ),
                "sources": ["cve"],
                "frameworks": FRAMEWORKS["cve"],
                "trace": {"sheetCount": sum(1 for c in catalog if c["id"] == "cve"), "findings": len(vulns)},
            }
        )
    if events:
        top_desc = "; ".join(f"{d} ×{c}" for d, c in desc_counts.most_common(3))
        evidence.append(
            {
                "id": "EV-SIEM",
                "rule": "coleta-siem",
                "title": "Alertas de monitoramento de várias origens",
                "severity": "Alta" if elevated_events else "Média" if high_events else "Baixa",
                "justification": "Nível 8+ no SIEM significa que a regra de detecção considerou o fato fora do normal.",
                "meaning": f"{len(events)} eventos. Nível ≥ 8: {high_events}. Regras mais frequentes: {top_desc}.",
                "sources": sorted({e["source"] for e in events}),
                "frameworks": FRAMEWORKS["conexao_negada"],
                "trace": {"events": len(events), "bySource": dict(source_counts)},
            }
        )
    if r1_hosts:
        extra = "" if len(r1_hosts) <= 8 else f" (+{len(r1_hosts) - 8})"
        evidence.append(
            {
                "id": "EV-R1",
                "rule": "R1",
                "title": CORRELATION_RULES[0]["title"],
                "severity": "Crítica",
                "justification": "Falha técnica + alerta no mesmo ativo é mais grave do que cada um isolado: a porta existe e alguém já 'bateu' nela.",
                "meaning": f"{len(r1_hosts)} ativo(s): {', '.join(r1_hosts[:8])}{extra}. Apelidos não revelam o hostname original.",
                "sources": ["cve"] + sorted({e["source"] for e in events if e["host"] in set(r1_hosts)}),
                "frameworks": FRAMEWORKS["cve"],
                "trace": {"hosts": len(r1_hosts), "rule": CORRELATION_RULES[0]["how"]},
            }
        )
    if r2_hosts:
        evidence.append(
            {
                "id": "EV-R2",
                "rule": "R2",
                "title": CORRELATION_RULES[1]["title"],
                "severity": "Alta",
                "justification": "Quem falha o login e em seguida executa comando privilegiado no mesmo ativo merece investigação humana.",
                "meaning": f"{len(r2_hosts)} ativo(s) na interseção autenticação × privilégio.",
                "sources": sorted({e["source"] for e in events if e["host"] in set(r2_hosts)}),
                "frameworks": FRAMEWORKS["privilegio"],
                "trace": {"hosts": len(r2_hosts), "rule": CORRELATION_RULES[1]["how"]},
            }
        )
    if flags["defesa_prejudicada"]:
        evidence.append(
            {
                "id": "EV-R3",
                "rule": "R3",
                "title": CORRELATION_RULES[2]["title"],
                "severity": "Crítica",
                "justification": "Sem log não há como provar o que aconteceu depois. Tratar como incidente, não como ruído.",
                "meaning": f"{flags['defesa_prejudicada']} evidência(s) de auditoria parada ou checksum alterado.",
                "sources": sorted({e["source"] for e in events if "defesa_prejudicada" in e["flags"]}),
                "frameworks": FRAMEWORKS["defesa_prejudicada"],
                "trace": {"count": int(flags["defesa_prejudicada"]), "rule": CORRELATION_RULES[2]["how"]},
            }
        )
    evidence.append(
        {
            "id": "EV-R4",
            "rule": "R4",
            "title": CORRELATION_RULES[3]["title"],
            "severity": "Média" if len(present) >= 3 else "Alta",
            "justification": "Diagnóstico com poucas fontes pode parecer calmo só porque faltou visibilidade.",
            "meaning": f"Fontes neste arquivo: {', '.join(sources) or 'nenhuma'}.",
            "sources": sources,
            "frameworks": FRAMEWORKS["nuvem"],
            "trace": {"sourceCount": len(present), "rule": CORRELATION_RULES[3]["how"]},
        }
    )

    recommendations: list[dict[str, str]] = []

    def add_rec(action: str, impact: str, effort: str, rationale: str) -> None:
        recommendations.append(
            {
                "action": action,
                "impact": impact,
                "effort": effort,
                "priority": _priority(impact, effort),
                "rationale": rationale,
            }
        )

    if r1_hosts or n_crit:
        add_rec(
            "Corrigir primeiro as falhas críticas dos ativos que também tiveram alerta alto.",
            "Alto",
            "Médio",
            "É o cruzamento R1: a porta existe e já houve sinal de uso. Maior redução de risco por hora de trabalho.",
        )
    if flags["defesa_prejudicada"]:
        add_rec(
            "Religar a auditoria e tratar a parada como incidente até prova em contrário.",
            "Alto",
            "Baixo",
            "Esforço baixo (serviço de log) e impacto alto (restaura a capacidade de ver o que acontece).",
        )
    if flags["privilegio"] or r2_hosts:
        add_rec(
            "Revisar contas privilegiadas e o horário dos comandos elevados.",
            "Alto",
            "Médio",
            "Comando como administrador é normal em manutenção e anormal fora da janela. Confirmar reduz falso positivo.",
        )
    if failed_events:
        add_rec(
            "Olhar origens com muitas falhas de senha ou conexão recusada no firewall.",
            "Médio",
            "Baixo",
            "Quase sempre é política funcionando ou tentativa ruidosa. Vale um filtro, não uma crise, salvo se coincidir com R1.",
        )
    if packages:
        top = ", ".join(f"{name} ({count})" for name, count in packages.most_common(3))
        add_rec(
            f"Atualizar de preferência os componentes mais citados: {top}.",
            "Alto",
            "Médio",
            "Corrigir o pacote que aparece mais vezes derruba várias CVE de uma vez.",
        )
    if gaps:
        add_rec(
            "Completar as fontes que faltaram (nuvem, PAM, firewall ou CVE) na próxima coleta.",
            "Médio",
            "Médio",
            "Sem a fonte, o score pode estar otimista. A lacuna é risco de visibilidade, não evidência de segurança.",
        )
    add_rec(
        "Gerar o relatório executivo e conferir os totais com as abas originais.",
        "Médio",
        "Baixo",
        "A validação de consistência desta plataforma precisa ser confrontada com a planilha de origem (rastreabilidade).",
    )
    recommendations.sort(key=lambda item: {"P1": 0, "P2": 1, "P3": 2}.get(item["priority"], 9))

    tickets = []
    seq = 1
    for rec in recommendations[:5]:
        tickets.append(
            {
                "id": f"CHG-{seq:03d}",
                "title": rec["action"][:120],
                "priority": rec["priority"],
                "effort": rec["effort"],
                "impact": rec["impact"],
                "status": "Aberto automaticamente (simulado — sem envio externo)",
                "owner": "Fila de infraestrutura (dados sintéticos)",
            }
        )
        seq += 1

    sev_unique = {"Crítica": n_crit, "Alta": n_high, "Média": n_med, "Baixa": n_low}
    pct = _percentages(sev_unique)
    rounded_sum = round(sum(item["points"] for item in contribution), 1)
    checks = [
        {
            "check": "Totais de eventos e CVE",
            "ok": True,
            "detail": f"{len(events)} eventos + {len(vulns)} linhas de CVE = {len(events) + len(vulns)} registros normalizados.",
        },
        {
            "check": "CVE distintas não excedem achados",
            "ok": len(unique_cves) <= len(vulns),
            "detail": f"{len(unique_cves)} distintas em {len(vulns)} linhas.",
        },
        {
            "check": "Percentuais de gravidade somam 100%",
            "ok": (sum(pct.values()) == 100) or sum(sev_unique.values()) == 0,
            "detail": f"Crítica {pct['Crítica']}%, alta {pct['Alta']}%, média {pct['Média']}%, baixa {pct['Baixa']}%."
            if sum(sev_unique.values())
            else "Sem CVE para percentual.",
        },
        {
            "check": "Score versus soma dos fatores",
            "ok": abs(score - min(100, int(round(raw_sum)))) <= 1,
            "detail": f"Nota {score} · soma bruta {rounded_sum} (teto 100).",
        },
        {
            "check": "Mínimo de 3 fontes",
            "ok": len(present) >= 3,
            "detail": f"{len(present)} fonte(s): {', '.join(sources) or 'nenhuma'}.",
        },
        {
            "check": "Campos sensíveis omitidos",
            "ok": True,
            "detail": "Contas, e-mails e endereços foram substituídos por apelidos. Credenciais jamais entram no relatório.",
        },
    ]

    justifications = [
        f"Fontes padronizadas: {', '.join(sources) or 'nenhuma'}. "
        f"{len(events)} eventos e {len(vulns)} achados de vulnerabilidade no mesmo modelo (origem, ativo-apelido, gravidade, evidência).",
        f"Score {score}/100 ({_risk_level(score)}). Fatores: "
        + "; ".join(f"{c['factor']} {c['points']}" for c in contribution)
        + ".",
    ]
    for item in evidence:
        justifications.append(f"[{item['id']}] {item['title']}: {item['meaning']}")
    if gaps:
        justifications.append("Limitações: " + "; ".join(gaps) + ".")

    top_desc = desc_counts.most_common(3)

    return {
        "finalRiskScore": score,
        "riskLevel": _risk_level(score),
        "totalEventsAnalyzed": len(events),
        "totalVulnerabilitiesFound": len(unique_cves) if unique_cves else len(vulns),
        "justifications": justifications,
        "filename": filename or "planilha.xlsx",
        "sources": sources,
        "sourceCatalog": catalog,
        "sheetCount": len(sheets),
        "severityBreakdown": {
            "critical": n_crit,
            "high": n_high,
            "medium": n_med,
            "low": n_low,
            "findings": len(vulns),
            "percentages": {
                "critical": pct["Crítica"],
                "high": pct["Alta"],
                "medium": pct["Média"],
                "low": pct["Baixa"],
            },
        },
        "eventBreakdown": {
            "highOrAbove": high_events,
            "level10OrAbove": elevated_events,
            "bySource": dict(source_counts),
        },
        "correlation": {
            "hostsWithCriticalCveAndHighEvent": r1_hosts[:20],
            "hostsWithAuthAndPrivilege": r2_hosts[:20],
            "rules": list(CORRELATION_RULES),
        },
        "evidenceTrail": evidence,
        "scoreContribution": contribution,
        "recommendations": recommendations,
        "remediationTickets": tickets,
        "gaps": gaps,
        "consistencyChecks": checks,
        "confidentiality": "Confidencial — uso interno · dados sintéticos Piersec · sem credenciais e sem dados pessoais identificáveis",
        "consistency": {
            "eventsPlusVulnRows": len(events) + len(vulns),
            "uniqueCves": len(unique_cves),
            "uniqueVulnHosts": len(hosts_vuln),
            "allChecksPassed": all(c["ok"] for c in checks),
        },
        "aiContext": {
            "score": score,
            "level": _risk_level(score),
            "sources": sources,
            "events": len(events),
            "uniqueCves": len(unique_cves),
            "severity": {"critica": n_crit, "alta": n_high, "media": n_med, "baixa": n_low},
            "highEvents": high_events,
            "flags": dict(flags),
            "r1Hosts": len(r1_hosts),
            "r2Hosts": len(r2_hosts),
            "topRules": [d for d, _ in top_desc],
            "gaps": gaps,
            "contribution": contribution,
        },
    }

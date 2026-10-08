"""Relatório executivo HTML gerado no servidor a partir da análise."""

from __future__ import annotations

import html
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_executive_report(result: dict[str, Any]) -> str:
    summary = result.get("executiveSummary") or {}
    score = result.get("finalRiskScore", 0)
    level = result.get("riskLevel", "—")
    events = result.get("totalEventsAnalyzed", 0)
    vulns = result.get("totalVulnerabilitiesFound", 0)
    contrib = result.get("scoreContribution") or []
    evidence = result.get("evidenceTrail") or []
    recs = result.get("recommendations") or []
    gaps = result.get("gaps") or []
    checks = result.get("consistencyChecks") or []
    tickets = result.get("remediationTickets") or []
    sources = result.get("sourceCatalog") or []
    confidentiality = result.get("confidentiality") or "Uso interno"

    contrib_rows = "".join(
        f"<tr><td>{_esc(item.get('factor'))}</td><td>{_esc(item.get('points'))}</td>"
        f"<td>{_esc(item.get('max'))}</td><td>{_esc(item.get('why'))}</td></tr>"
        for item in contrib
    )
    evidence_rows = "".join(
        f"<article class='card'><h3>{_esc(item.get('id'))} · {_esc(item.get('title'))}</h3>"
        f"<p><strong>Severidade:</strong> {_esc(item.get('severity'))} — {_esc(item.get('justification'))}</p>"
        f"<p>{_esc(item.get('meaning'))}</p>"
        f"<p class='meta'>Fontes: {_esc(', '.join(item.get('sources') or []))} · "
        f"Regra {_esc(item.get('rule'))} · CIS {_esc((item.get('frameworks') or {}).get('cis'))} · "
        f"MITRE {_esc((item.get('frameworks') or {}).get('mitre'))} · "
        f"NIST {_esc((item.get('frameworks') or {}).get('nist'))} · "
        f"ISO {_esc((item.get('frameworks') or {}).get('iso'))}</p></article>"
        for item in evidence
    )
    rec_rows = "".join(
        f"<tr><td>{_esc(item.get('priority') if isinstance(item, dict) else '')}</td>"
        f"<td>{_esc(item.get('action') if isinstance(item, dict) else item)}</td>"
        f"<td>{_esc(item.get('impact') if isinstance(item, dict) else '')}</td>"
        f"<td>{_esc(item.get('effort') if isinstance(item, dict) else '')}</td>"
        f"<td>{_esc(item.get('rationale') if isinstance(item, dict) else '')}</td></tr>"
        for item in recs
    )
    ticket_rows = "".join(
        f"<tr><td>{_esc(t.get('id'))}</td><td>{_esc(t.get('title'))}</td>"
        f"<td>{_esc(t.get('priority'))}</td><td>{_esc(t.get('status'))}</td></tr>"
        for t in tickets
    )
    gap_items = "".join(f"<li>{_esc(g)}</li>" for g in gaps) or "<li>Nenhuma lacuna estrutural detectada.</li>"
    check_items = "".join(
        f"<li>{'OK' if c.get('ok') else 'Atenção'}: {_esc(c.get('check'))} — {_esc(c.get('detail'))}</li>"
        for c in checks
    )
    source_items = "".join(
        f"<li><strong>{_esc(s.get('id'))}</strong> ({_esc(s.get('label'))}): {_esc(s.get('rule'))} "
        f"— {_esc(s.get('records'))} registros na aba {_esc(s.get('sheet'))}.</li>"
        for s in sources
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"/>
<title>Relatório executivo de risco — PierSec</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;color:#1f2937;background:#f4f6f8;margin:0;padding:32px}}
h1,h2{{color:#0f172a}}
.kpi{{display:flex;gap:12px;flex-wrap:wrap}}
.kpi div{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;min-width:140px}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px;margin:10px 0}}
table{{width:100%;border-collapse:collapse;background:#fff}}
th,td{{border:1px solid #e5e7eb;padding:8px;font-size:13px;text-align:left;vertical-align:top}}
.meta{{font-size:12px;color:#6b7280}}
.banner{{border-left:4px solid #00AEEF;padding:8px 12px;background:#e0f4fc}}
</style></head><body>
<p class="banner">{_esc(confidentiality)}</p>
<h1>Relatório executivo de risco</h1>
<p class="meta">Gerado automaticamente pela plataforma · {_esc(result.get("analyzedAt"))} · {_esc(result.get("filename"))}</p>
<div class="kpi">
  <div><strong>Score</strong><br>{_esc(score)}/100<br>{_esc(level)}</div>
  <div><strong>Eventos</strong><br>{_esc(events)}</div>
  <div><strong>Vulnerabilidades</strong><br>{_esc(vulns)}</div>
  <div><strong>Narrativa</strong><br>{_esc(result.get("narrativeSource"))}</div>
</div>
<h2>Como estamos</h2><p>{_esc(summary.get("situation"))}</p>
<h2>O que é mais grave</h2><p>{_esc(summary.get("worst"))}</p>
<h2>O que fazemos agora</h2><p>{_esc(summary.get("nextStep"))}</p>
<h2>Resumo</h2><p>{_esc(summary.get("narrative"))}</p>
<h2>Fontes coletadas (rastreáveis)</h2><ul>{source_items}</ul>
<h2>Contribuição do score</h2>
<table><thead><tr><th>Fator</th><th>Pontos</th><th>Teto</th><th>Por quê</th></tr></thead><tbody>{contrib_rows}</tbody></table>
<h2>Trilha de evidências e correlações</h2>{evidence_rows}
<h2>Plano de remediação (prioridade × esforço)</h2>
<table><thead><tr><th>Pri.</th><th>Ação</th><th>Impacto</th><th>Esforço</th><th>Por quê</th></tr></thead><tbody>{rec_rows}</tbody></table>
<h2>Chamados técnicos abertos automaticamente (simulado)</h2>
<table><thead><tr><th>ID</th><th>Título</th><th>Prioridade</th><th>Status</th></tr></thead><tbody>{ticket_rows}</tbody></table>
<h2>Lacunas e limitações</h2><ul>{gap_items}</ul>
<h2>Validação de consistência</h2><ul>{check_items}</ul>
<p class="meta">Este relatório não contém credenciais nem dados pessoais identificáveis. Hosts e contas foram substituídos por apelidos irreversíveis.</p>
</body></html>"""

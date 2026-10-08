"""Textos executivos via OpenAI, só com agregados já anonimizados."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger("piersec")

SYSTEM_PROMPT = """Você é analista sênior de cibersegurança escrevendo para diretoria.
Responda SOMENTE JSON válido, em português do Brasil.
Regras:
- Explique termos técnicos entre parênteses na primeira menção.
- Não invente números; use apenas o contexto recebido.
- Não inclua senhas, tokens, chaves, e-mails, IPs ou nomes de pessoas.
- Não descreva como explorar falhas; fale só do impacto de negócio e da correção.
- Dados são sintéticos de laboratório.
Campos obrigatórios:
{
  "situation": "como estamos, 2-4 frases",
  "worst": "o que é mais grave, 1-3 frases",
  "nextStep": "o que fazemos agora, 1-3 frases",
  "narrative": "resumo executivo contínuo, até 900 caracteres",
  "findings": [{"title": "", "meaning": "", "severity": "Crítica|Alta|Média|Baixa", "justification": ""}],
  "recommendations": [{"action": "", "impact": "Alto|Médio|Baixo", "effort": "Alto|Médio|Baixo", "priority": "P1|P2|P3", "rationale": ""}]
}
Máximo 6 findings e 6 recommendations, priorizadas por impacto e esforço.
"""


def _fallback(result: dict[str, Any]) -> dict[str, Any]:
    level = result.get("riskLevel") or "Indefinido"
    score = result.get("finalRiskScore") or 0
    gaps = result.get("gaps") or []
    corr = result.get("correlation") or {}
    hosts = corr.get("hostsWithCriticalCveAndHighEvent") or []
    drafts = result.get("recommendations") or []
    findings = []
    for item in (result.get("evidenceTrail") or [])[:6]:
        findings.append(
            {
                "title": item.get("title") or "Evidência",
                "meaning": item.get("meaning") or item.get("justification") or "",
                "severity": item.get("severity") or "Média",
                "justification": item.get("justification") or "",
            }
        )
    return {
        "situation": (
            f"O ambiente sintético analisado está classificado como {level} "
            f"(nota {score} de 100). A nota junta falhas técnicas conhecidas, "
            f"alertas de monitoramento e a sobreposição desses sinais no mesmo ativo."
        ),
        "worst": (
            f"O ponto mais grave é a combinação de falha crítica e alerta alto "
            f"no mesmo ativo ({len(hosts)} ocorrência(s)). Isso aumenta a chance "
            f"de um incidente sair do monitoramento e afetar a operação."
            if hosts
            else "Não houve sobreposição clara de falha crítica com alerta alto; o risco vem do volume isolado de achados."
        ),
        "nextStep": (
            "Tratar primeiro os ativos em que a falha técnica e o alerta coincidem, "
            "depois senhas privilegiadas e falhas repetidas de acesso, e por fim "
            "completar as fontes que faltaram nesta planilha."
            + (f" Lacunas: {', '.join(gaps)}." if gaps else "")
        ),
        "narrative": (
            f"Estamos em nível {level} ({score}/100). O mais urgente é reduzir "
            f"a exposição nos ativos correlacionados e fechar as lacunas de visibilidade."
        ),
        "findings": findings,
        "recommendations": drafts,
        "narrativeSource": "regras-locais",
    }


def enrich_with_narrative(result: dict[str, Any]) -> dict[str, Any]:
    context = result.get("aiContext") or {}
    payload = _fallback(result)
    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        result["executiveSummary"] = payload
        result["narrativeSource"] = "regras-locais"
        return result

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key, timeout=25.0)
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        completion = client.chat.completions.create(
            model=model,
            temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(context, ensure_ascii=False)[:12000],
                },
            ],
        )
        raw = completion.choices[0].message.content or "{}"
        data = json.loads(raw)
        if data.get("situation"):
            payload["situation"] = str(data["situation"])[:2000]
        if data.get("worst"):
            payload["worst"] = str(data["worst"])[:2000]
        if data.get("nextStep"):
            payload["nextStep"] = str(data["nextStep"])[:2000]
        if data.get("narrative"):
            payload["narrative"] = str(data["narrative"])[:2000]
        if isinstance(data.get("findings"), list) and data["findings"]:
            payload["findings"] = data["findings"][:6]
        if isinstance(data.get("recommendations"), list) and data["recommendations"]:
            merged = []
            for item in data["recommendations"][:6]:
                merged.append(
                    {
                        "action": item.get("action") or "",
                        "impact": item.get("impact") or "Médio",
                        "effort": item.get("effort") or "Médio",
                        "priority": item.get("priority") or "P2",
                        "rationale": item.get("rationale") or "",
                    }
                )
            if merged:
                payload["recommendations"] = merged
                result["recommendations"] = merged
        payload["narrativeSource"] = "openai"
    except Exception:
        logger.exception("narrativa openai indisponivel; usando regras locais")
        payload["narrativeSource"] = "regras-locais"

    result["executiveSummary"] = payload
    result["narrativeSource"] = payload["narrativeSource"]
    if payload.get("findings"):
        result["findingsNarrative"] = payload["findings"]
    return result

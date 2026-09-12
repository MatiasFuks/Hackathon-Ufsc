"""
Renderização do relatório: Markdown e JSON.

Determinismo
------------
Nenhuma saída carrega timestamp, caminho absoluto ou contagem dependente da
ordem de execução. Rodar duas vezes no mesmo repo produz bytes idênticos —
requisito do desafio (pipeline não determinístico é desclassificado).
Se quiser data no relatório, passe `stamp=` explicitamente pelo main.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from models import Category, Confidence, Finding, Severity

# Perguntas do security-questionnaire.md (cliente enterprise, prazo de 30 dias).
# O item 1.1 não está na lista plana do .md — vem da versão em slides do deck.
QUESTIONARIO: dict[str, str] = {
    "Q1": "Protegido contra SQL Injection?",
    "Q2": "Protegido contra XSS?",
    "Q3": "Senhas com hash seguro (bcrypt/PBKDF2/Argon2)?",
    "Q4": "Credenciais e API keys fora do código-fonte?",
    "Q5": "Repositório sem `.env` com valores reais commitado?",
    "Q6": "Modo debug desativado em produção?",
    "Q7": "Sem MD5/SHA-1 para dados sensíveis?",
    "1.1": "Exige autenticação para acessar dados de clientes?",
}

# Seção 2 do deck (SQLi + XSS) exige 100% de conformidade: qualquer "Não"
# bloqueia o contrato de R$ 8.000/mês. Não é "prioridade alta" — é bloqueador.
ITENS_BLOQUEANTES = {"Q1", "Q2"}

SEV_RANK = {Severity.CRITICA: 3, Severity.ALTA: 2, Severity.MEDIA: 1, Severity.BAIXA: 0}
CONF_RANK = {Confidence.ALTA: 2, Confidence.MEDIA: 1, Confidence.BAIXA: 0}


def ordenar(findings: Iterable[Finding]) -> list[Finding]:
    """
    Ordenação provisória, até o `scoring.py` assumir.

    Chave: severidade, depois confiança, depois localização, depois uid. O uid
    no fim garante desempate estável — sem ele, dois achados idênticos em
    severidade poderiam trocar de lugar entre execuções.
    """
    return sorted(
        findings,
        key=lambda f: (-SEV_RANK[f.severity], -CONF_RANK[f.confidence], f.file, f.line, f.uid),
    )


def _itens_do_finding(finding: Finding) -> list[str]:
    """Um achado pode derrubar mais de um item ("Q3,Q7" no caso do MD5)."""
    if not finding.questionnaire_item:
        return []
    return [p.strip() for p in finding.questionnaire_item.split(",") if p.strip()]


def scorecard(findings: Iterable[Finding], itens_cobertos: set[str]) -> list[dict[str, Any]]:
    """
    Situação honesta de cada pergunta do questionário.

    Três estados, e a distinção importa: ausência de achado NÃO é aprovação
    quando nenhum detector cobre a pergunta.

        falha         -> existe achado derrubando o item
        conforme      -> algum detector cobre o item e não achou nada
        sem_cobertura  -> nenhum detector carregado sabe verificar isso
    """
    por_item: dict[str, list[Finding]] = {}
    for f in findings:
        for item in _itens_do_finding(f):
            por_item.setdefault(item, []).append(f)

    linhas = []
    for item, pergunta in QUESTIONARIO.items():
        achados = por_item.get(item, [])
        if achados:
            estado = "falha"
        elif item in itens_cobertos:
            estado = "conforme"
        else:
            estado = "sem_cobertura"
        linhas.append({
            "item": item,
            "pergunta": pergunta,
            "estado": estado,
            "bloqueante": item in ITENS_BLOQUEANTES,
            "achados": len(achados),
            "locais": sorted({f.location for f in achados})[:5],
        })
    return linhas


def resumo(findings: list[Finding]) -> dict[str, Any]:
    por_categoria = {c.value: 0 for c in Category}
    por_severidade = {s.value: 0 for s in Severity}
    por_confianca = {c.value: 0 for c in Confidence}
    for f in findings:
        por_categoria[f.category.value] += 1
        por_severidade[f.severity.value] += 1
        por_confianca[f.confidence.value] += 1
    return {
        "total": len(findings),
        "esforco_total_story_points": round(sum(f.effort_points for f in findings), 1),
        "por_categoria": por_categoria,
        "por_severidade": por_severidade,
        "por_confianca": por_confianca,
    }


def render_json(
    findings: list[Finding],
    repo: dict[str, Any],
    tools: list[dict[str, Any]],
    itens_cobertos: set[str],
    stamp: str | None = None,
) -> str:
    ordenados = ordenar(findings)
    payload = {
        "schema_version": 1,
        "repo": repo,
        "tools": tools,
        "summary": resumo(ordenados),
        "questionnaire": scorecard(ordenados, itens_cobertos),
        "findings": [f.to_dict() for f in ordenados],
    }
    if stamp:
        payload["generated_at"] = stamp
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


_ESTADO_MD = {
    "falha": "❌ **NÃO**",
    "conforme": "✅ sem achado",
    "sem_cobertura": "⚠️ sem cobertura",
}


def render_markdown(
    findings: list[Finding],
    repo: dict[str, Any],
    tools: list[dict[str, Any]],
    itens_cobertos: set[str],
    stamp: str | None = None,
) -> str:
    ordenados = ordenar(findings)
    sumario = resumo(ordenados)
    out: list[str] = []
    add = out.append

    add(f"# Radar de Débitos Técnicos — `{repo['name']}`")
    add("")
    add(f"Linguagens detectadas: {', '.join(repo['languages']) or '—'}  ")
    add(f"Achados: **{sumario['total']}** · "
        f"esforço somado: **{sumario['esforco_total_story_points']} story points** "
        f"(time entrega ~6 SP/semana)")
    if stamp:
        add(f"Gerado em: {stamp}")
    add("")
    add("> Ordenação provisória por severidade e confiança. As colunas "
        "**Impacto**, **Valor** e **Prioridade** exigidas pelo relatório final "
        "são preenchidas pelo `scoring.py` (determinístico) e pelo "
        "enriquecimento de descrição via IA.")
    add("")

    # --- ferramentas --------------------------------------------------------
    add("## Ferramentas executadas")
    add("")
    add("| Ferramenta | Disponível | OK | Achados | Observação |")
    add("|---|:---:|:---:|---:|---|")
    for t in tools:
        nota = "; ".join(t.get("notes") or []) or t.get("error") or "—"
        add(f"| `{t['tool']}` | {'sim' if t['available'] else '**não**'} | "
            f"{'sim' if t['ok'] else 'não'} | {t['findings']} | {nota} |")
    add("")

    # --- questionário -------------------------------------------------------
    add("## Questionário de segurança do cliente enterprise")
    add("")
    add("| # | Pergunta | Situação | Evidência |")
    add("|---|---|:---:|---|")
    for linha in scorecard(ordenados, itens_cobertos):
        marca = "🔒 " if linha["bloqueante"] else ""
        locais = ", ".join(f"`{l}`" for l in linha["locais"]) or "—"
        if linha["achados"] > 5:
            locais += f" (+{linha['achados'] - 5})"
        add(f"| {marca}{linha['item']} | {linha['pergunta']} | "
            f"{_ESTADO_MD[linha['estado']]} | {locais} |")
    add("")
    add("🔒 = item bloqueante: o deck exige 100% de conformidade na seção de "
        "SQLi/XSS. Qualquer \"Não\" impede a assinatura do contrato.")
    add("")
    add("⚠️ *sem cobertura* significa que nenhum detector carregado sabe "
        "verificar a pergunta — **não** que o código está conforme.")
    add("")

    # --- distribuição -------------------------------------------------------
    add("## Distribuição")
    add("")
    add("| Categoria | Achados |   | Severidade | Achados |   | Confiança | Achados |")
    add("|---|---:|---|---|---:|---|---|---:|")
    cats = [(k, v) for k, v in sumario["por_categoria"].items()]
    sevs = [(k, v) for k, v in sumario["por_severidade"].items()]
    confs = [(k, v) for k, v in sumario["por_confianca"].items()]
    for i in range(max(len(cats), len(sevs), len(confs))):
        c = f"{cats[i][0]} | {cats[i][1]}" if i < len(cats) else " | "
        s = f"{sevs[i][0]} | {sevs[i][1]}" if i < len(sevs) else " | "
        f_ = f"{confs[i][0]} | {confs[i][1]}" if i < len(confs) else " | "
        add(f"| {c} |  | {s} |  | {f_} |")
    add("")

    # --- tabela de achados --------------------------------------------------
    add("## Achados")
    add("")
    add("| ID | DT | Categoria | Nome | Local | Sev. | Conf. | SP | CWE |")
    add("|---|---|---|---|---|---|---|---:|---|")
    for f in ordenados:
        add(f"| `{f.uid}` | {f.debt_id or '—'} | {f.category.value} | {f.title} | "
            f"`{f.location}` | {f.severity.value} | {f.confidence.value} | "
            f"{f.effort_points:g} | {('CWE-' + str(f.cwe)) if f.cwe else '—'} |")
    add("")

    # --- detalhe ------------------------------------------------------------
    add("## Detalhe dos achados")
    add("")
    for f in ordenados:
        add(f"### `{f.uid}` — {f.title}")
        add("")
        add(f"- **Local:** `{f.location}`")
        add(f"- **Categoria:** {f.category.value} · **Severidade:** {f.severity.value} "
            f"· **Confiança:** {f.confidence.value} · **Esforço:** {f.effort_points:g} SP")
        add(f"- **Regra:** `{f.rule_id}` (fonte: {f.source})")
        if f.debt_id:
            add(f"- **Débito:** {f.debt_id}")
        if f.questionnaire_item:
            add(f"- **Derruba no questionário:** {f.questionnaire_item}")
        if f.corroborated_by:
            add(f"- **Corroborado por:** {', '.join(f'`{c}`' for c in sorted(f.corroborated_by))}")
        if f.metrics:
            metricas = ", ".join(f"`{k}`={v}" for k, v in sorted(f.metrics.items()) if v != "")
            if metricas:
                add(f"- **Métricas:** {metricas}")
        add("")
        add(f"{f.description}")
        add("")
        if f.evidence:
            add("```")
            add(f.evidence)
            add("```")
            add("")
    return "\n".join(out)

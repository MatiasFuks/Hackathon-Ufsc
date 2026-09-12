"""
Scoring model determinístico do pipeline.

Regra de ouro
-------------
Este módulo NUNCA olha `source`, `language`, `rule_id` ou `metrics` de um
`Finding`. Ele lê apenas o vocabulário normalizado (severity, confidence,
category, questionnaire_item, effort_points e os flags de negócio). É isso que
faz o MESMO scoring rodar idêntico sobre achados de Python e de PHP — o que
viabiliza o bônus.

Determinismo
------------
- Nenhuma dependência de relógio: as pressões de prazo são ENTRADA fixa do
  `ScoringContext`, não calculadas de `datetime.now()`. Calcular da data de
  hoje faria o score mudar a cada dia.
- A ordenação final é (score desc, uid asc): empate nunca depende da ordem em
  que o detector cuspiu o achado.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from models import Category, Confidence, Finding, Severity


class Priority(str, Enum):
    """Prioridade de SAÍDA do scoring — o que o relatório exibe na coluna Prioridade."""
    CRITICA = "Crítica"
    ALTA = "Alta"
    MEDIA = "Média"
    BAIXA = "Baixa"


class Horizon(str, Enum):
    """Em qual janela o débito deve ser atacado (slide s2c do deck)."""
    FURACAO = "Furacão (0–30 dias)"       # desbloqueia contrato/release
    CURTO_PRAZO = "4–8 semanas"            # destrava a próxima feature; prepara a saída do dev
    BACKLOG = "Backlog estruturado"       # roadmap, não sprint de emergência


# Limiares de score -> prioridade. Calibrados contra os 37 achados reais do
# repo-alvo; documentados aqui para que a faixa seja auditável.
PRIORITY_THRESHOLDS: list[tuple[float, Priority]] = [
    (120.0, Priority.CRITICA),
    (70.0, Priority.ALTA),
    (35.0, Priority.MEDIA),
]


def priority_from_score(score: float) -> Priority:
    for minimo, prioridade in PRIORITY_THRESHOLDS:
        if score >= minimo:
            return prioridade
    return Priority.BAIXA


def _questionnaire_items(finding: Finding) -> set[str]:
    """Um achado pode derrubar mais de um item ('Q3,Q7' no caso do MD5)."""
    if not finding.questionnaire_item:
        return set()
    return {p.strip() for p in finding.questionnaire_item.split(",") if p.strip()}


def horizon_for(finding: Finding, priority: Priority, is_blocker: bool) -> Horizon:
    """
    Mapeia o achado num dos 3 horizontes do deck (slide s2c).

    🌀 Furacão: bloqueadores de contrato + críticos baratos (quick wins como
       `debug=True`) — tudo que desbloqueia os 14/30 dias e cabe na janela.
    🔧 4–8 semanas: Alta, críticos caros demais pra janela (precisam de plano) e
       mitigadores da saída do dev (testes/documentação).
    🚀 Backlog: o resto (Média/Baixa, performance, refatoração grande).
    """
    if is_blocker:
        return Horizon.FURACAO
    if priority is Priority.CRITICA:
        return Horizon.FURACAO if finding.effort_points <= 5 else Horizon.CURTO_PRAZO
    if priority is Priority.ALTA or finding.mitigates_bus_factor:
        return Horizon.CURTO_PRAZO
    return Horizon.BACKLOG

# --- severidade-base de entrada -> pontos ----------------------------------
# Slide s9 fixa Crítica=100, Alta=70; Média/Baixa preenchidos com folga
# defensável entre as faixas.
BASE: dict[Severity, float] = {
    Severity.CRITICA: 100.0,
    Severity.ALTA: 70.0,
    Severity.MEDIA: 40.0,
    Severity.BAIXA: 15.0,
}

# --- fator de confiança (defesa anti-falso-positivo) -----------------------
# Achado de baixa confiança AFUNDA no ranking em vez de virar "Crítica" e
# custar ponto. A penalidade de falso positivo do desafio vive aqui.
CONF_FACTOR: dict[Confidence, float] = {
    Confidence.ALTA: 1.0,
    Confidence.MEDIA: 0.8,
    Confidence.BAIXA: 0.5,
}


@dataclass
class ScoringContext:
    """Pressões de negócio da HourTrack — entrada fixa e determinística."""
    days_until_release: int = 14
    days_until_audit: int = 30
    enterprise_deal_active: bool = True
    # Espelha report.ITENS_BLOQUEANTES; um teste garante que não divergem.
    blocking_items: frozenset[str] = frozenset({"Q1", "Q2"})


@dataclass
class ScoredFinding:
    """Um `Finding` com o resultado do scoring acoplado."""
    finding: Finding
    score: float
    priority: Priority
    horizon: Horizon
    breakdown: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Funde os campos do Finding com o resultado do scoring — pronto pro report/JSON."""
        d = self.finding.to_dict()
        d["score"] = self.score
        d["priority"] = self.priority.value
        d["horizon"] = self.horizon.value
        d["score_breakdown"] = self.breakdown
        return d


def score_one(finding: Finding, ctx: ScoringContext) -> ScoredFinding:
    base = BASE[finding.severity]
    score = base
    breakdown = [f"base({finding.severity.value})={base:g}"]

    # segurança + auditoria próxima → dobra (slide s9)
    if finding.category is Category.SEGURANCA and ctx.days_until_audit <= 30:
        score *= 2.0
        breakdown.append(f"×2.0 segurança + auditoria em ≤{ctx.days_until_audit}d")

    # esforço alto durante o crunch da release → penaliza (slide s9).
    # Não é "menos importante": é inviável de fazer na janela de 14 dias,
    # então desce de horizonte em vez de competir com os quick wins.
    if ctx.days_until_release <= 14 and finding.effort_points > 8:
        score *= 0.5
        breakdown.append(
            f"×0.5 esforço {finding.effort_points:g}SP > 8 na janela de release ({ctx.days_until_release}d)")

    # flags de negócio (setados pela camada de detecção). Amplificam achados
    # que o contexto da HourTrack torna mais caros do que a severidade sozinha
    # sugere.
    if finding.publicly_reachable and ctx.enterprise_deal_active:
        score *= 1.5
        breakdown.append("×1.5 alcançável sem auth + deal enterprise em risco")
    if finding.impacts_revenue:
        score *= 1.5
        breakdown.append("×1.5 corrompe faturamento")
    if finding.mitigates_bus_factor:
        score *= 1.25
        breakdown.append("×1.25 mitiga a saída do dev (bus factor)")

    conf = CONF_FACTOR[finding.confidence]
    score *= conf
    breakdown.append(f"×confiança({finding.confidence.value})={conf:g}")

    priority = priority_from_score(score)
    breakdown.append(f"score={score:g} → {priority.value}")

    # Override (B): item da Seção 2 (SQLi/XSS) bloqueia o contrato de R$ 8k/mês —
    # é inegociável. Travamos em Crítica independente do score. A exigência de
    # confiança ALTA evita travar um falso positivo (ex.: o DELETE de
    # everything.py:205, que o detector já rebaixou para confiança Baixa).
    bloqueantes = _questionnaire_items(finding) & ctx.blocking_items
    is_blocker = finding.confidence is Confidence.ALTA and bool(bloqueantes)
    if is_blocker:
        priority = Priority.CRITICA
        breakdown.append(f"override: bloqueador de contrato ({','.join(sorted(bloqueantes))}) → Crítica")

    horizon = horizon_for(finding, priority, is_blocker)
    breakdown.append(f"horizonte: {horizon.value}")

    return ScoredFinding(finding=finding, score=score, priority=priority,
                         horizon=horizon, breakdown=breakdown)


def score_findings(findings: list[Finding], ctx: ScoringContext) -> list[ScoredFinding]:
    """
    Pontua e ordena todos os achados. Ponto de entrada do módulo.

    Ordenação determinística: (score desc, uid asc). O uid no desempate garante
    que dois achados de mesmo score nunca troquem de lugar entre execuções.
    """
    scored = [score_one(f, ctx) for f in findings]
    scored.sort(key=lambda sf: (-sf.score, sf.finding.uid))
    return scored


def build_scoring_payload(findings: list[Finding], ctx: ScoringContext,
                          repo: dict | None = None) -> dict:
    """
    Monta o payload serializável do scoring — o que o `main.py` grava em
    `output/<linguagem>/scoring.json` como etapa do pipeline.

    É o artefato de handoff: quem gera o relatório lê a Prioridade/Horizonte
    daqui (ou importa este módulo), sem o scoring precisar tocar no `report.py`.
    """
    scored = score_findings(findings, ctx)

    por_prioridade = {p.value: 0 for p in Priority}
    por_horizonte = {h.value: 0 for h in Horizon}
    for sf in scored:
        por_prioridade[sf.priority.value] += 1
        por_horizonte[sf.horizon.value] += 1

    return {
        "schema_version": 1,
        "repo": repo or {},
        "scoring_context": {
            "days_until_release": ctx.days_until_release,
            "days_until_audit": ctx.days_until_audit,
            "enterprise_deal_active": ctx.enterprise_deal_active,
            "blocking_items": sorted(ctx.blocking_items),
        },
        "summary": {
            "total": len(scored),
            "por_prioridade": por_prioridade,
            "por_horizonte": por_horizonte,
        },
        "findings": [sf.to_dict() for sf in scored],
    }

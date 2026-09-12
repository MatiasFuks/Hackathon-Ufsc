"""
Testes do scoring model determinístico.

O scoring é o coração da nota (25%) e precisa ser 100% determinístico. Estes
testes cobrem: o cálculo base, os multiplicadores de contexto, a defesa
anti-falso-positivo por confiança, o override de bloqueador de contrato (B),
a derivação de prioridade/horizonte, o determinismo e a invariância de
linguagem (o mesmo scoring roda em Python e PHP).
"""
from __future__ import annotations

from models import Category, Confidence, Finding, Language, Severity
import scoring


def mk(**kw) -> Finding:
    """Factory de Finding com defaults neutros — o teste sobrescreve o que importa."""
    base = dict(
        rule_id="test:RULE",
        source="test",
        language=Language.PYTHON,
        category=Category.MANUTENIBILIDADE,
        title="achado de teste",
        description="",
        file="app/x.py",
        line=1,
        severity=Severity.BAIXA,
        confidence=Confidence.ALTA,
        effort_points=1.0,
    )
    base.update(kw)
    return Finding(**base)


def test_score_base_usa_severidade_sem_multiplicadores():
    """Achado neutro (sem segurança, sem flags, confiança alta) = BASE da severidade."""
    ctx = scoring.ScoringContext()
    sf = scoring.score_one(mk(severity=Severity.BAIXA, confidence=Confidence.ALTA), ctx)

    assert sf.finding.severity is Severity.BAIXA
    assert sf.score == 15.0


def test_confianca_baixa_afunda_o_score():
    """Defesa anti-falso-positivo: confiança Média/Baixa multiplica por <1."""
    ctx = scoring.ScoringContext()
    media = scoring.score_one(mk(severity=Severity.MEDIA, confidence=Confidence.MEDIA), ctx)
    baixa = scoring.score_one(mk(severity=Severity.MEDIA, confidence=Confidence.BAIXA), ctx)

    assert media.score == 40.0 * 0.8   # 32.0
    assert baixa.score == 40.0 * 0.5   # 20.0


def test_seguranca_com_auditoria_proxima_dobra():
    """Achado de segurança + questionário em ≤30 dias → ×2.0 (slide s9)."""
    sec = mk(category=Category.SEGURANCA, severity=Severity.ALTA, confidence=Confidence.ALTA)

    dentro = scoring.score_one(sec, scoring.ScoringContext(days_until_audit=30))
    fora = scoring.score_one(sec, scoring.ScoringContext(days_until_audit=60))

    assert dentro.score == 70.0 * 2.0   # 140.0
    assert fora.score == 70.0           # multiplicador não dispara


def test_multiplicador_seguranca_nao_afeta_outras_categorias():
    """O ×2.0 é só de segurança — um achado de manutenibilidade não pega."""
    manut = mk(category=Category.MANUTENIBILIDADE, severity=Severity.ALTA, confidence=Confidence.ALTA)
    sf = scoring.score_one(manut, scoring.ScoringContext(days_until_audit=30))
    assert sf.score == 70.0


def test_esforco_alto_na_janela_de_release_penaliza():
    """Release em ≤14 dias + esforço > 8 SP → ×0.5 (manda o caro pro próximo horizonte)."""
    caro = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
              confidence=Confidence.ALTA, effort_points=10.0)

    na_janela = scoring.score_one(caro, scoring.ScoringContext(days_until_release=14))
    fora = scoring.score_one(caro, scoring.ScoringContext(days_until_release=30))

    assert na_janela.score == 40.0 * 0.5   # 20.0
    assert fora.score == 40.0              # sem crunch, sem penalidade


def test_esforco_no_limite_nao_penaliza():
    """8 SP não é > 8: a penalidade só dispara acima do limiar."""
    no_limite = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
                   confidence=Confidence.ALTA, effort_points=8.0)
    sf = scoring.score_one(no_limite, scoring.ScoringContext(days_until_release=14))
    assert sf.score == 40.0


def test_publicly_reachable_amplifica_com_deal_enterprise():
    """Alcançável sem auth + deal enterprise ativo → ×1.5 (risco de acesso a dados)."""
    f = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
           confidence=Confidence.ALTA, publicly_reachable=True)
    sf = scoring.score_one(f, scoring.ScoringContext(enterprise_deal_active=True))
    assert sf.score == 40.0 * 1.5   # 60.0


def test_impacts_revenue_e_bus_factor_amplificam():
    """Corromper faturamento → ×1.5; mitigar a saída do dev → ×1.25."""
    receita = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
                 confidence=Confidence.ALTA, impacts_revenue=True)
    bus = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
             confidence=Confidence.ALTA, mitigates_bus_factor=True)

    assert scoring.score_one(receita, scoring.ScoringContext()).score == 40.0 * 1.5   # 60.0
    assert scoring.score_one(bus, scoring.ScoringContext()).score == 40.0 * 1.25      # 50.0


def test_acesso_so_amplifica_se_houver_deal_enterprise():
    """Sem deal enterprise em negociação, o risco de acesso a dados não amplifica."""
    f = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
           confidence=Confidence.ALTA, publicly_reachable=True)
    sf = scoring.score_one(f, scoring.ScoringContext(enterprise_deal_active=False))
    assert sf.score == 40.0


def test_prioridade_derivada_por_faixa_de_score():
    """Score vira Prioridade por limiares fixos: Crítica ≥120 · Alta ≥70 · Média ≥35 · Baixa <35."""
    ctx = scoring.ScoringContext()
    critica = mk(category=Category.SEGURANCA, severity=Severity.ALTA, confidence=Confidence.ALTA)  # 70×2=140
    alta = mk(category=Category.MANUTENIBILIDADE, severity=Severity.ALTA, confidence=Confidence.ALTA)  # 70
    media = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA, confidence=Confidence.ALTA)  # 40
    baixa = mk(category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA, confidence=Confidence.ALTA)  # 15

    assert scoring.score_one(critica, ctx).priority is scoring.Priority.CRITICA
    assert scoring.score_one(alta, ctx).priority is scoring.Priority.ALTA
    assert scoring.score_one(media, ctx).priority is scoring.Priority.MEDIA
    assert scoring.score_one(baixa, ctx).priority is scoring.Priority.BAIXA


def test_override_bloqueador_de_contrato_trava_em_critica():
    """Item bloqueante (Q1/Q2) + confiança ALTA → Crítica, mesmo com score baixo."""
    ctx = scoring.ScoringContext()
    # score base baixo de propósito, pra provar que o override domina
    bloqueante = mk(category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
                    confidence=Confidence.ALTA, questionnaire_item="Q1")
    sf = scoring.score_one(bloqueante, ctx)
    assert sf.priority is scoring.Priority.CRITICA


def test_override_nao_dispara_com_confianca_baixa():
    """Defesa anti-FP: o DELETE de everything.py:205 cai em Q1 mas tem confiança Baixa
    — não pode ser travado em Crítica."""
    ctx = scoring.ScoringContext()
    fp = mk(category=Category.SEGURANCA, severity=Severity.BAIXA,
            confidence=Confidence.BAIXA, questionnaire_item="Q1")
    sf = scoring.score_one(fp, ctx)
    assert sf.priority is not scoring.Priority.CRITICA


def test_override_nao_dispara_em_item_nao_bloqueante():
    """Q3 (hash) não é da Seção 2 — não trava contrato, não força Crítica."""
    ctx = scoring.ScoringContext()
    q3 = mk(category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
            confidence=Confidence.ALTA, questionnaire_item="Q3,Q7")
    sf = scoring.score_one(q3, ctx)
    assert sf.priority is not scoring.Priority.CRITICA


def test_horizonte_furacao_bloqueador_e_quick_win_critico():
    """Furacão (0–30d): bloqueadores de contrato e críticos baratos (ex.: debug=True)."""
    ctx = scoring.ScoringContext()
    bloqueador = mk(category=Category.SEGURANCA, severity=Severity.CRITICA,
                    confidence=Confidence.ALTA, questionnaire_item="Q1", effort_points=3.0)
    quick_win = mk(category=Category.SEGURANCA, severity=Severity.CRITICA,
                   confidence=Confidence.ALTA, questionnaire_item="Q6", effort_points=0.5)  # debug

    assert scoring.score_one(bloqueador, ctx).horizon is scoring.Horizon.FURACAO
    assert scoring.score_one(quick_win, ctx).horizon is scoring.Horizon.FURACAO


def test_horizonte_curto_prazo_critico_caro_alta_e_bus_factor():
    """4–8 semanas: crítico caro demais pro furacão, Alta, e mitigadores da saída do dev."""
    critico_caro = mk(category=Category.SEGURANCA, severity=Severity.CRITICA,
                      confidence=Confidence.ALTA, questionnaire_item="Q6", effort_points=10.0)
    alta = mk(category=Category.MANUTENIBILIDADE, severity=Severity.ALTA, confidence=Confidence.ALTA)
    testes = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
                confidence=Confidence.ALTA, mitigates_bus_factor=True)

    # release longe pra isolar: o crítico caro não pode ser rebaixado pela penalidade de esforço
    ctx = scoring.ScoringContext(days_until_release=60)
    assert scoring.score_one(critico_caro, ctx).horizon is scoring.Horizon.CURTO_PRAZO
    assert scoring.score_one(alta, ctx).horizon is scoring.Horizon.CURTO_PRAZO
    assert scoring.score_one(testes, ctx).horizon is scoring.Horizon.CURTO_PRAZO


def test_horizonte_backlog_para_baixa_prioridade():
    """Backlog: severidade baixa sem amplificador de negócio."""
    ctx = scoring.ScoringContext()
    baixa = mk(category=Category.PERFORMANCE, severity=Severity.BAIXA, confidence=Confidence.ALTA)
    assert scoring.score_one(baixa, ctx).horizon is scoring.Horizon.BACKLOG


def test_score_findings_ordena_por_score_desc():
    """A lista sai ordenada do maior score para o menor."""
    ctx = scoring.ScoringContext()
    alto = mk(category=Category.SEGURANCA, severity=Severity.CRITICA,
              confidence=Confidence.ALTA, questionnaire_item="Q1", file="a.py", line=1)
    medio = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
               confidence=Confidence.ALTA, file="b.py", line=2)
    baixo = mk(category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
               confidence=Confidence.ALTA, file="c.py", line=3)

    resultado = scoring.score_findings([medio, baixo, alto], ctx)
    scores = [sf.score for sf in resultado]
    assert scores == sorted(scores, reverse=True)
    assert resultado[0].finding is alto


def test_empate_de_score_desempata_por_uid():
    """Empate no score é resolvido por uid crescente — estável entre execuções."""
    ctx = scoring.ScoringContext()
    # mesmo score (40), uids diferentes (file/line diferentes)
    f1 = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA, file="z.py", line=9)
    f2 = mk(category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA, file="a.py", line=1)

    resultado = scoring.score_findings([f1, f2], ctx)
    uids = [sf.finding.uid for sf in resultado]
    assert uids == sorted(uids)


def test_determinismo_ordem_independe_da_ordem_de_entrada():
    """Rodar com a entrada embaralhada produz exatamente a mesma saída."""
    ctx = scoring.ScoringContext()
    fs = [
        mk(severity=Severity.MEDIA, file="a.py", line=1),
        mk(category=Category.SEGURANCA, severity=Severity.CRITICA, questionnaire_item="Q1", file="b.py", line=2),
        mk(severity=Severity.BAIXA, file="c.py", line=3),
    ]
    ordem1 = [sf.finding.uid for sf in scoring.score_findings(fs, ctx)]
    ordem2 = [sf.finding.uid for sf in scoring.score_findings(list(reversed(fs)), ctx)]
    assert ordem1 == ordem2


def test_breakdown_registra_as_regras_aplicadas():
    """Cada fator aplicado deixa rastro auditável — é o 'regras justificadas' dos 25%."""
    ctx = scoring.ScoringContext()
    sec = mk(category=Category.SEGURANCA, severity=Severity.ALTA,
             confidence=Confidence.ALTA, questionnaire_item="Q1")
    sf = scoring.score_one(sec, ctx)

    texto = " | ".join(sf.breakdown).lower()
    assert "70" in texto                               # base da severidade Alta
    assert "2.0" in texto or "2x" in texto             # multiplicador de segurança
    assert any("override" in b.lower() for b in sf.breakdown)   # bloqueador registrado


def test_to_dict_une_finding_e_resultado_do_scoring():
    """A saída serializável carrega score/priority/horizon + os campos do Finding."""
    ctx = scoring.ScoringContext()
    sf = scoring.score_one(mk(), ctx)
    d = sf.to_dict()

    assert d["score"] == sf.score
    assert d["priority"] == sf.priority.value
    assert d["horizon"] == sf.horizon.value
    assert d["score_breakdown"] == sf.breakdown
    assert d["uid"] == sf.finding.uid          # campos do Finding preservados


def test_scoring_independe_da_linguagem():
    """INVARIANTE DO BÔNUS: dois achados normalizados iguais pontuam igual, seja PHP ou Python."""
    ctx = scoring.ScoringContext()
    comum = dict(category=Category.SEGURANCA, severity=Severity.CRITICA,
                 confidence=Confidence.ALTA, questionnaire_item="Q1", effort_points=3.0)
    py = scoring.score_one(mk(language=Language.PYTHON, **comum), ctx)
    php = scoring.score_one(mk(language=Language.PHP, **comum), ctx)

    assert (py.score, py.priority, py.horizon) == (php.score, php.priority, php.horizon)


def test_conjunto_bloqueante_nao_diverge_do_report():
    """GUARDA: a lista de itens bloqueantes do scoring tem que bater com a do report."""
    import report
    assert scoring.ScoringContext().blocking_items == report.ITENS_BLOQUEANTES

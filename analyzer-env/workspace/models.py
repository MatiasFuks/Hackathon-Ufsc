"""
Contrato normalizado do pipeline: `Finding`.

Regra arquitetural central
--------------------------
O `scoring.py` NUNCA olha `source` nem `language` para decidir prioridade.
Ele lê apenas campos normalizados (severity, confidence, category, flags de
negócio, effort_points). É isso que permite que o mesmo scoring model rode
sobre achados de bandit, radon, pylint, phpmetrics ou dos detectores próprios,
em Python ou PHP, sem saber de onde vieram.

Determinismo
------------
- `uid` é hash de (rule_id, file, line) — estável entre execuções.
- Nenhum campo carrega timestamp, caminho absoluto ou ordem de descoberta.
- A ordenação final é (score desc, uid asc): empate nunca depende da ordem
  em que a ferramenta cuspiu o resultado.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    """Categorias exigidas pelo relatório (cenario-do-desafio.md)."""
    SEGURANCA = "Segurança"
    DESIGN = "Design"
    MANUTENIBILIDADE = "Manutenibilidade"
    PERFORMANCE = "Performance"
    ARQUITETURA = "Arquitetura"


class Severity(str, Enum):
    """Severidade-base de ENTRADA do scoring — não é a prioridade de saída."""
    CRITICA = "Crítica"
    ALTA = "Alta"
    MEDIA = "Média"
    BAIXA = "Baixa"


class Confidence(str, Enum):
    """
    Quão certo estamos de que o achado é real.

    Existe por causa da penalidade de falso positivo do desafio: achado
    sintático sem corroboração entra como MEDIA/BAIXA e afunda no scoring,
    em vez de virar "Crítica" e custar ponto.
    """
    ALTA = "Alta"
    MEDIA = "Média"
    BAIXA = "Baixa"


class Language(str, Enum):
    PYTHON = "python"
    PHP = "php"
    AGNOSTIC = "agnostic"   # achados de repo (ex.: ausência de testes)


@dataclass
class Finding:
    """Um débito técnico localizado. Unidade única que trafega no pipeline."""

    # --- identidade e origem -------------------------------------------------
    rule_id: str                    # "bandit:B324", "builtin:PY-XSS-FSTRING"
    source: str                     # "bandit" | "radon" | "builtin" | ...
    language: Language

    # --- o que é -------------------------------------------------------------
    category: Category
    title: str
    description: str

    # --- onde está (evidência) ----------------------------------------------
    file: str                       # SEMPRE relativo ao repo analisado
    line: int
    end_line: int | None = None
    evidence: str = ""              # trecho de código, 1-3 linhas

    # --- entradas do scoring -------------------------------------------------
    severity: Severity = Severity.MEDIA
    confidence: Confidence = Confidence.MEDIA
    effort_points: float = 1.0      # story points de correção

    # --- ganchos de contexto de negócio (lidos pelo scoring) -----------------
    questionnaire_item: str | None = None   # "Q1".."Q7", "1.1"
    impacts_revenue: bool = False           # corrompe cálculo/persistência de fatura
    publicly_reachable: bool = False        # alcançável sem autenticação
    mitigates_bus_factor: bool = False      # rede de segurança p/ saída do dev

    # --- rastreabilidade -----------------------------------------------------
    cwe: int | None = None
    debt_id: str | None = None              # "DT-01", liga ao findings-ground-truth.md
    corroborated_by: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        """Identificador determinístico e estável do achado."""
        raw = f"{self.rule_id}|{self.file}|{self.line}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def merge_key(self) -> tuple[str, str, int]:
        """
        Chave de deduplicação entre ferramentas.

        Duas ferramentas que apontam o MESMO problema no MESMO lugar viram um
        achado só, com `corroborated_by` registrando quem mais viu. É o que
        evita inflar a contagem — inflar contagem é o oposto de priorizar.

        Quando os dois lados já estão mapeados para o mesmo débito do
        ground truth, o `debt_id` é a chave (mais preciso que a categoria):
        `radon:CC` e `pylint:too-many-locals` em everything.py:40 são o mesmo
        DT-09. Sem `debt_id`, cai para a categoria: `bandit:B110` e
        `pylint:broad-exception-caught` na mesma linha são um achado só.
        """
        discriminator = self.debt_id or self.category.value
        return (discriminator, self.file, self.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "rule_id": self.rule_id,
            "source": self.source,
            "language": self.language.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "effort_points": self.effort_points,
            "questionnaire_item": self.questionnaire_item,
            "impacts_revenue": self.impacts_revenue,
            "publicly_reachable": self.publicly_reachable,
            "mitigates_bus_factor": self.mitigates_bus_factor,
            "cwe": self.cwe,
            "debt_id": self.debt_id,
            "corroborated_by": sorted(self.corroborated_by),
            "metrics": self.metrics,
        }


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Funde achados equivalentes e acumula corroboração.

    Determinístico: a ordem de entrada é normalizada por `uid` antes da fusão,
    então o "vencedor" de cada grupo não depende de qual detector rodou primeiro.
    Mantém o de maior severidade; em empate, o de maior confiança.
    """
    sev_rank = {Severity.CRITICA: 3, Severity.ALTA: 2, Severity.MEDIA: 1, Severity.BAIXA: 0}
    conf_rank = {Confidence.ALTA: 2, Confidence.MEDIA: 1, Confidence.BAIXA: 0}

    groups: dict[tuple[str, str, int], list[Finding]] = {}
    for f in sorted(findings, key=lambda x: x.uid):
        groups.setdefault(f.merge_key(), []).append(f)

    merged: list[Finding] = []
    for _, group in sorted(groups.items()):
        winner = max(group, key=lambda f: (sev_rank[f.severity], conf_rank[f.confidence], f.uid))
        for other in group:
            if other is winner:
                continue
            if other.rule_id not in winner.corroborated_by:
                winner.corroborated_by.append(other.rule_id)
            # O vencedor herda metadado que ele não tem. Sem isso, fundir
            # bandit:B110 (que carrega CWE-703) com pylint:broad-exception-caught
            # (que vence por confiança) perderia o CWE — e o CWE é o que dá
            # rastreabilidade no questionário de segurança.
            if winner.cwe is None and other.cwe is not None:
                winner.cwe = other.cwe
            if winner.questionnaire_item is None and other.questionnaire_item:
                winner.questionnaire_item = other.questionnaire_item
            if winner.debt_id is None and other.debt_id:
                winner.debt_id = other.debt_id
            for key, value in other.metrics.items():
                winner.metrics.setdefault(key, value)
        merged.append(winner)
    return merged

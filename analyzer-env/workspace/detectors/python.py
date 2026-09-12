"""
Adaptador das ferramentas externas de Python: bandit, radon, pylint, semgrep.

Princípio de mandato
--------------------
Cada ferramenta entra no pipeline com UMA responsabilidade e tudo que ela
produz fora dela é descartado. Sem isso o resultado é "dump bruto de
ferramenta", que o desafio penaliza explicitamente.

    bandit   -> evidência de segurança com CWE   (6 test_ids na whitelist)
    radon cc -> complexidade numérica por função (1 achado por função acima do limiar)
    pylint   -> higiene localizada               (7 símbolos na whitelist)
    semgrep  -> NÃO gera achado; só corrobora taint de SQL (ajusta confiança)

Degradação sem ferramenta
-------------------------
Toda invocação tolera ferramenta ausente, quebrada ou lenta. O pipeline
continua com o que sobrou e `ToolRun` registra o que rodou — requisito do
README do desafio ("as ferramentas podem não estar instaladas").

A mecânica compartilhada (`ToolRun`, `run_tool`, `rel_path`, `snippet`, `ler`)
vive em `detectors/base.py` e é a MESMA usada por `detectors/php.py`. Aqui
ficam só o catálogo de regras e a normalização — o que de fato é específico
de Python.

Cegueiras medidas (não são bugs do nosso pipeline)
--------------------------------------------------
- bandit NÃO reporta B201 em `run.py`: o arquivo faz `from app.everything
  import app` e não importa flask, então o bandit não reconhece o objeto como
  app Flask. O item Q6 do questionário fica sem cobertura aqui e é coberto
  pelo `detectors/builtin.py`.
- bandit pega 4 dos 9 segredos hardcoded (só os nomeados *_SECRET/*_TOKEN/*_PASS).
- pylint NÃO emite R0801 (duplicate-code) neste repo: a duplicação é divergente.
- semgrep `p/secrets` = 0 achados e semgrep no PHP = 0 achados. Por isso o
  mandato dele aqui é estreito.
"""
from __future__ import annotations

import ast
import json

from detectors.base import ToolRun, ler, rel_path, run_tool, snippet
from models import Category, Confidence, Finding, Language, Severity

# ---------------------------------------------------------------------------
# Catálogo bandit: test_id -> metadados normalizados.
# Tudo que não está aqui é descartado (mandato: segurança com CWE).
# ---------------------------------------------------------------------------
BANDIT_RULES: dict[str, dict] = {
    "B608": dict(  # SQL construído por string
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=89,
        questionnaire_item="Q1", debt_id="DT-01", effort=3.0,
        title="SQL Injection via interpolação de string",
    ),
    "B324": dict(  # hashlib com algoritmo fraco
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=327,
        questionnaire_item="Q3,Q7", debt_id="DT-03", effort=3.0,
        title="Hash de senha com algoritmo quebrado (MD5)",
    ),
    "B105": dict(  # string que parece credencial
        category=Category.SEGURANCA, severity=Severity.ALTA, cwe=798,
        questionnaire_item="Q4", debt_id="DT-04", effort=2.0,
        title="Credencial hardcoded no código-fonte",
    ),
    "B106": dict(
        category=Category.SEGURANCA, severity=Severity.ALTA, cwe=798,
        questionnaire_item="Q4", debt_id="DT-04", effort=2.0,
        title="Credencial hardcoded passada como argumento",
    ),
    "B201": dict(  # flask debug=True — ver "Cegueiras medidas"
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=489,
        questionnaire_item="Q6", debt_id="DT-05", effort=0.5,
        title="Debug habilitado em produção",
    ),
    "B110": dict(  # try/except/pass
        category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA, cwe=703,
        questionnaire_item=None, debt_id="DT-17", effort=2.0,
        title="Exceção engolida silenciosamente",
    ),
    "B113": dict(  # requests sem timeout
        category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA, cwe=400,
        questionnaire_item=None, debt_id="DT-19", effort=1.0,
        title="Chamada HTTP sem timeout",
    ),
}

# Itens do questionário que este detector NÃO pode assegurar, mesmo tendo
# regra mapeada para eles.
#
# Q6 (debug em produção): B201 está no catálogo acima porque, se o bandit
# reportar, queremos o achado. Mas foi MEDIDO que ele não reporta neste repo —
# `run.py` faz `from app.everything import app` e o bandit não reconhece o
# objeto como app Flask (teste de controle: com `from flask import Flask` no
# mesmo arquivo, o B201 dispara). Declarar Q6 como coberto faria o pipeline
# responder "sem achado" para uma pergunta que ninguém verificou de fato —
# exatamente o erro que o comercial da HourTrack cometeu ao responder "Sim"
# para tudo. Quem assegura Q6 é o detector builtin.
ITENS_NAO_ASSEGURADOS = {"Q6"}

# ---------------------------------------------------------------------------
# Catálogo pylint: symbol -> metadados. Whitelist deliberadamente curta.
#
# Descartados de propósito:
#   import-error  -> ruído de ambiente (flask não instalado no container de
#                    análise). Não é débito do código-alvo. Reportar = FP.
#   no-else-return, redefined-outer-name, redefined-builtin -> estilo, sem
#                    impacto de negócio.
#   broad-exception-caught e missing-timeout ficam, mas são o MESMO achado que
#                    bandit B110/B113 — a deduplicação em models.deduplicate()
#                    funde os dois e registra corroboração em vez de contar 2x.
# ---------------------------------------------------------------------------
PYLINT_RULES: dict[str, dict] = {
    "unused-variable": dict(
        category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
        debt_id="DT-28", effort=0.5, title="Código morto (variável não usada)",
    ),
    "fixme": dict(
        category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
        debt_id="DT-21", effort=0.5, title="TODO/FIXME pendente no código",
    ),
    "broad-exception-caught": dict(
        category=Category.MANUTENIBILIDADE, severity=Severity.MEDIA,
        debt_id="DT-17", effort=2.0, title="Exceção genérica capturada",
    ),
    "missing-timeout": dict(
        category=Category.MANUTENIBILIDADE, severity=Severity.BAIXA,
        debt_id="DT-19", effort=1.0, title="Chamada HTTP sem timeout",
    ),
    "inconsistent-return-statements": dict(
        category=Category.DESIGN, severity=Severity.MEDIA,
        debt_id=None, effort=1.0, title="Função retorna None implicitamente",
    ),
    "too-many-branches": dict(
        category=Category.DESIGN, severity=Severity.MEDIA,
        debt_id="DT-11", effort=5.0, title="Função com ramificação excessiva",
    ),
    "too-many-locals": dict(
        category=Category.DESIGN, severity=Severity.BAIXA,
        debt_id="DT-09", effort=5.0, title="Função com estado local excessivo",
    ),
}

# ---------------------------------------------------------------------------
# Bandas de complexidade PRÓPRIAS.
#
# Não usamos o campo `rank` do radon: ele discorda da tabela do FERRAMENTAS.md
# (handle_date=29 sai como "D" no radon 6.0.1 e como "F" na doc) e o `radon mi`
# classifica 100% dos arquivos deste repo como "A" — sinal zero. Usamos o
# número bruto com limiares nossos, documentados aqui.
# ---------------------------------------------------------------------------
CC_BANDS = [
    # (cc_minimo, severidade, esforço em story points, debt_id)
    (25, Severity.ALTA,  8.0, "DT-11"),
    (16, Severity.MEDIA, 5.0, "DT-09"),
    (11, Severity.BAIXA, 3.0, "DT-09"),
]
CC_FLOOR = 11  # abaixo disso não gera achado


# ===========================================================================
# Cross-check anti-falso-positivo para SQL Injection
#
# O bandit marca B608 em qualquer SQL montado por string — inclusive quando o
# valor interpolado não é atacável. Medido no repo-alvo: 7 B608, sendo 2 falsos
# positivos. Esta análise de AST classifica a ORIGEM de cada interpolação:
#
#   tainted   -> vem de request.args/form/values/get_json  => Confidence.ALTA
#   internal  -> parâmetro de função, self.x, valor do banco => Confidence.MEDIA
#   literal   -> lookup em dict com chaves constantes        => Confidence.BAIXA
#
# O caso `literal` é o `f'DELETE FROM {TABLE_MAP[thing]}'` de everything.py:205:
# `thing` vem da URL, mas o dict tem 4 chaves literais e qualquer outro valor
# dá KeyError -> não é injetável. O semgrep marca essa linha como tainted
# (ele vê o dado do request chegando na string, mas não que o dict restringe o
# domínio), então NOSSA classificação tem precedência sobre a corroboração
# dele. É a decisão que evita o falso positivo que o semgrep sozinho confirmaria.
# ===========================================================================
TAINT_SOURCES = ("args", "form", "values", "json", "get_json", "cookies", "headers")


class _OriginIndex:
    """Índice por arquivo: nome de variável -> origem provável do valor."""

    def __init__(self, source: str) -> None:
        self.tainted: set[str] = set()
        self.literal_maps: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        # Varredura única do módulo inteiro, ignorando escopo. Simplificação
        # deliberada: nestes arquivos não há colisão de nome entre escopos, e
        # errar para "mais informação" é melhor que não classificar.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if self._is_request_derived(node.value):
                self.tainted.add(target.id)
            elif self._is_literal_dict(node.value):
                self.literal_maps.add(target.id)

    @staticmethod
    def _is_request_derived(node: ast.AST) -> bool:
        """True se a expressão toca `request.<fonte>` em qualquer profundidade."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in TAINT_SOURCES:
                base = sub.value
                if isinstance(base, ast.Name) and base.id == "request":
                    return True
                if isinstance(base, ast.Attribute) and base.attr == "request":
                    return True
            # request.args.get('month') -> Call sobre Attribute sobre Attribute
            if isinstance(sub, ast.Name) and sub.id == "request":
                return True
        return False

    @staticmethod
    def _is_literal_dict(node: ast.AST) -> bool:
        return isinstance(node, ast.Dict) and bool(node.keys) and all(
            isinstance(k, ast.Constant) for k in node.keys
        )

    def classify(self, expr: ast.AST) -> str:
        """Classifica UMA expressão interpolada."""
        if isinstance(expr, ast.Subscript):
            base = expr.value
            if isinstance(base, ast.Name) and base.id in self.literal_maps:
                return "literal"
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return "tainted"
        if self._is_request_derived(expr):
            return "tainted"
        return "internal"


def _sqli_origin(repo: str, rel: str, line: int) -> tuple[str, str]:
    """
    Classifica a origem dos valores interpolados no SQL próximo a `line`.

    Retorna (classificação, detalhe). Precedência: tainted > internal > literal.
    Determinístico: depende só do conteúdo do arquivo.
    """
    source = ler(repo, rel)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "internal", "arquivo não parseável; confiança mantida em MÉDIA"
    if not source:
        return "internal", "arquivo ilegível; confiança mantida em MÉDIA"

    index = _OriginIndex(source)
    best, detail = None, ""
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start) or start
        # bandit ancora no início do statement; a interpolação pode estar
        # dezenas de linhas abaixo. Aceitamos a f-string que contém a linha
        # reportada OU que comece nela.
        if not (start <= line <= end or start == line):
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            kind = index.classify(part.value)
            if kind == "tainted":
                return "tainted", "valor interpolado vem de `request`"
            if best is None or (best == "literal" and kind == "internal"):
                best, detail = kind, {
                    "literal": "valor vem de dict com chaves constantes — domínio fechado, não injetável",
                    "internal": "valor interno (parâmetro, atributo ou vindo do banco)",
                }[kind]
    if best is None:
        return "internal", "f-string não localizada; confiança mantida em MÉDIA"
    return best, detail


# ===========================================================================
# Ferramentas
# ===========================================================================
def normalize_bandit(payload: dict, repo: str) -> tuple[list[Finding], int]:
    """
    Converte o JSON do bandit em Findings. Função pura: não invoca subprocess.

    Separada de `run_bandit` de propósito — é o que permite testar o mandato,
    o mapeamento de CWE e o cross-check anti-FP sem ter bandit instalado.
    Devolve (achados, quantos foram descartados por estarem fora do mandato).
    """
    findings, discarded = [], 0
    for issue in payload.get("results", []):
        test_id = issue.get("test_id", "")
        rule = BANDIT_RULES.get(test_id)
        if rule is None:                      # fora do mandato -> descarta
            discarded += 1
            continue
        rel = rel_path(issue.get("filename", ""), repo)
        line = int(issue.get("line_number", 0) or 0)
        description = issue.get("issue_text", "").strip()
        confidence = Confidence.MEDIA
        corroboration: list[str] = []

        if test_id == "B608":
            origin, detail = _sqli_origin(repo, rel, line)
            confidence = {
                "tainted": Confidence.ALTA,
                "internal": Confidence.MEDIA,
                "literal": Confidence.BAIXA,
            }[origin]
            description = f"{description} Origem do valor interpolado: {detail}."
            corroboration.append(f"builtin:origin={origin}")

        findings.append(Finding(
            rule_id=f"bandit:{test_id}",
            source="bandit",
            language=Language.PYTHON,
            category=rule["category"],
            title=rule["title"],
            description=description,
            file=rel,
            line=line,
            evidence=snippet(repo, rel, line),
            severity=rule["severity"],
            confidence=confidence,
            effort_points=rule["effort"],
            questionnaire_item=rule["questionnaire_item"],
            cwe=rule["cwe"],
            debt_id=rule["debt_id"],
            corroborated_by=corroboration,
            metrics={"bandit_severity": issue.get("issue_severity", "")},
        ))
    return findings, discarded


def run_bandit(repo: str) -> tuple[list[Finding], ToolRun]:
    ok, out, err = run_tool(["bandit", "-r", repo, "-f", "json", "-q"])
    if not ok:
        return [], ToolRun("bandit", available=False, ok=False, error=err)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return [], ToolRun("bandit", available=True, ok=False, error="stdout não é JSON")

    findings, discarded = normalize_bandit(payload, repo)
    status = ToolRun("bandit", available=True, ok=True, findings=len(findings))
    status.notes.append(f"{discarded} achados fora do mandato descartados")
    if not any(f.rule_id == "bandit:B201" for f in findings):
        status.notes.append(
            "B201 ausente: esperado — run.py não importa flask, o bandit não "
            "reconhece o app. Q6 é coberto pelo detector builtin."
        )
    return findings, status


def normalize_radon(payload: dict, repo: str) -> list[Finding]:
    """Converte o JSON do `radon cc` em Findings. Função pura."""
    findings = []
    for path, blocks in sorted(payload.items()):
        if not isinstance(blocks, list):      # radon reporta erro por arquivo
            continue
        rel = rel_path(path, repo)
        for block in blocks:
            cc = int(block.get("complexity", 0) or 0)
            if cc < CC_FLOOR:
                continue
            severity, effort, debt_id = next(
                (s, e, d) for lo, s, e, d in CC_BANDS if cc >= lo
            )
            name = block.get("name", "?")
            line = int(block.get("lineno", 0) or 0)
            findings.append(Finding(
                rule_id="radon:CC",
                source="radon",
                language=Language.PYTHON,
                category=Category.MANUTENIBILIDADE,
                title=f"Complexidade ciclomática alta em `{name}` (CC={cc})",
                description=(
                    f"A função `{name}` tem complexidade ciclomática {cc}. "
                    f"Cada caminho independente é um caminho não testado: o repo "
                    f"tem zero testes e o autor de 90% do código sai em 6 semanas."
                ),
                file=rel,
                line=line,
                evidence=snippet(repo, rel, line),
                severity=severity,
                confidence=Confidence.ALTA,   # métrica objetiva, não heurística
                effort_points=effort,
                debt_id=debt_id,
                metrics={"cc": cc, "radon_rank": block.get("rank", ""), "symbol": name},
            ))
    return findings


def run_radon(repo: str) -> tuple[list[Finding], ToolRun]:
    ok, out, err = run_tool(["radon", "cc", repo, "-j"])
    if not ok:
        return [], ToolRun("radon", available=False, ok=False, error=err)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return [], ToolRun("radon", available=True, ok=False, error="stdout não é JSON")
    findings = normalize_radon(payload, repo)
    return findings, ToolRun("radon", available=True, ok=True, findings=len(findings))


def normalize_pylint(payload: list, repo: str) -> tuple[list[Finding], int]:
    """Converte o JSON do pylint em Findings. Função pura."""
    findings, discarded = [], 0
    for msg in payload:
        symbol = msg.get("symbol", "")
        rule = PYLINT_RULES.get(symbol)
        if rule is None:
            discarded += 1
            continue
        rel = rel_path(msg.get("path", ""), repo)
        line = int(msg.get("line", 0) or 0)
        findings.append(Finding(
            rule_id=f"pylint:{symbol}",
            source="pylint",
            language=Language.PYTHON,
            category=rule["category"],
            title=rule["title"],
            description=msg.get("message", "").strip(),
            file=rel,
            line=line,
            evidence=snippet(repo, rel, line),
            severity=rule["severity"],
            confidence=Confidence.ALTA,
            effort_points=rule["effort"],
            debt_id=rule["debt_id"],
            metrics={"pylint_type": msg.get("type", "")},
        ))
    return findings, discarded


def run_pylint(repo: str) -> tuple[list[Finding], ToolRun]:
    # --disable=C apenas. Desabilitar R também (como sugere o FERRAMENTAS.md)
    # mataria too-many-branches/locals, que são justamente o que aproveitamos.
    ok, out, err = run_tool(["pylint", repo, "--output-format=json", "--disable=C"])
    if not ok:
        return [], ToolRun("pylint", available=False, ok=False, error=err)
    try:
        payload = json.loads(out or "[]")
    except json.JSONDecodeError:
        return [], ToolRun("pylint", available=True, ok=False, error="stdout não é JSON")
    findings, discarded = normalize_pylint(payload, repo)
    status = ToolRun("pylint", available=True, ok=True, findings=len(findings))
    status.notes.append(f"{discarded} mensagens fora da whitelist descartadas (inclui import-error)")
    return findings, status


def corroborate_with_semgrep(repo: str, findings: list[Finding], timeout: int = 300) -> ToolRun:
    """
    Semgrep NÃO produz achado próprio. Ele só confirma que dado do request
    alcança a query (taint tracking), o que o bandit não sabe fazer.

    Efeito: registra `semgrep:<regra>` em `corroborated_by`. Não sobe confiança
    já classificada como BAIXA pela análise de dict-literal — ver comentário do
    bloco anti-falso-positivo. Precisa de internet; falhar aqui é aceitável.
    """
    ok, out, err = run_tool(
        ["semgrep", "--config=p/owasp-top-ten", "--json", "--metrics=off", "-q", repo],
        timeout=timeout,
    )
    if not ok:
        return ToolRun("semgrep", available=False, ok=False, error=err,
                       notes=["sem corroboração de taint; confiança dos SQLi vem só da nossa AST"])
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return ToolRun("semgrep", available=True, ok=False, error="stdout não é JSON")

    taint: dict[tuple[str, int], str] = {}
    for hit in payload.get("results", []):
        check = hit.get("check_id", "")
        if "sql" not in check and "taint" not in check:
            continue
        rel = rel_path(hit.get("path", ""), repo)
        start = int(hit.get("start", {}).get("line", 0) or 0)
        end = int(hit.get("end", {}).get("line", start) or start)
        for ln in range(start, end + 1):
            taint[(rel, ln)] = check.split(".")[-1]

    matched, upgraded = 0, 0
    for finding in findings:
        if finding.rule_id != "bandit:B608":
            continue
        hit = taint.get((finding.file, finding.line))
        if hit is None:
            continue
        matched += 1
        tag = f"semgrep:{hit}"
        if tag not in finding.corroborated_by:
            finding.corroborated_by.append(tag)
        if finding.confidence is Confidence.MEDIA:
            finding.confidence = Confidence.ALTA
            upgraded += 1

    status = ToolRun("semgrep", available=True, ok=True, findings=0)
    status.notes.append(f"{len(taint)} linhas com taint de SQL; {matched} achados corroborados, {upgraded} com confiança elevada")
    return status


def analyze(repo: str, use_semgrep: bool = True) -> tuple[list[Finding], list[ToolRun]]:
    """Roda as ferramentas externas de Python e devolve achados normalizados."""
    findings: list[Finding] = []
    runs: list[ToolRun] = []

    for runner in (run_bandit, run_radon, run_pylint):
        got, status = runner(repo)
        findings.extend(got)
        runs.append(status)

    if use_semgrep:
        runs.append(corroborate_with_semgrep(repo, findings))

    findings.sort(key=lambda f: f.uid)   # ordem determinística de saída
    return findings, runs


def cobertura_questionario(ferramentas_ok: set[str] | None = None) -> set[str]:
    """
    Itens do security-questionnaire.md que este detector EFETIVAMENTE verificou.

    Contrato que todo detector expõe. O relatório usa isso para distinguir
    "não achamos nada" (conforme) de "ninguém olhou" (sem cobertura) — a
    diferença entre responder o questionário com honestidade e chutar.

    `ferramentas_ok` é o conjunto de ferramentas que rodaram com sucesso. Sem
    esse filtro o pipeline afirmaria conformidade em Q1/Q3/Q4/Q7 mesmo com o
    bandit ausente, que é exatamente o erro que o time comercial da HourTrack
    cometeu ao responder "Sim" para tudo.

    Cobertura máxima possível aqui: Q1, Q3, Q4 e Q7 (bandit). Q2 (XSS) e
    Q6 (debug) nunca aparecem — nenhuma das quatro ferramentas os detecta
    neste repo; são responsabilidade do detector builtin.
    """
    catalogos = (("bandit", BANDIT_RULES), ("pylint", PYLINT_RULES))
    itens: set[str] = set()
    for ferramenta, catalogo in catalogos:
        if ferramentas_ok is not None and ferramenta not in ferramentas_ok:
            continue
        for rule in catalogo.values():
            raw = rule.get("questionnaire_item")
            if raw:
                itens.update(p.strip() for p in raw.split(","))
    return itens - ITENS_NAO_ASSEGURADOS

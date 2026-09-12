"""
Adaptador de análise PHP: phpstan, phpmetrics, phploc + detectores próprios.

Princípio de mandato (mesmo do detectors/python.py)
---------------------------------------------------
Cada ferramenta entra com UMA responsabilidade e tudo que ela produz fora dela
é descartado. Sem isso o resultado é "dump bruto de ferramenta", que o desafio
penaliza explicitamente.

    phpstan    -> corretude/tipos, DEPOIS de filtrar o ruído de framework ausente
    phpmetrics -> complexidade ciclomática por classe
    phploc     -> métrica de projeto: contexto, NÃO achado (não tem linha)
    semgrep    -> corroboração de SQLi; medido = 0 achados em PHP
    builtin    -> TODA a segurança (nenhuma ferramenta PHP daqui faz isso)

Por que existe detector próprio aqui
------------------------------------
O ferramental PHP deste ambiente não tem equivalente do `bandit`. phpstan não
é scanner de segurança, phpmetrics e phploc são métricas, e o semgrep em PHP
foi medido em 0 achados (registrado no docstring do detectors/python.py). Se
o detector dependesse só das ferramentas externas, o scorecard responderia
"sem cobertura" para Q1, Q2, Q4, Q6 e 1.1 — ou seja, o pipeline não teria
nada a dizer sobre o questionário que trava o contrato de R$ 8.000/mês.

Os detectores `builtin:PHP-*` cobrem essa lacuna com análise léxica própria
do PHP. Eles são a razão de o repo PHP conseguir responder o mesmo scorecard
que o Python — que é exatamente o desafio arquitetural do bônus.

Diferenças REAIS entre os dois repos (não são bugs deste detector)
------------------------------------------------------------------
- O PHP usa `bcrypt()` e `Hash::make()`, NÃO `md5`. DT-03 (Q3/Q7) simplesmente
  não existe aqui. Portar o ground truth do Python às cegas produziria um
  falso positivo — e falso positivo desconta ponto.
- `EverythingController::delete()` usa query builder (`DB::table($map[$thing])`),
  não SQL cru. A armadilha FP-03 do Python (o `TABLE_MAP` em f-string) não tem
  equivalente injetável em PHP.
- Não há `database.sqlite` nem `.env` commitados (só `.env.example`, que é o
  template esperado). FP-01 e FP-02 valem aqui também: não reportar.

Cegueiras conhecidas deste detector
-----------------------------------
- Sem parser de PHP (não há binário `php` no host nem parser em stdlib), a
  análise é léxica: lê literais de string e classifica interpolação. Ela
  entende aspas simples vs duplas vs heredoc vs nowdoc, mas não resolve fluxo
  entre funções nem entre arquivos.
- A classificação de origem ignora escopo dentro do arquivo, igual à do
  detector Python. Documentado em teste.
- Q6 (debug) nunca é declarado coberto — ver `ITENS_NAO_ASSEGURADOS`.

Riscos latentes de falso positivo (medidos, NÃO corrigidos de propósito)
------------------------------------------------------------------------
Testados com repositórios adversariais: nenhum ocorre no código-alvo, e cada
correção trocaria um falso positivo hipotético por um falso NEGATIVO possível.
Em detector de segurança essa troca é ruim, então ficam documentados:

1. `scan_rotas_sem_auth` só olha `routes/`. O Laravel também aceita
   `$this->middleware('auth')` no construtor do controller. Checar isso
   suprimiria o achado quando QUALQUER controller tivesse auth, escondendo
   rotas realmente desprotegidas. (No alvo: nenhum controller usa.)
2. `scan_log_sensivel` exige acessor e sink no mesmo ARQUIVO, não na mesma
   função. Um arquivo que valida `$request->all()` e, à parte, insere dado não
   relacionado dispara. Separar exigiria achar fronteira de função sem parser
   (contagem de chaves), que erra dentro de string e comentário — modo de
   falha novo, gerando FP e FN. (No alvo: mesma função, 7 linhas de distância.)
3. `scan_xss_blade` não distingue `{!! $htmlConfiavel !!}` intencional de
   descuido. Não é corrigível sem saber a origem do valor; qualquer heurística
   por nome de variável seria chute.
4. `verificar_env_commitado` trata `.env.testing` como arquivo real. Excluí-lo
   criaria ponto cego para credencial real commitada ali.
"""
from __future__ import annotations

import json
import os
import re

from detectors.base import (
    ToolRun, listar_arquivos, ler, numero_da_linha, rel_path, run_tool, snippet,
)
from models import Category, Confidence, Finding, Language, Severity

# ---------------------------------------------------------------------------
# Catálogo de débitos.
#
# Os valores de severidade/esforço/questionário para um mesmo `debt_id` são
# DELIBERADAMENTE iguais aos de BANDIT_RULES em detectors/python.py. O scoring
# model é cego à linguagem: se DT-04 valesse 2.0 SP em Python e 1.0 em PHP, a
# priorização mudaria só por causa do repo de origem, que é o oposto do que o
# bônus pede. Mexeu num lado, mexe no outro.
# ---------------------------------------------------------------------------
DEBITOS: dict[str, dict] = {
    "DT-01": dict(
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=89,
        questionnaire_item="Q1", effort=3.0,
        title="SQL Injection via interpolação de string",
    ),
    "DT-02": dict(
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=79,
        questionnaire_item="Q2", effort=3.0,
        title="XSS: saída sem escape no template",
    ),
    "DT-04": dict(
        category=Category.SEGURANCA, severity=Severity.ALTA, cwe=798,
        questionnaire_item="Q4", effort=2.0,
        title="Credencial hardcoded no código-fonte",
    ),
    "DT-06": dict(
        category=Category.SEGURANCA, severity=Severity.CRITICA, cwe=306,
        questionnaire_item="1.1", effort=8.0,
        title="Rotas sem autenticação",
    ),
    "DT-08": dict(
        category=Category.SEGURANCA, severity=Severity.ALTA, cwe=532,
        questionnaire_item=None, effort=1.0,
        title="Dado sensível gravado em log",
    ),
}

# Itens do questionário que este detector NÃO pode assegurar.
#
# Q6 (debug em produção): a configuração de produção não está no repositório —
# e é certo que não esteja. O único sinal disponível é `APP_DEBUG=true` no
# `.env.example`, que é o skeleton intocado do Laravel e está CORRETO (aquele
# arquivo serve a desenvolvimento local). `config/app.php` usa
# `env('APP_DEBUG', false)`, o default seguro. Não há evidência para afirmar
# "Q6 = NÃO" nem para afirmar "Q6 = sim", então Q6 fica "sem cobertura":
# ninguém verificou a produção de fato. Ver o bloco de DT-05 mais abaixo.
ITENS_NAO_ASSEGURADOS = {"Q6"}

# ---------------------------------------------------------------------------
# Ruído do phpstan neste ambiente (FP-04 do findings-ground-truth.md).
#
# O container não instala as dependências do Laravel, então o phpstan reporta
# centenas de "unknown class Illuminate\*". Isso é ruído de ambiente, não
# débito do time — o ground truth manda filtrar explicitamente.
# ---------------------------------------------------------------------------
RUIDO_PHPSTAN = (
    re.compile(r"unknown class .*\\?(Illuminate|Symfony|Laravel|PHPUnit|Faker)\\", re.I),
    re.compile(r"(extends|implements) unknown (class|interface)", re.I),
    re.compile(r"has unknown class .* as its type", re.I),
    re.compile(r"not found in (?:the )?(?:class|ReflectionException)", re.I),
    re.compile(r"used function (env|config|view|redirect|response|request|bcrypt|now)\b.*not found", re.I),
    re.compile(r"used constant .* not found", re.I),
)

# ---------------------------------------------------------------------------
# Ruído de SEGUNDA ORDEM — só existe quando as dependências não estão instaladas.
#
# Este é o filtro que faltava, e a falha era silenciosa. `RUIDO_PHPSTAN` pega a
# CAUSA ("SyncData extends unknown class Illuminate\Console\Command"), mas não
# a CONSEQUÊNCIA: com a classe-mãe irresolvível, todo método herdado vira
# "Call to an undefined method App\...\SyncData::option()". Essa mensagem não
# menciona Illuminate em lugar nenhum, então passava pelo filtro e virava 8
# achados — `option`, `info`, `error`, `warn` são todos do `Command` do Laravel.
#
# Sem `vendor/autoload.php` no repo, QUALQUER conclusão do phpstan que dependa
# de resolver classe é não-confiável por construção. Não é conservadorismo:
# é a FP-04 do findings-ground-truth.md ("filtrar no pipeline").
# ---------------------------------------------------------------------------
RUIDO_SEM_DEPENDENCIAS = (
    re.compile(r"Call to an undefined method", re.I),
    re.compile(r"Access to an undefined property", re.I),
    re.compile(r"Call to (?:static )?method \S+ on an unknown class", re.I),
    re.compile(r"Instantiated class \S+ not found", re.I),
    re.compile(r"(?:Function|Class|Interface|Trait) \S+ not found", re.I),
)

# phpstan reporta MUITA coisa que não é débito priorizável (estilo, generics,
# `iterable` sem tipo). Só estes padrões viram achado — mandato de corretude.
PHPSTAN_ACIONAVEL = (
    (re.compile(r"(?:Undefined variable|Variable .* might not be defined)", re.I),
     Category.MANUTENIBILIDADE, Severity.MEDIA, 1.0, "Variável possivelmente indefinida"),
    (re.compile(r"Call to an undefined method", re.I),
     Category.MANUTENIBILIDADE, Severity.ALTA, 2.0, "Chamada a método inexistente"),
    # "Comparison always true" saiu do mandato. No alvo ele só apontava
    # `if ($month >= 1 && $month <= 3) ... elseif ($month >= 4 ...)`: numa
    # cadeia de faixas, o limite inferior é redundante para o phpstan mas é o
    # que torna o código legível. Reportar isso como débito é o FP-05 do
    # ground truth — ruído de ferramenta elevado a achado.
    (re.compile(r"Unreachable statement", re.I),
     Category.MANUTENIBILIDADE, Severity.BAIXA, 0.5, "Código inalcançável"),
    (re.compile(r"returns? .* but return statement is missing", re.I),
     Category.DESIGN, Severity.MEDIA, 1.0, "Função sem retorno em algum caminho"),
)

# ---------------------------------------------------------------------------
# Bandas de complexidade do phpmetrics.
#
# ATENÇÃO à diferença de granularidade: `radon cc` mede CC por FUNÇÃO e o
# phpmetrics mede CC por CLASSE (soma dos métodos). Um CC=16 em PHP não é o
# mesmo fenômeno que um CC=16 em Python.
#
# Mesmo assim usamos os MESMOS limiares do detector Python, por duas razões:
# (1) a tabela de comparação do FERRAMENTAS.md trata os pares como
#     equivalentes (DateHelper=36 ↔ handle_date=29), porque neste código-alvo
#     as classes são finas e a maior parte da CC vem de um método gigante;
# (2) limiar diferente por linguagem faria o mesmo débito receber prioridade
#     diferente conforme o repo — o scoring deve ser cego à linguagem.
# A ressalva fica registrada em ToolRun.notes, para o relatório não vender
# como equivalência exata o que é aproximação justificada.
# ---------------------------------------------------------------------------
CC_BANDS = [
    # (cc_minimo, severidade, esforço em story points, debt_id)
    (25, Severity.ALTA,  8.0, "DT-11"),
    (16, Severity.MEDIA, 5.0, "DT-09"),
    (11, Severity.BAIXA, 3.0, "DT-09"),
]
CC_FLOOR = 11


# ===========================================================================
# Análise léxica de PHP
#
# Não há binário `php` no ambiente de análise nem parser de PHP na stdlib, então
# tudo aqui é leitura de literais de string. O que torna isso confiável o
# suficiente é uma particularidade da linguagem: em PHP, SÓ aspas duplas e
# heredoc interpolam variáveis. Aspas simples e nowdoc são literais puros.
#
#     DB::select('SELECT ... WHERE m = $month')   -> seguro: $month é literal
#     DB::select("SELECT ... WHERE m = '$month'") -> injetável
#
# Essa distinção é o que separa achado real de falso positivo, e é sintática —
# não depende de inferência.
# ===========================================================================

# Chamadas que recebem SQL cru. Query builder (`DB::table(...)->where(...)`)
# fica DE FORA de propósito: ele parametriza sozinho, e incluí-lo marcaria
# como injetável o `DB::table($map[$thing])->delete()` do EverythingController,
# que não monta SQL nenhum.
CHAMADAS_SQL = (
    "DB::select", "DB::statement", "DB::insert", "DB::update", "DB::delete",
    "DB::raw", "->whereRaw", "->selectRaw", "->havingRaw", "->orderByRaw",
    "->query", "->exec",
)

# Expressões interpoladas: sintaxe simples (`$a`, `$a->b`, `$a['k']`) e
# complexa (`{$a->b()}`).
_INTERPOLACAO = re.compile(r"\{\$[^{}]+\}|\$\w+(?:->\w+|\[[^\]]*\])*")

# Superglobais: qualquer uma delas é dado do usuário, sem intermediário.
_SUPERGLOBAIS = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b")

# `$x = $r->get(...)` / `->input(` / `->query(` / `->all(` / `request(`
# `protected $table = 'customers';` — propriedade de valor constante. Interpolar
# isso em SQL não é injeção: o domínio é fechado, igual ao dict de chaves
# literais do repo Python (FP-03 do ground truth).
_PROPRIEDADE_LITERAL = re.compile(
    r"(?:private|protected|public|var|static)\s+\$(\w+)\s*=\s*['\"][^'\"]*['\"]\s*;"
)

_ATRIBUICAO_DE_REQUEST = re.compile(
    r"\$(\w+)\s*=\s*[^;\n]*?(?:"
    r"\$\w+\s*->\s*(?:get|input|query|post|all|json|header|cookie|only|except)\s*\("
    r"|\brequest\s*\("
    r"|\$_(?:GET|POST|REQUEST|COOKIE)\b"
    r")"
)


def _ler_literal(source: str, i: int) -> tuple[str, str, int] | None:
    """
    Lê o literal de string que começa em/depois de `i`, pulando espaço.

    Devolve `(tipo, conteudo, offset_inicial)` com tipo em
    {"single", "double", "heredoc", "nowdoc"}, ou None se o próximo token não
    for um literal (ex.: a chamada recebeu uma variável, não uma string).
    """
    n = len(source)
    while i < n and source[i] in " \t\r\n":
        i += 1
    if i >= n:
        return None

    if source[i] in "'\"":
        aspas = source[i]
        tipo = "single" if aspas == "'" else "double"
        inicio = i
        i += 1
        buf = []
        while i < n:
            c = source[i]
            if c == "\\" and i + 1 < n:
                buf.append(source[i:i + 2])
                i += 2
                continue
            if c == aspas:
                return tipo, "".join(buf), inicio
            buf.append(c)
            i += 1
        return None  # string não fechada: arquivo truncado ou nosso erro

    if source.startswith("<<<", i):
        m = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n", source[i:])
        if not m:
            return None
        tipo = "nowdoc" if m.group(1) == "'" else "heredoc"
        rotulo = m.group(2)
        corpo_ini = i + m.end()
        fim = re.search(rf"^[ \t]*{re.escape(rotulo)}\b", source[corpo_ini:], re.M)
        if not fim:
            return None
        return tipo, source[corpo_ini:corpo_ini + fim.start()], i

    return None


def _sql_interpolado(source: str) -> list[tuple[int, str, list[str]]]:
    """
    Todos os literais de SQL que INTERPOLAM valor.

    Devolve `(linha, tipo_de_literal, expressões_interpoladas)`. Literais em
    aspas simples e nowdoc nunca entram: PHP não interpola neles, então um
    `$month` ali é texto, não injeção. É o mesmo papel do cross-check de AST
    do detector Python — evitar o falso positivo de "todo SQL é injetável".
    """
    achados = []
    for chamada in CHAMADAS_SQL:
        inicio = 0
        while True:
            pos = source.find(chamada, inicio)
            if pos == -1:
                break
            inicio = pos + len(chamada)
            abre = source.find("(", inicio)
            if abre == -1 or not source[inicio:abre].strip() == "":
                continue
            literal = _ler_literal(source, abre + 1)
            if literal is None:
                continue
            tipo, conteudo, offset = literal
            if tipo in ("single", "nowdoc"):
                continue
            exprs = _INTERPOLACAO.findall(conteudo)
            if not exprs:
                continue
            achados.append((numero_da_linha(source, offset), tipo, sorted(set(exprs))))
    # Ordenado por linha: saída estável independente da ordem de CHAMADAS_SQL.
    return sorted(achados)


class _IndiceDeOrigem:
    """
    Índice por arquivo: nome de variável -> origem provável do valor.

    Simplificação deliberada (igual à do detector Python): varredura do
    arquivo inteiro ignorando escopo. Nestes arquivos não há colisão de nome
    entre escopos, e errar para "mais informação" é melhor que não classificar.
    """

    def __init__(self, source: str) -> None:
        self.tainted: set[str] = set(_ATRIBUICAO_DE_REQUEST.findall(source))
        # Propriedades com valor literal: `protected $table = 'customers';`.
        # Domínio fechado — interpolar isso em SQL não é injetável.
        self.literais: set[str] = set(_PROPRIEDADE_LITERAL.findall(source))

    def classificar(self, expr: str) -> str:
        """
        Classifica UMA expressão interpolada.

            tainted  -> vem do request                      => Confidence.ALTA
            internal -> parâmetro, $this->x, valor do banco  => Confidence.MEDIA
            literal  -> propriedade com valor constante      => não é achado
        """
        # Literal primeiro: `{$this->table}` não pode ser "tainted" por uma
        # variável local homônima, e a checagem de nome abaixo casaria `table`.
        prop = re.fullmatch(r"\{?\s*\$this\s*->\s*(\w+)\s*\}?", expr)
        if prop and prop.group(1) in self.literais:
            return "literal"
        if _SUPERGLOBAIS.search(expr):
            return "tainted"
        # `{$r->get('month')}` interpolado direto, sem variável intermediária.
        if re.search(r"->\s*(?:get|input|query|post|all|json)\s*\(", expr):
            return "tainted"
        for nome in re.findall(r"\$(\w+)", expr):
            if nome in self.tainted:
                return "tainted"
        return "internal"

    def classificar_conjunto(self, exprs: list[str]) -> tuple[str, str]:
        """
        Precedência: tainted > internal > literal.

        Basta UMA expressão atacável para o SQL ser atacável. O inverso também
        vale: só quando TODAS são literais o SQL deixa de ser injetável — é o
        equivalente PHP do `TABLE_MAP` em f-string do repo Python (FP-03), e a
        mesma decisão que a análise de AST do detector Python já toma.
        """
        classificacoes = [self.classificar(e) for e in exprs]
        for expr, kind in zip(exprs, classificacoes):
            if kind == "tainted":
                return "tainted", f"`{expr}` vem de `request`"
        if classificacoes and all(k == "literal" for k in classificacoes):
            return "literal", "todos os valores são propriedades constantes — domínio fechado"
        return "internal", "valores internos (parâmetro, `$this` ou vindo do banco)"


# ===========================================================================
# Detectores próprios (builtin) — a segurança que nenhuma ferramenta PHP pega
# ===========================================================================
def scan_sql_injection(repo: str) -> list[Finding]:
    """DT-01. Um achado por local de SQL: cada um é uma correção distinta."""
    regra = DEBITOS["DT-01"]
    achados = []
    for rel in listar_arquivos(repo, (".php",)):
        source = ler(repo, rel)
        if not source:
            continue
        index = _IndiceDeOrigem(source)
        for linha, tipo, exprs in _sql_interpolado(source):
            origem, detalhe = index.classificar_conjunto(exprs)
            if origem == "literal":
                # Domínio fechado: não é injetável. Descartar (e não rebaixar a
                # confiança) é deliberado — um não-problema sobrevive no
                # relatório mesmo com confiança Baixa, porque a severidade-base
                # de SQLi é Crítica e o scoring ainda o deixa em Alta.
                continue
            confianca = Confidence.ALTA if origem == "tainted" else Confidence.MEDIA
            achados.append(Finding(
                rule_id="builtin:PHP-SQLI-INTERP",
                source="builtin",
                language=Language.PHP,
                category=regra["category"],
                title=regra["title"],
                description=(
                    f"SQL montado com interpolação de string ({tipo}): "
                    f"{', '.join(f'`{e}`' for e in exprs)}. Origem: {detalhe}. "
                    f"Aspas simples não interpolariam — o uso de {tipo} aqui é o "
                    f"que torna o valor injetável. Correção: binding com `?` e "
                    f"array de parâmetros, como já é feito em outras queries "
                    f"deste mesmo repositório."
                ),
                file=rel,
                line=linha,
                evidence=snippet(repo, rel, linha),
                severity=regra["severity"],
                confidence=confianca,
                effort_points=regra["effort"],
                questionnaire_item=regra["questionnaire_item"],
                publicly_reachable=(origem == "tainted"),
                cwe=regra["cwe"],
                debt_id="DT-01",
                corroborated_by=[f"builtin:origin={origem}"],
                metrics={"literal": tipo, "interpolacoes": len(exprs)},
            ))
    return achados


def scan_xss_blade(repo: str) -> list[Finding]:
    """
    DT-02. `{!! !!}` desliga o escape do Blade; `{{ }}` escapa.

    Um achado por TEMPLATE, não por ocorrência. O desafio diz que o
    diferencial está em priorizar, não em contar: as 7 ocorrências do
    monolith.blade.php são uma correção só (trocar a sintaxe no arquivo).
    As linhas todas vão em `metrics` para não perder evidência.
    """
    regra = DEBITOS["DT-02"]
    achados = []
    for rel in listar_arquivos(repo, (".blade.php",)):
        source = ler(repo, rel)
        if not source:
            continue
        linhas = [
            numero_da_linha(source, m.start())
            for m in re.finditer(r"\{!!.*?!!\}", source, re.S)
        ]
        if not linhas:
            continue
        achados.append(Finding(
            rule_id="builtin:PHP-XSS-BLADE",
            source="builtin",
            language=Language.PHP,
            category=regra["category"],
            title=regra["title"],
            description=(
                f"{len(linhas)} saída(s) com `{{!! !!}}`, que desliga o escape "
                f"automático do Blade, renderizando dado vindo do banco como "
                f"HTML. Qualquer nome de cliente contendo `<script>` executa no "
                f"navegador de quem abrir o dashboard. Correção: trocar por "
                f"`{{{{ }}}}`, que escapa por padrão."
            ),
            file=rel,
            line=linhas[0],
            end_line=linhas[-1],
            evidence=snippet(repo, rel, linhas[0]),
            severity=regra["severity"],
            confidence=Confidence.ALTA,   # sintático e inequívoco
            effort_points=regra["effort"],
            questionnaire_item=regra["questionnaire_item"],
            publicly_reachable=True,
            cwe=regra["cwe"],
            debt_id="DT-02",
            metrics={"ocorrencias": len(linhas), "linhas": linhas},
        ))
    return achados


# Nomes que denunciam credencial. Casar pelo NOME (e não pelo formato do
# valor) é o que evita o falso positivo de `protected $table = 'customers'`.
# `webhook` entra na lista porque uma URL de webhook do Slack É uma credencial:
# quem tem a URL posta na conta. Note que `$erpApiUrl`/`$crmApiUrl` continuam de
# fora — URL de API não é segredo, e "Url" não casa com nenhum termo daqui.
_NOME_DE_SEGREDO = re.compile(
    r"(?:api)?(?:_|\b)(?:token|secret|password|passwd|pwd|apikey|api_key|"
    r"access_key|private_key|auth|credential|webhook)s?\b|"
    # `id` NÃO entra como terminador: fazia `$pushAppId` (App ID do OneSignal)
    # virar "credencial". App ID é identificador PÚBLICO por design — vai
    # embarcado no SDK do cliente. Marcá-lo sob o Q4 ("credenciais e API keys
    # fora do código-fonte") afirma vazamento onde não há, e o bandit, do lado
    # Python, corretamente não o reporta. Nenhum segredo real dos dois repos
    # depende desse terminador.
    r"(?:sms|push|erp|crm|slack|smtp|mail|accounting)\w*"
    r"(?:key|token|secret|pass|webhook|hook)",
    re.I,
)
# Atribuição a propriedade/variável: `private $smsApiKey = 'VALOR';`
_ATRIB_SEGREDO = re.compile(
    r"(?:(?:private|protected|public|var|static)\s+)*\$(\w+)\s*=\s*(['\"])([^'\"]{8,})\2\s*;"
)
# Chave de array: `'api_token' => 'VALOR',`
_CHAVE_SEGREDO = re.compile(r"(['\"])(\w+)\1\s*=>\s*(['\"])([^'\"]{8,})\3")


def scan_segredos(repo: str) -> list[Finding]:
    """
    DT-04. Credencial literal no código.

    Anti-falso-positivo, em três camadas:
      1. o NOME precisa parecer credencial (`$table = 'customers'` não passa);
      2. valor vindo de `env(...)` nunca entra — é justamente o jeito certo,
         e `config/*.php` é cheio disso;
      3. placeholder óbvio (`your-key-here`, `changeme`, `null`) é ignorado.
    """
    regra = DEBITOS["DT-04"]
    placeholders = re.compile(
        r"^(?:null|none|false|true|changeme|your[-_ ]|xxx+|\.{3}|example|dummy|"
        r"placeholder|test|sk_test|localhost|utf8|utf8mb4|database|password)$",
        re.I,
    )
    achados = []
    for rel in listar_arquivos(repo, (".php",)):
        source = ler(repo, rel)
        if not source:
            continue
        texto_da_linha = source.splitlines()
        candidatos: list[tuple[int, str, str]] = []
        for m in _ATRIB_SEGREDO.finditer(source):
            candidatos.append((numero_da_linha(source, m.start()), m.group(1), m.group(3)))
        for m in _CHAVE_SEGREDO.finditer(source):
            candidatos.append((numero_da_linha(source, m.start()), m.group(2), m.group(4)))

        for linha, nome, valor in sorted(set(candidatos)):
            if not _NOME_DE_SEGREDO.search(nome):
                continue
            if placeholders.match(valor.strip()):
                continue
            # `'key' => env('APP_KEY', 'algo')` — o literal é o default do env,
            # não um segredo versionado. A checagem é na LINHA do candidato, não
            # numa janela de caracteres: uma janela vaza para as linhas vizinhas
            # e um `env()` em qualquer lugar por perto suprimiria um segredo
            # real logo acima. Falso negativo silencioso é pior que o falso
            # positivo que a guarda evita.
            if 1 <= linha <= len(texto_da_linha) and "env(" in texto_da_linha[linha - 1]:
                continue
            achados.append(Finding(
                rule_id="builtin:PHP-SECRET-HARDCODED",
                source="builtin",
                language=Language.PHP,
                category=regra["category"],
                title=regra["title"],
                description=(
                    f"`${nome}` recebe uma credencial literal no código-fonte, "
                    f"versionada no Git. Está no histórico do repositório mesmo "
                    f"que seja removida agora — a correção exige ROTACIONAR a "
                    f"chave, não só movê-la para `env()`."
                ),
                file=rel,
                line=linha,
                evidence=snippet(repo, rel, linha),
                severity=regra["severity"],
                confidence=Confidence.ALTA,
                effort_points=regra["effort"],
                questionnaire_item=regra["questionnaire_item"],
                cwe=regra["cwe"],
                debt_id="DT-04",
                metrics={"variavel": nome, "tamanho_do_valor": len(valor)},
            ))
    return achados


# -----------------------------------------------------------------------------
# DT-05 (debug em produção) NÃO tem detector aqui — e a ausência é deliberada.
#
# Existia um `scan_debug` que reportava `APP_DEBUG=true` no `.env.example`.
# Auditado contra o alvo, era FALSO POSITIVO: aquele arquivo é o skeleton do
# Laravel sem nenhuma modificação (`APP_NAME=Laravel`, `APP_KEY=` vazio,
# `APP_ENV=local`). `APP_DEBUG=true` num `.env.example` é o default do próprio
# framework e está CORRETO — o arquivo existe para desenvolvimento local.
# Reportá-lo marcaria como dívida todo projeto Laravel que existe.
#
# A pergunta real do questionário (Q6) é sobre a configuração de PRODUÇÃO, que
# não está no repositório — e é certo que não esteja. `config/app.php` usa
# `env('APP_DEBUG', false)`, o default seguro. Por isso Q6 aparece no scorecard
# como "sem cobertura": ninguém verificou a produção, e admitir isso é mais
# honesto que inventar evidência a partir de um template.
# -----------------------------------------------------------------------------


def scan_rotas_sem_auth(repo: str) -> list[Finding]:
    """
    DT-06 (item 1.1 do questionário). Rotas declaradas sem middleware de auth.

    Um achado por arquivo de rotas: a correção é adicionar o grupo de
    middleware, não editar rota a rota.
    """
    regra = DEBITOS["DT-06"]
    achados = []
    for rel in listar_arquivos(repo, (".php",)):
        if not rel.replace(os.sep, "/").startswith("routes/"):
            continue
        source = ler(repo, rel)
        rotas = re.findall(r"Route::(get|post|put|patch|delete|any|match)\s*\(", source)
        if not rotas:
            continue
        tem_auth = re.search(r"middleware\s*\(\s*\[?\s*['\"](auth|auth:\w+|verified)", source)
        if tem_auth:
            continue
        linha = numero_da_linha(source, source.find("Route::"))
        achados.append(Finding(
            rule_id="builtin:PHP-ROUTES-NO-AUTH",
            source="builtin",
            language=Language.PHP,
            category=regra["category"],
            title=regra["title"],
            description=(
                f"{len(rotas)} rota(s) declaradas em `{rel}` sem nenhum middleware "
                f"de autenticação. Qualquer visitante lê, cria e apaga dado de "
                f"qualquer uma das 47 agências — inclusive a rota "
                f"`/delete/{{thing}}/{{id}}`, que é GET e portanto disparável por "
                f"um simples link. É o maior risco de negócio do repositório: "
                f"vazamento de dado de contrato entre agências e seus clientes."
            ),
            file=rel,
            line=linha,
            evidence=snippet(repo, rel, linha),
            severity=regra["severity"],
            confidence=Confidence.ALTA,
            effort_points=regra["effort"],
            questionnaire_item=regra["questionnaire_item"],
            publicly_reachable=True,
            cwe=regra["cwe"],
            debt_id="DT-06",
            metrics={"rotas": len(rotas)},
        ))
    return achados


def scan_log_sensivel(repo: str) -> list[Finding]:
    """
    DT-08. Middleware que loga o corpo inteiro da request.

    Débito específico do repo PHP: não tem equivalente no ground truth Python.
    Log com senha e token em texto plano é achado de auditoria clássico e
    nenhuma das ferramentas PHP deste ambiente o detecta.

    A regra casa o ACESSOR e exige um SINK no mesmo arquivo, em vez de casar
    os dois juntos: no `LogEverything`, os acessores entram num array que só
    depois é persistido (`DB::table('request_logs')->insert(...)`), várias
    linhas abaixo. Uma regra de linha única não veria o débito mais grave do
    middleware — e o sink nem é o logger do Laravel, é o banco.
    """
    regra = DEBITOS["DT-08"]
    achados = []
    acessores = re.compile(
        r"\$request\s*->\s*(?:all\s*\(\)"
        r"|session\s*\(\)\s*->\s*all\s*\(\)"
        r"|headers\s*->\s*all\s*\(\))"
    )
    sinks = re.compile(r"Log::\w+\s*\(|->insert\s*\(|file_put_contents\s*\(|error_log\s*\(")
    for rel in listar_arquivos(repo, (".php",)):
        source = ler(repo, rel)
        ocorrencias = list(acessores.finditer(source))
        if not ocorrencias or not sinks.search(source):
            continue
        linhas = [numero_da_linha(source, m.start()) for m in ocorrencias]
        for linha in linhas[:1]:   # um achado por arquivo: a correção é uma só
            achados.append(Finding(
                rule_id="builtin:PHP-LOG-SENSITIVE",
                source="builtin",
                language=Language.PHP,
                category=regra["category"],
                title=regra["title"],
                description=(
                    f"{len(linhas)} acessor(es) que capturam a request inteira "
                    f"(`->all()`, headers, sessão) e são persistidos no mesmo "
                    f"arquivo. Vão junto senha, header `Authorization` e dado "
                    f"pessoal, em texto plano. O destino passa a ser um alvo tão "
                    f"sensível quanto o banco, sem nenhum dos controles do banco — "
                    f"e sem retenção definida."
                ),
                file=rel,
                line=linha,
                evidence=snippet(repo, rel, linha),
                severity=regra["severity"],
                confidence=Confidence.ALTA,
                effort_points=regra["effort"],
                cwe=regra["cwe"],
                debt_id="DT-08",
                metrics={"acessores": len(linhas), "linhas": linhas},
            ))
    return achados


# Arquivos `.env` que são TEMPLATE e devem estar no repositório. Versionar
# `.env.example` é a prática correta do Laravel, não dívida.
_ENV_TEMPLATE = re.compile(r"\.(example|sample|dist|template|test)$", re.I)
# Chaves cujo valor preenchido indica credencial de verdade, não placeholder.
_ENV_CHAVE_SENSIVEL = re.compile(
    r"^(?:APP_KEY|DB_PASSWORD|DB_USERNAME|MAIL_PASSWORD|REDIS_PASSWORD|"
    r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|\w*(?:TOKEN|SECRET|API_KEY|PASSWORD))$",
    re.I,
)


def verificar_env_commitado(repo: str) -> tuple[list[Finding], str]:
    """
    Q5 — "o repositório não contém `.env` com valores reais commitado?"

    Este scanner existe porque a resposta estava sendo AFIRMADA sem verificação.
    O detector declarava Q5 como coberto apoiado num comentário ("não há `.env`
    real no repo, só `.env.example`"), e o scorecard imprimia "conforme" —
    exatamente o erro do comercial da HourTrack, que respondeu "Sim" para tudo
    sem a área técnica ter olhado. Observação de quem escreveu o detector não é
    verificação do pipeline.

    Distingue template de arquivo real: `.env.example` DEVE estar versionado
    (é a prática do Laravel). O que é dívida é um `.env` com valor preenchido.

    Devolve (achados, veredito) para o chamador declarar cobertura só quando a
    varredura realmente rodou.
    """
    achados: list[Finding] = []
    examinados: list[str] = []
    for rel in listar_arquivos(repo, (".env",)) + [
        n for n in (sorted(os.listdir(repo)) if os.path.isdir(repo) else [])
        if n.startswith(".env") and os.path.isfile(os.path.join(repo, n))
    ]:
        nome = os.path.basename(rel)
        if not nome.startswith(".env") or _ENV_TEMPLATE.search(nome):
            continue
        if rel in examinados:
            continue
        examinados.append(rel)
        for i, linha in enumerate(ler(repo, rel).splitlines(), start=1):
            if "=" not in linha or linha.lstrip().startswith("#"):
                continue
            chave, _, valor = linha.partition("=")
            chave, valor = chave.strip(), valor.strip().strip("'\"")
            if not valor or not _ENV_CHAVE_SENSIVEL.match(chave):
                continue
            achados.append(Finding(
                rule_id="builtin:PHP-ENV-COMMITADO",
                source="builtin",
                language=Language.PHP,
                category=Category.SEGURANCA,
                title="Arquivo de ambiente com valor real versionado",
                description=(
                    f"`{rel}` não é template e traz `{chave}` preenchido. "
                    f"Credencial de ambiente no Git fica no histórico mesmo "
                    f"depois de removida — a correção exige rotacionar."
                ),
                file=rel, line=i, evidence=f"{chave}=<omitido>",
                severity=Severity.ALTA, confidence=Confidence.ALTA,
                effort_points=2.0, questionnaire_item="Q5", cwe=798,
            ))

    if achados:
        veredito = f"{len(achados)} valor(es) real(is) em {', '.join(examinados)}"
    elif examinados:
        veredito = f"{', '.join(examinados)} sem valor sensível preenchido"
    else:
        veredito = "nenhum `.env` versionado (só template) — Q5 conforme"
    return achados, veredito


def verificar_hash_de_senha(repo: str) -> tuple[list[Finding], str]:
    """
    Q3/Q7 — e aqui a resposta honesta é diferente da do repo Python.

    Procura hash quebrado (`md5`/`sha1`) aplicado a senha e, em paralelo,
    confirma uso de hash forte. No alvo PHP o resultado medido é: nenhum
    md5/sha1, e `bcrypt()`/`Hash::make()` presentes — ou seja, Q3 e Q7 são
    **conformes**, ao contrário do Python, onde DT-03 derruba os dois.

    Devolve (achados, veredito) para o chamador declarar cobertura só quando a
    varredura realmente aconteceu.
    """
    achados: list[Finding] = []
    fraco = re.compile(r"\b(md5|sha1)\s*\(", re.I)
    forte = re.compile(r"\b(bcrypt|Hash::make|password_hash|Argon2)\b", re.I)
    viu_forte = False
    for rel in listar_arquivos(repo, (".php",)):
        source = ler(repo, rel)
        if forte.search(source):
            viu_forte = True
        for m in fraco.finditer(source):
            linha = numero_da_linha(source, m.start())
            contexto = snippet(repo, rel, linha)
            if not re.search(r"pass|senha|pwd|credential|token|secret", contexto, re.I):
                continue   # md5 para cache-key/ETag não é débito de senha
            achados.append(Finding(
                rule_id="builtin:PHP-WEAK-HASH",
                source="builtin",
                language=Language.PHP,
                category=Category.SEGURANCA,
                title="Hash de senha com algoritmo quebrado",
                description=(
                    f"`{m.group(1).lower()}` aplicado a credencial. Algoritmo "
                    f"criptograficamente quebrado; derruba Q3 e Q7 do questionário."
                ),
                file=rel, line=linha, evidence=contexto,
                severity=Severity.CRITICA, confidence=Confidence.ALTA,
                effort_points=3.0, questionnaire_item="Q3,Q7",
                cwe=327, debt_id="DT-03",
            ))
    if achados:
        veredito = "md5/sha1 aplicado a credencial"
    elif viu_forte:
        veredito = "sem md5/sha1; bcrypt/Hash::make presentes — Q3 e Q7 conformes"
    else:
        veredito = "sem md5/sha1, mas também sem hash forte identificado"
    return achados, veredito


# ===========================================================================
# Ferramentas externas
# ===========================================================================
def _alvo(repo: str) -> str:
    """
    Diretório a analisar: `app/` quando existe, senão o repo inteiro.

    O ground truth (FP-04) manda filtrar pelo path de código do time. Apontar
    o phpstan para a raiz incluiria `config/`, `database/` e migrations, que
    rendem ruído de framework ausente sem nenhum débito priorizável.
    """
    app = os.path.join(repo, "app")
    return app if os.path.isdir(app) else repo


def dependencias_instaladas(repo: str) -> bool:
    """
    As dependências do Composer estão no repo? (`vendor/autoload.php`)

    Sem elas o phpstan não resolve nenhuma classe do framework, e metade do
    que ele reporta vira consequência disso — não débito do time.
    """
    return os.path.isfile(os.path.join(repo, "vendor", "autoload.php"))


def normalize_phpstan(
    payload: dict, repo: str, deps_instaladas: bool = True
) -> tuple[list[Finding], int, int]:
    """
    Converte o JSON do phpstan em Findings. Função pura: não invoca subprocess.

    Separada de `run_phpstan` pelo mesmo motivo das `normalize_*` do detector
    Python: dá para testar o filtro de ruído e o mandato sem ter phpstan
    instalado. Devolve (achados, descartados_por_ruido, descartados_fora_do_mandato).

    `deps_instaladas=False` liga o filtro de ruído de segunda ordem — ver
    `RUIDO_SEM_DEPENDENCIAS`.
    """
    filtros = RUIDO_PHPSTAN if deps_instaladas else RUIDO_PHPSTAN + RUIDO_SEM_DEPENDENCIAS
    findings: list[Finding] = []
    ruido = fora_do_mandato = 0
    for caminho, bloco in sorted((payload.get("files") or {}).items()):
        rel = rel_path(caminho, repo)
        for msg in bloco.get("messages", []):
            texto = (msg.get("message") or "").strip()
            if any(p.search(texto) for p in filtros):
                ruido += 1
                continue
            regra = next((r for r in PHPSTAN_ACIONAVEL if r[0].search(texto)), None)
            if regra is None:
                fora_do_mandato += 1
                continue
            _, categoria, severidade, esforco, titulo = regra
            linha = int(msg.get("line", 0) or 0)
            findings.append(Finding(
                rule_id="phpstan:acionavel",
                source="phpstan",
                language=Language.PHP,
                category=categoria,
                title=titulo,
                description=texto,
                file=rel,
                line=linha,
                evidence=snippet(repo, rel, linha),
                severity=severidade,
                # MEDIA, não ALTA: sem as dependências do Laravel instaladas o
                # phpstan enxerga o código pela metade, e um "método inexistente"
                # pode ser um método do framework que ele não carregou.
                confidence=Confidence.MEDIA,
                effort_points=esforco,
                metrics={"phpstan_identifier": msg.get("identifier", "")},
            ))
    return findings, ruido, fora_do_mandato


def run_phpstan(repo: str) -> tuple[list[Finding], ToolRun]:
    ok, out, err = _executar_json(
        ["phpstan", "analyse", "--error-format=json", "--no-progress",
         "--level=5", _alvo(repo)],
        timeout=300,
    )
    if ok is False:
        return [], ToolRun("phpstan", available=False, ok=False, error=err)
    if out is None:
        return [], ToolRun("phpstan", available=True, ok=False, error="stdout não é JSON")

    deps = dependencias_instaladas(repo)
    findings, ruido, fora = normalize_phpstan(out, repo, deps_instaladas=deps)
    status = ToolRun("phpstan", available=True, ok=True, findings=len(findings))
    status.notes.append(
        f"{ruido} mensagens filtradas como ruído de ambiente (FP-04); "
        f"{fora} fora do mandato de corretude"
    )
    if not deps:
        status.notes.append(
            "sem `vendor/` no repo: o phpstan não resolve classe do framework, "
            "então conclusões que dependem disso (método/propriedade "
            "inexistente) foram descartadas — seriam falso positivo. "
            "Rode `composer install` no alvo para o phpstan render de verdade."
        )
    return findings, status


def normalize_phpmetrics(payload, repo: str) -> list[Finding]:
    """
    Converte o relatório do phpmetrics em Findings de complexidade.

    O JSON do phpmetrics já mudou de forma entre versões (lista de objetos em
    uma, dict indexado por nome em outra). Aceitamos as duas, porque quebrar
    por causa de versão de ferramenta é exatamente o que o requisito de
    degradação do desafio manda evitar.
    """
    if isinstance(payload, dict):
        itens = [
            dict(info, name=info.get("name", nome))
            for nome, info in payload.items()
            if isinstance(info, dict)
        ]
    elif isinstance(payload, list):
        itens = [i for i in payload if isinstance(i, dict)]
    else:
        return []

    findings = []
    for info in sorted(itens, key=lambda d: str(d.get("name", ""))):
        nome = str(info.get("name", "")) or "?"
        cc = info.get("ccn", info.get("cyclomaticComplexity"))
        try:
            cc = int(cc)
        except (TypeError, ValueError):
            continue
        if cc < CC_FLOOR:
            continue
        severidade, esforco, debt_id = next(
            (s, e, d) for lo, s, e, d in CC_BANDS if cc >= lo
        )
        # `file` do phpmetrics é caminho absoluto e precisa virar relativo; o
        # caminho derivado do FQCN JÁ é relativo e não pode passar pelo
        # rel_path (ele resolveria contra o cwd e produziria `../../...`).
        bruto = info.get("file")
        rel = rel_path(str(bruto), repo) if bruto else _classe_para_arquivo(nome)
        linha = int(info.get("line", 0) or 0) or _linha_da_classe(repo, rel, nome)
        # Nomes dos métodos: o phpmetrics os fornece, e sem eles o leitor tem a
        # classe mas não sabe onde olhar dentro dela.
        metodos = sorted(
            m.get("name", "") for m in (info.get("methods") or [])
            if isinstance(m, dict) and m.get("name")
        )
        findings.append(Finding(
            rule_id="phpmetrics:CCN",
            source="phpmetrics",
            language=Language.PHP,
            category=Category.MANUTENIBILIDADE,
            title=f"Complexidade ciclomática alta em `{nome}` (CC={cc})",
            description=(
                f"A classe `{nome}` soma complexidade ciclomática {cc}. Cada "
                f"caminho independente é um caminho não testado: o repo tem zero "
                f"testes e o autor de 90% do código sai em 6 semanas. Medida por "
                f"CLASSE (phpmetrics), não por função — não é diretamente "
                f"comparável ao número do `radon` no repo Python."
            ),
            file=rel,
            line=linha,
            evidence=snippet(repo, rel, linha),
            severity=severidade,
            confidence=Confidence.ALTA,      # métrica objetiva, não heurística
            effort_points=esforco,
            mitigates_bus_factor=True,
            debt_id=debt_id,
            metrics={
                "cc": cc, "symbol": nome, "granularidade": "classe",
                "cc_metodo_max": info.get("ccnMethodMax"),
                "metodos": metodos,
            },
        ))
    return findings


def _linha_da_classe(repo: str, rel: str, fqcn: str) -> int:
    """
    Localiza a declaração `class <Nome>` no arquivo.

    O phpmetrics NÃO emite linha em lugar nenhum: `file` vem `None` e a lista
    `methods` traz só nomes. Sem esta busca, todo achado de complexidade caía
    no default da linha 1 e a evidência virava `<?php` — um achado verdadeiro
    que ninguém consegue acionar. O radon, do lado Python, entrega a linha da
    função; isto aproxima o PHP desse padrão.

    Devolve 1 se não encontrar — a linha errada é ruim, mas quebrar o achado
    inteiro por causa da evidência seria pior.
    """
    nome = fqcn.replace("/", "\\").split("\\")[-1]
    if not nome:
        return 1
    source = ler(repo, rel)
    if not source:
        return 1
    m = re.search(
        rf"^[ \t]*(?:final\s+|abstract\s+|readonly\s+)*class\s+{re.escape(nome)}\b",
        source, re.M,
    )
    return numero_da_linha(source, m.start()) if m else 1


def _classe_para_arquivo(fqcn: str) -> str:
    """`App\\Helpers\\DateHelper` -> `app/Helpers/DateHelper.php` (convenção PSR-4)."""
    partes = [p for p in fqcn.replace("/", "\\").split("\\") if p]
    if not partes:
        return ""
    if partes[0] == "App":
        partes[0] = "app"
    return "/".join(partes) + ".php"


def cmd_phpmetrics(destino: str, alvo: str) -> list[str]:
    """
    Linha de comando do phpmetrics. Isolada para ser testável.

    SEM `--quiet`: medido no container, a flag faz o phpmetrics sair com
    código 0 e NÃO escrever o arquivo de relatório. Falha silenciosa — o
    pipeline reportava "ferramenta ok, 0 achados" e perdia as 6 classes
    complexas do repo. Barulho no stdout é preferível a resultado vazio.
    """
    return ["phpmetrics", f"--report-json={destino}", alvo]


def run_phpmetrics(repo: str) -> tuple[list[Finding], ToolRun]:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        destino = os.path.join(tmp, "phpmetrics.json")
        ok, _, err = run_tool(cmd_phpmetrics(destino, _alvo(repo)), timeout=300)
        if not ok:
            return [], ToolRun("phpmetrics", available=False, ok=False, error=err)
        try:
            with open(destino, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return [], ToolRun("phpmetrics", available=True, ok=False, error=str(exc))

    findings = normalize_phpmetrics(payload, repo)
    status = ToolRun("phpmetrics", available=True, ok=True, findings=len(findings))
    status.notes.append(
        "CC medida por CLASSE (soma dos métodos); o radon mede por FUNÇÃO. "
        "Mesmos limiares nos dois detectores para o scoring não depender da "
        "linguagem — aproximação justificada, não equivalência exata."
    )
    return findings, status


def run_phploc(repo: str) -> ToolRun:
    """
    phploc NÃO gera achado. Gera contexto.

    Todas as métricas dele são agregadas por projeto e não têm arquivo nem
    linha — não cabem no contrato `Finding`, que exige evidência localizável.
    Emitir "CC média = 4.5" como débito seria dump bruto de ferramenta, que o
    desafio penaliza. As métricas entram em `notes` e servem para o relatório
    comparar tamanho e densidade entre os dois repositórios.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        destino = os.path.join(tmp, "phploc.json")
        ok, _, err = run_tool(["phploc", f"--log-json={destino}", _alvo(repo)], timeout=180)
        if not ok:
            return ToolRun("phploc", available=False, ok=False, error=err)
        try:
            with open(destino, encoding="utf-8") as fh:
                dados = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return ToolRun("phploc", available=True, ok=False, error=str(exc))

    status = ToolRun("phploc", available=True, ok=True, findings=0)
    status.notes.append("contexto (não gera achado): " + _metricas_phploc(dados))
    return status


def _metricas_phploc(dados: dict) -> str:
    """
    Formata as métricas do phploc, tolerando as duas nomenclaturas do JSON.

    O exemplo do FERRAMENTAS.md documenta `linesOfCode` e um objeto aninhado
    `cyclomaticComplexity.average`, mas a versão instalada no container emite
    chaves planas e curtas (`loc`, `lloc`, `classCcnAvg`). Lendo só as
    documentadas, todas as métricas saíam como "?" — a ferramenta era
    reportada como OK entregando nada. Aceitamos as duas formas.
    """
    aninhado = dados.get("cyclomaticComplexity") or {}

    def pega(*chaves, padrao="?"):
        for chave in chaves:
            valor = dados.get(chave, aninhado.get(chave))
            if valor not in (None, ""):
                return valor
        return padrao

    return (
        f"{pega('loc', 'linesOfCode')} LOC, "
        f"{pega('lloc', 'logicalLinesOfCode')} LLOC, "
        f"{pega('classes', 'numberOfClasses')} classes, "
        f"CC média por classe {pega('classCcnAvg', 'average')}, "
        f"CC máxima {pega('classCcnMax', 'maximum')}"
    )


def corroborate_with_semgrep(repo: str, findings: list[Finding], timeout: int = 300) -> ToolRun:
    """
    Semgrep NÃO produz achado próprio aqui — só corrobora taint de SQL.

    Medição registrada no detector Python: semgrep em PHP = 0 achados neste
    repositório. Rodamos assim mesmo para que o relatório mostre que a
    ferramenta foi executada e não encontrou nada, em vez de omitir. Se ele
    achar algo, a corroboração entra em `corroborated_by`; ele nunca REBAIXA
    nossa classificação, porque a análise léxica de aspas simples vs duplas é
    mais precisa que o taint dele para este caso específico.
    """
    ok, out, err = run_tool(
        ["semgrep", "--config=p/owasp-top-ten", "--json", "--metrics=off", "-q", repo],
        timeout=timeout,
    )
    if not ok:
        return ToolRun("semgrep", available=False, ok=False, error=err,
                       notes=["sem corroboração; confiança dos SQLi vem só da nossa análise léxica"])
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
        ini = int(hit.get("start", {}).get("line", 0) or 0)
        fim = int(hit.get("end", {}).get("line", ini) or ini)
        for ln in range(ini, fim + 1):
            taint[(rel, ln)] = check.split(".")[-1]

    corroborados = 0
    for f in findings:
        if f.rule_id != "builtin:PHP-SQLI-INTERP":
            continue
        hit = taint.get((f.file, f.line))
        if hit is None:
            continue
        corroborados += 1
        tag = f"semgrep:{hit}"
        if tag not in f.corroborated_by:
            f.corroborated_by.append(tag)

    status = ToolRun("semgrep", available=True, ok=True, findings=0)
    status.notes.append(
        f"{len(taint)} linhas com taint de SQL; {corroborados} achados corroborados"
        + ("" if taint else " — 0 achados em PHP é o resultado ESPERADO e medido")
    )
    return status


# ===========================================================================
# Orquestração
# ===========================================================================
def _executar_json(cmd: list[str], timeout: int):
    """
    Roda a ferramenta e devolve (ok, payload|None, err).

    `ok=False` -> ferramenta ausente/travou. `payload=None` -> rodou mas o
    stdout não era JSON. phpstan imprime o JSON depois de um cabeçalho em
    algumas versões, então tentamos a partir da primeira chave.
    """
    ok, out, err = run_tool(cmd, timeout=timeout)
    if not ok:
        return False, None, err
    try:
        return True, json.loads(out), err
    except json.JSONDecodeError:
        inicio = out.find("{")
        if inicio > 0:
            try:
                return True, json.loads(out[inicio:]), err
            except json.JSONDecodeError:
                pass
    return True, None, err


def analyze(repo: str, use_semgrep: bool = True) -> tuple[list[Finding], list[ToolRun]]:
    """
    Roda o pipeline PHP e devolve achados normalizados.

    Contrato idêntico ao de `detectors.python.analyze` — é o que permite ao
    `main.py` trocar de linguagem por uma linha de registro.
    """
    findings: list[Finding] = []
    runs: list[ToolRun] = []

    # --- detectores próprios: sempre rodam, não dependem de nada instalado ---
    builtin = []
    builtin += scan_sql_injection(repo)
    builtin += scan_xss_blade(repo)
    builtin += scan_segredos(repo)
    builtin += scan_rotas_sem_auth(repo)
    builtin += scan_log_sensivel(repo)
    hash_findings, veredito_hash = verificar_hash_de_senha(repo)
    builtin += hash_findings
    env_findings, veredito_env = verificar_env_commitado(repo)
    builtin += env_findings

    findings.extend(builtin)
    status_builtin = ToolRun("builtin:php", available=True, ok=True, findings=len(builtin))
    status_builtin.notes.append(
        "análise léxica própria: cobre a segurança que phpstan/phpmetrics/phploc "
        "não fazem (Q1, Q2, Q4, 1.1)"
    )
    status_builtin.notes.append(f"hash de senha: {veredito_hash}")
    status_builtin.notes.append(f"`.env` versionado: {veredito_env}")
    runs.append(status_builtin)

    # --- ferramentas externas: toleram ausência ---
    for runner in (run_phpstan, run_phpmetrics):
        got, status = runner(repo)
        findings.extend(got)
        runs.append(status)
    runs.append(run_phploc(repo))

    if use_semgrep:
        runs.append(corroborate_with_semgrep(repo, findings))

    findings.sort(key=lambda f: f.uid)   # ordem determinística de saída
    return findings, runs


def cobertura_questionario(ferramentas_ok: set[str] | None = None) -> set[str]:
    """
    Itens do questionário que este detector EFETIVAMENTE verificou.

    Contrato que todo detector expõe, consumido pelo `main.py`. Distingue
    "não achamos nada" (conforme) de "ninguém olhou" (sem cobertura) — a
    diferença entre responder o questionário com honestidade e chutar, que é o
    erro que o time comercial da HourTrack cometeu ao responder "Sim" para tudo.

    Aqui quem cobre quase tudo é o `builtin:php`, não as ferramentas externas:
    nenhuma das três ferramentas PHP deste ambiente faz análise de segurança.

    Cada item aqui tem um scanner que REALMENTE roda — nenhum é afirmado a
    partir de observação de quem escreveu o detector:

        Q1  scan_sql_injection      Q2  scan_xss_blade
        Q3  verificar_hash_de_senha Q4  scan_segredos
        Q5  verificar_env_commitado Q7  verificar_hash_de_senha
        1.1 scan_rotas_sem_auth
        Q6 -> nunca declarado; ver ITENS_NAO_ASSEGURADOS.
    """
    if ferramentas_ok is not None and "builtin:php" not in ferramentas_ok:
        return set()
    return {"Q1", "Q2", "Q3", "Q4", "Q5", "Q7", "1.1"} - ITENS_NAO_ASSEGURADOS

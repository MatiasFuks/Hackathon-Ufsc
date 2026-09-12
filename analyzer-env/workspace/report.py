"""
Renderização do relatório: Markdown (executivo) e JSON (máquina).

Duas audiências, dois artefatos
-------------------------------
`findings.json` é para máquina e é 100% determinístico — nenhuma linha dele
passa por IA.

`relatorio.md` é para o CEO, a diretoria e o time de produto da HourTrack, que
não são técnicos. Ele abre com a leitura de negócio e empurra a lista técnica
para um anexo no fim. A prosa pode vir do Gemini (ver `ai.py`); todo NÚMERO,
severidade, esforço e ordenação vem do pipeline determinístico. Sem chave de
API o relatório sai inteiro, com a narrativa estática deste módulo.

Determinismo
------------
Nenhuma saída carrega timestamp, caminho absoluto ou contagem dependente da
ordem de execução. Rodar duas vezes no mesmo repo produz bytes idênticos —
requisito do desafio. Se quiser data no relatório, passe `stamp=`.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import scoring
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

# Tradução de cada pergunta para linguagem de negócio — usada no relatório
# executivo, porque "Q1 falhou" não diz nada para a diretoria.
QUESTIONARIO_LEIGO: dict[str, str] = {
    "Q1": "um visitante pode alterar as consultas ao banco de dados e ler dados de qualquer cliente",
    "Q2": "conteúdo cadastrado por um cliente pode executar código no navegador de outro",
    "Q3": "as senhas dos usuários estão guardadas com proteção obsoleta",
    "Q4": "senhas de sistemas externos estão escritas dentro do código, visíveis a quem tem acesso ao repositório",
    "Q5": "arquivos de configuração com dados reais estão versionados",
    "Q6": "o modo de diagnóstico está ligado, expondo detalhes internos a quem acessa o site",
    "Q7": "o método de embaralhar senhas usado é reconhecidamente quebrado",
    "1.1": "o sistema não pede login para ver, criar ou apagar dados de clientes",
}

# Seção 2 do deck (SQLi + XSS) exige 100% de conformidade: qualquer "Não"
# bloqueia o contrato de R$ 8.000/mês. Não é "prioridade alta" — é bloqueador.
ITENS_BLOQUEANTES = {"Q1", "Q2"}

# Capacidade real do time (business-context.md): 2 devs, ~6 story points/semana.
SP_POR_SEMANA = 6.0

# Glossário de negócio por débito. É o fallback estático quando não há IA, e
# serve de âncora factual: a IA escreve melhor, mas não escreve nada aqui que
# contradiga isto.
GLOSSARIO: dict[str, dict[str, str]] = {
    "DT-01": dict(
        titulo="Consultas ao banco podem ser manipuladas de fora",
        o_que_e="Parte das buscas ao banco de dados é montada juntando texto digitado pelo visitante. "
                "Quem souber o formato consegue mudar a pergunta que o sistema faz ao banco.",
        consequencia="Vazamento dos dados de contratos de todos os 47 clientes, e reprovação imediata "
                     "no questionário do cliente enterprise.",
    ),
    "DT-02": dict(
        titulo="Conteúdo de um cliente roda no navegador de outro",
        o_que_e="O que os clientes digitam (nome, observação) é devolvido nas telas sem tratamento. "
                "Um texto malicioso cadastrado por um cliente é executado quando outro abre a tela.",
        consequencia="Roubo de sessão entre clientes concorrentes e reprovação no questionário.",
    ),
    "DT-03": dict(
        titulo="Senhas guardadas com proteção obsoleta",
        o_que_e="As senhas usam um método de embaralhamento abandonado pela indústria há mais de "
                "uma década. Ferramentas gratuitas revertem senhas comuns em segundos.",
        consequencia="Se o banco vazar, as senhas dos 180 usuários vazam junto — e muitas pessoas "
                     "repetem senha em outros sistemas.",
    ),
    "DT-04": dict(
        titulo="Senhas de sistemas externos escritas dentro do código",
        o_que_e="Acessos ao e-mail, ao SMS, ao ERP, ao CRM e ao sistema contábil estão digitados "
                "direto nos arquivos do sistema, versionados no repositório.",
        consequencia="Qualquer pessoa que já teve acesso ao código — incluindo quem sai da empresa — "
                     "mantém acesso a esses sistemas.",
    ),
    "DT-05": dict(
        titulo="Modo de diagnóstico ligado em produção",
        o_que_e="O sistema roda com o modo de desenvolvimento ativo, que mostra detalhes internos "
                "quando algo falha e, em certas condições, permite executar comandos no servidor.",
        consequencia="Um erro comum vira porta de entrada. A correção é de minutos.",
    ),
    "DT-06": dict(
        titulo="O sistema não pede login",
        o_que_e="As telas e os endereços que criam, listam e apagam dados não exigem autenticação. "
                "Quem tiver o endereço acessa.",
        consequencia="Qualquer pessoa na internet pode apagar horas faturáveis de qualquer cliente.",
    ),
    "DT-08": dict(
        titulo="Dados sensíveis gravados nos registros de acesso",
        o_que_e="O sistema registra o conteúdo completo das requisições, incluindo senhas e dados "
                "pessoais, em texto legível.",
        consequencia="O arquivo de log se torna uma segunda cópia dos dados sensíveis, sem proteção.",
    ),
    "DT-09": dict(
        titulo="Funções grandes demais para alterar com segurança",
        o_que_e="Algumas partes concentram muitas decisões em um só lugar. Mexer em uma coisa "
                "costuma quebrar outra.",
        consequencia="Cada nova funcionalidade fica mais lenta e mais arriscada de entregar.",
    ),
    "DT-11": dict(
        titulo="A função de datas faz coisas demais",
        o_que_e="Um único trecho cuida de formatar, validar e calcular datas, inclusive as do "
                "faturamento. É a parte mais complicada do sistema.",
        consequencia="Erro de data em fatura é erro de cobrança — e é o tipo de bug que o cliente "
                     "descobre antes da empresa.",
    ),
    "DT-17": dict(
        titulo="Falhas acontecem sem ninguém saber",
        o_que_e="Em vários pontos, quando algo dá errado o sistema simplesmente segue adiante e "
                "não registra nada.",
        consequencia="Problemas de cobrança e de envio passam semanas invisíveis. Sem monitoramento, "
                     "quem avisa é o cliente.",
    ),
    "DT-19": dict(
        titulo="Chamadas a sistemas externos sem limite de espera",
        o_que_e="As integrações não têm tempo máximo de resposta nem verificam se deram certo.",
        consequencia="Um sistema externo lento derruba a tela junto. E um envio que falhou é "
                     "contado como sucesso.",
    ),
    "DT-21": dict(
        titulo="Telas carregam todos os registros de uma vez",
        o_que_e="Não existe paginação: a tela principal busca tudo que existe no banco a cada acesso.",
        consequencia="Conforme a base cresce, a tela fica mais lenta para todos os clientes ao "
                     "mesmo tempo.",
    ),
    "DT-28": dict(
        titulo="Código que não faz nada",
        o_que_e="Trechos calculados e nunca usados, e anotações de tarefas pendentes antigas.",
        consequencia="Confunde quem assume o código — relevante com a saída do desenvolvedor "
                     "principal em 6 semanas.",
    ),
}

SEV_RANK = {Severity.CRITICA: 3, Severity.ALTA: 2, Severity.MEDIA: 1, Severity.BAIXA: 0}
CONF_RANK = {Confidence.ALTA: 2, Confidence.MEDIA: 1, Confidence.BAIXA: 0}


# ===========================================================================
# Ordenação, agregação e horizontes — tudo determinístico
# ===========================================================================
def ordenar_por_deteccao(findings: Iterable[Finding]) -> list[Finding]:
    """
    Ordem do `findings.json`: severidade, confiança, localização, uid.

    Independente do scoring de propósito — o JSON de achados é a saída da
    DETECÇÃO. Quem quer prioridade lê `scoring.json`. O uid no fim garante
    desempate estável entre execuções.
    """
    return sorted(
        findings,
        key=lambda f: (-SEV_RANK[f.severity], -CONF_RANK[f.confidence], f.file, f.line, f.uid),
    )


def ordenar_por_score(
    findings: Iterable[Finding], ctx: scoring.ScoringContext | None = None
) -> list[scoring.ScoredFinding]:
    """
    Ordem do relatório em Markdown: a do `scoring.py`, por score decrescente.

    O relatório não recalcula prioridade nem inventa critério próprio — ele
    consome o scoring determinístico. Era a heurística provisória daqui que
    saiu de cena.
    """
    return scoring.score_findings(list(findings), ctx or scoring.ScoringContext())


# `ordenar` continua apontando para a ordem de detecção: é o que o
# `render_json` usa e o que testes antigos esperam.
ordenar = ordenar_por_deteccao


def _itens_do_finding(finding: Finding) -> list[str]:
    """Um achado pode derrubar mais de um item ("Q3,Q7" no caso do MD5)."""
    if not finding.questionnaire_item:
        return []
    return [p.strip() for p in finding.questionnaire_item.split(",") if p.strip()]


def custos_por_horizonte(
    scored: Iterable[scoring.ScoredFinding],
) -> dict[str, dict[str, float]]:
    """
    Esforço somado por horizonte do scoring, convertido em semanas de time.

    Os horizontes são os três do deck (slide s2c) e vêm do `scoring.py` —
    este módulo não classifica nada, só soma.
    """
    buckets: dict[str, list[scoring.ScoredFinding]] = {h.value: [] for h in scoring.Horizon}
    for sf in scored:
        buckets[sf.horizon.value].append(sf)
    return {
        janela: {
            "achados": len(itens),
            "story_points": round(sum(sf.finding.effort_points for sf in itens), 1),
            "semanas": round(sum(sf.finding.effort_points for sf in itens) / SP_POR_SEMANA, 1),
        }
        for janela, itens in buckets.items()
    }


def scorecard(findings: Iterable[Finding], itens_cobertos: set[str]) -> list[dict[str, Any]]:
    """
    Situação honesta de cada pergunta do questionário.

    Três estados, e a distinção importa: ausência de achado NÃO é aprovação
    quando nenhum detector cobre a pergunta.

        falha         -> existe achado derrubando o item
        conforme      -> algum detector cobre o item e não achou nada
        sem_cobertura -> nenhum detector carregado sabe verificar isso
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
            "explicacao": QUESTIONARIO_LEIGO.get(item, ""),
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
        "semanas_de_time": round(sum(f.effort_points for f in findings) / SP_POR_SEMANA, 1),
        "por_categoria": por_categoria,
        "por_severidade": por_severidade,
        "por_confianca": por_confianca,
    }


def debitos_relevantes(findings: Iterable[Finding], limite: int = 6) -> list[tuple[str, int]]:
    """
    Débitos distintos mais graves, agrupados por `debt_id`.

    Agrupar importa: 7 achados de DT-01 são UM risco de negócio com 7
    evidências, não 7 riscos. Relatório para diretoria fala de riscos.
    """
    pior: dict[str, tuple[int, int]] = {}
    for f in findings:
        if not f.debt_id:
            continue
        rank, contagem = pior.get(f.debt_id, (-1, 0))
        pior[f.debt_id] = (max(rank, SEV_RANK[f.severity]), contagem + 1)
    ordenados = sorted(pior.items(), key=lambda kv: (-kv[1][0], kv[0]))
    return [(debt_id, dados[1]) for debt_id, dados in ordenados[:limite]]


# ===========================================================================
# JSON — saída da DETECÇÃO, sem IA, byte-idêntico entre execuções
# ===========================================================================
def render_json(
    findings: list[Finding],
    repo: dict[str, Any],
    tools: list[dict[str, Any]],
    itens_cobertos: set[str],
    stamp: str | None = None,
) -> str:
    """
    `findings.json` é o artefato da detecção: o que existe e onde.

    Prioridade, score e horizonte NÃO entram aqui — são do `scoring.json`.
    Duplicar os dois artefatos criaria duas fontes de verdade que podem
    divergir, que é o DT-12 do código-alvo.
    """
    ordenados = ordenar_por_deteccao(findings)
    payload = {
        "schema_version": 2,
        "repo": repo,
        "tools": tools,
        "summary": resumo(ordenados),
        "questionnaire": scorecard(ordenados, itens_cobertos),
        "findings": [f.to_dict() for f in ordenados],
    }
    if stamp:
        payload["generated_at"] = stamp
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# ===========================================================================
# Narrativa estática — o relatório tem que ficar completo sem IA
# ===========================================================================
_FURACAO = scoring.Horizon.FURACAO.value
_CURTO = scoring.Horizon.CURTO_PRAZO.value
_BACKLOG = scoring.Horizon.BACKLOG.value


def narrativa_estatica(
    scored: list[scoring.ScoredFinding], itens_cobertos: set[str]
) -> dict[str, Any]:
    findings = [sf.finding for sf in scored]
    sumario = resumo(findings)
    cartao = scorecard(findings, itens_cobertos)
    falhas = [q for q in cartao if q["estado"] == "falha"]
    bloqueios = [q for q in falhas if q["bloqueante"]]
    custos = custos_por_horizonte(scored)
    criticos = sum(1 for sf in scored if sf.priority is scoring.Priority.CRITICA)

    riscos = []
    for debt_id, contagem in debitos_relevantes(findings):
        verbete = GLOSSARIO.get(debt_id)
        if not verbete:
            continue
        riscos.append({
            "titulo": verbete["titulo"],
            "o_que_e": verbete["o_que_e"],
            "consequencia": verbete["consequencia"],
            "ocorrencias": contagem,
        })

    if bloqueios:
        situacao = (
            f"O questionário de segurança do cliente enterprise reprova em "
            f"{len(falhas)} dos {len(QUESTIONARIO)} itens. "
            f"{len(bloqueios)} deles são bloqueantes: o contrato de R$ 8.000/mês "
            f"não pode ser assinado enquanto existirem. Todo o trabalho do "
            f"primeiro horizonte custa {custos[_FURACAO]['story_points']} story "
            f"points, cerca de {custos[_FURACAO]['semanas']} semanas do time."
        )
    else:
        sem_cobertura = sum(1 for q in cartao if q["estado"] == "sem_cobertura")
        situacao = (
            f"Nenhum item bloqueante do questionário foi encontrado por este "
            f"pipeline. Atenção: {sem_cobertura} perguntas ficaram sem "
            f"verificação, o que não é o mesmo que estar conforme."
        )

    return {
        "resumo_executivo": (
            f"A análise automatizada encontrou {sumario['total']} débitos técnicos, "
            f"{criticos} deles de prioridade crítica. Corrigir tudo custaria "
            f"{sumario['esforco_total_story_points']} story points — cerca de "
            f"{sumario['semanas_de_time']} semanas de trabalho dos dois "
            f"desenvolvedores, o que não cabe nos prazos atuais. A boa notícia é "
            f"que o que trava o contrato do cliente enterprise é uma fração disso. "
            f"A recomendação é tratar essa fração primeiro e deixar o resto para "
            f"um roadmap estruturado."
        ),
        "situacao_do_contrato": situacao,
        "riscos": riscos,
        "plano_furacao": [
            f"Corrigir os {custos[_FURACAO]['achados']} itens do primeiro horizonte "
            f"({custos[_FURACAO]['story_points']} SP): é o que desbloqueia o "
            f"questionário e, com ele, o contrato.",
            "Não iniciar nenhuma refatoração estrutural durante os 14 dias da release.",
        ],
        "plano_curto_prazo": [
            f"Tratar os {custos[_CURTO]['achados']} itens de 4 a 8 semanas "
            f"({custos[_CURTO]['story_points']} SP).",
            "Escrever testes das rotinas de faturamento antes da saída do "
            "desenvolvedor principal, em 6 semanas.",
        ],
        "plano_backlog": [
            f"Roadmap estruturado para os {custos[_BACKLOG]['achados']} itens "
            f"restantes ({custos[_BACKLOG]['story_points']} SP).",
            "Reavaliar performance somente diante de incidente ou crescimento de base.",
        ],
        "nao_vamos_fazer": [
            "Reescrever o módulo principal — custo alto, sem prazo pressionando e sem "
            "testes para garantir que nada quebre.",
            "Otimizar performance agora — o sistema tem 99,1% de disponibilidade e 180 "
            "usuários; não é o gargalo do momento.",
        ],
        "recomendacao": (
            "Primeiro o que desbloqueia dinheiro: os itens que reprovam o questionário "
            "de segurança, porque o contrato de R$ 8.000/mês dobra a receita e tem prazo "
            "de 30 dias. Em paralelo, nada de refatoração durante os 14 dias da release, "
            "porque não há ambiente de teste nem cobertura automatizada — mudança grande "
            "vai direto para produção. Depois da release, testes das rotinas de "
            "faturamento, enquanto o desenvolvedor que conhece o código ainda está na "
            "empresa. Performance e reorganização do código ficam para o roadmap."
        ),
    }


def riscos_validados(
    riscos: list[dict[str, Any]], findings: Iterable[Finding]
) -> list[dict[str, Any]]:
    """
    Filtra os riscos escritos pela IA contra os achados reais.

    Duas coisas acontecem aqui, e as duas são defesa contra alucinação:

    1. Risco que não cita nenhum `debt_id` presente nos achados é DESCARTADO.
       Medido: a IA incluiu "saída do desenvolvedor principal" como risco —
       é fato do contexto de negócio, não achado desta análise. Sem este
       filtro, o relatório afirmaria à diretoria que o diagnóstico detectou
       algo que ele não detectou.
    2. A contagem de ocorrências é calculada AQUI, a partir dos achados, e
       nunca aceita da IA. A IA escreve a frase; o pipeline fornece o número.
    """
    contagem: dict[str, int] = {}
    for f in findings:
        if f.debt_id:
            contagem[f.debt_id] = contagem.get(f.debt_id, 0) + 1

    validados = []
    for risco in riscos:
        citados = [d for d in risco.get("debitos", []) if d in contagem]
        if not citados:
            continue
        validados.append({
            **risco,
            "debitos": sorted(citados),
            "ocorrencias": sum(contagem[d] for d in citados),
        })
    return validados


# ===========================================================================
# Markdown — relatório executivo + anexo técnico
# ===========================================================================
_ESTADO_MD = {
    "falha": "❌ **não**",
    "conforme": "✅ sem achado",
    "sem_cobertura": "⚠️ não verificado",
}


def render_markdown(
    findings: list[Finding],
    repo: dict[str, Any],
    tools: list[dict[str, Any]],
    itens_cobertos: set[str],
    stamp: str | None = None,
    narrativa: dict[str, Any] | None = None,
    ai_status: str = "narrativa estática",
    ctx: scoring.ScoringContext | None = None,
) -> str:
    scored = ordenar_por_score(findings, ctx)
    puros = [sf.finding for sf in scored]
    sumario = resumo(puros)
    cartao = scorecard(puros, itens_cobertos)
    custos = custos_por_horizonte(scored)
    texto = narrativa or narrativa_estatica(scored, itens_cobertos)
    if narrativa:
        # Riscos escritos pela IA passam pelo filtro de aterramento; se sobrar
        # nada, o relatório usa os riscos estáticos em vez de uma seção vazia.
        filtrados = riscos_validados(narrativa.get("riscos", []), puros)
        texto = {**texto, "riscos": filtrados or
                 narrativa_estatica(scored, itens_cobertos)["riscos"]}
    por_prioridade = {p.value: 0 for p in scoring.Priority}
    for sf in scored:
        por_prioridade[sf.priority.value] += 1

    out: list[str] = []
    add = out.append

    # ------------------------------------------------------------------ capa
    add("# Diagnóstico Técnico — HourTrack")
    add("")
    add(f"**Repositório analisado:** `{repo['name']}` "
        f"({', '.join(repo['languages'])}) · "
        f"**{sumario['total']} débitos** encontrados")
    if stamp:
        add(f"**Gerado em:** {stamp}")
    add("")
    add("Este documento é escrito para o time de produto e a diretoria. "
        "A lista técnica completa está no anexo, no fim.")
    add("")
    add("---")
    add("")

    # ---------------------------------------------------- resumo executivo
    add("## Resumo executivo")
    add("")
    add(texto["resumo_executivo"])
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Débitos encontrados | **{sumario['total']}** |")
    add(f"| Prioridade crítica | **{por_prioridade[scoring.Priority.CRITICA.value]}** |")
    add(f"| Custo para corrigir tudo | **{sumario['esforco_total_story_points']} story points** "
        f"≈ **{sumario['semanas_de_time']} semanas** de time |")
    add(f"| Itens do questionário reprovados | "
        f"**{sum(1 for q in cartao if q['estado'] == 'falha')} de {len(QUESTIONARIO)}** |")
    add("| Capacidade real do time | 6 story points por semana (2 devs) |")
    add("")

    # ------------------------------------------------------------- contrato
    add("## O contrato de R$ 8.000/mês")
    add("")
    add(texto["situacao_do_contrato"])
    add("")
    add("O cliente enterprise enviou sete perguntas. O time comercial respondeu "
        "\"sim\" para todas, sem revisão técnica. A situação real:")
    add("")
    add("| Pergunta | O que significa na prática | Situação |")
    add("|---|---|:---:|")
    for linha in cartao:
        marca = "🔒 " if linha["bloqueante"] else ""
        explicacao = linha["explicacao"] or linha["pergunta"]
        if linha["estado"] == "falha":
            explicacao = f"Hoje, {explicacao}"
        add(f"| {marca}**{linha['item']}** — {linha['pergunta']} | {explicacao} | "
            f"{_ESTADO_MD[linha['estado']]} |")
    add("")
    add("🔒 **Itens bloqueantes.** O cliente exige 100% de conformidade nestes dois. "
        "Qualquer \"não\" impede a assinatura, independentemente do resto.")
    add("")
    add("⚠️ **Não verificado** não quer dizer \"está tudo bem\". Quer dizer que "
        "nenhuma ferramenta deste diagnóstico sabe checar esse ponto — a resposta "
        "honesta ao cliente é que ainda não sabemos.")
    add("")

    # ---------------------------------------------------------------- riscos
    add("## Os principais riscos")
    add("")
    for i, risco in enumerate(texto["riscos"], start=1):
        ocorrencias = risco.get("ocorrencias")
        if ocorrencias:
            plural = "ocorrência" if ocorrencias == 1 else "ocorrências"
            sufixo = f" _({ocorrencias} {plural} no código)_"
        else:
            sufixo = ""
        add(f"**{i}. {risco['titulo']}**{sufixo}")
        add("")
        add(f"{risco['o_que_e']}")
        add("")
        add(f"→ *{risco['consequencia']}*")
        add("")

    # ----------------------------------------------------------------- custo
    add("## Quanto custa, e quando")
    add("")
    add("O time entrega cerca de 6 story points por semana. Essa é a restrição "
        "que define o plano — não a gravidade dos problemas.")
    add("")
    add("| Horizonte | Débitos | Esforço | Semanas de time |")
    add("|---|---:|---:|---:|")
    for janela in (_FURACAO, _CURTO, _BACKLOG):
        dados = custos[janela]
        add(f"| {janela} | {dados['achados']} | {dados['story_points']} SP | "
            f"{dados['semanas']} |")
    add(f"| **Total** | **{sumario['total']}** | "
        f"**{sumario['esforco_total_story_points']} SP** | "
        f"**{sumario['semanas_de_time']}** |")
    add("")
    add("> O horizonte de cada débito é calculado pelo scoring determinístico, a "
        "partir da prioridade, do esforço e das pressões de prazo da empresa. "
        "Nenhuma dessas janelas foi escolhida à mão.")
    add("")

    # ------------------------------------------------------------------ plano
    add("## Plano")
    add("")
    for chave, titulo in (("plano_furacao", f"{_FURACAO} — desbloquear contrato e release"),
                          ("plano_curto_prazo", f"{_CURTO} — destravar a próxima feature"),
                          ("plano_backlog", f"{_BACKLOG}")):
        add(f"### {titulo}")
        add("")
        for item in texto[chave]:
            add(f"- {item}")
        add("")

    add("### O que não vamos fazer agora")
    add("")
    for item in texto["nao_vamos_fazer"]:
        add(f"- {item}")
    add("")

    # ----------------------------------------------------------- recomendação
    add("## Recomendação")
    add("")
    add(texto["recomendacao"])
    add("")
    add("---")
    add("")

    # -------------------------------------------------------- anexo técnico
    add("# Anexo técnico")
    add("")
    add("A partir daqui o conteúdo é para os desenvolvedores.")
    add("")
    add(f"Narrativa das seções acima: {ai_status}. Todos os números, severidades, "
        f"esforços, prioridades e horizontes são calculados pelo pipeline "
        f"determinístico — nenhum deles passa por IA.")
    add("")

    add("## Ferramentas executadas")
    add("")
    add("| Ferramenta | Disponível | OK | Achados | Observação |")
    add("|---|:---:|:---:|---:|---|")
    for t in tools:
        nota = "; ".join(t.get("notes") or []) or t.get("error") or "—"
        add(f"| `{t['tool']}` | {'sim' if t['available'] else '**não**'} | "
            f"{'sim' if t['ok'] else 'não'} | {t['findings']} | {nota} |")
    add("")

    add("## Distribuição")
    add("")
    add("| Prioridade | Achados | | Categoria | Achados | | Confiança | Achados |")
    add("|---|---:|---|---|---:|---|---|---:|")
    prios = list(por_prioridade.items())
    cats = list(sumario["por_categoria"].items())
    confs = list(sumario["por_confianca"].items())
    for i in range(max(len(prios), len(cats), len(confs))):
        a = f"{prios[i][0]} | {prios[i][1]}" if i < len(prios) else " | "
        b = f"{cats[i][0]} | {cats[i][1]}" if i < len(cats) else " | "
        c = f"{confs[i][0]} | {confs[i][1]}" if i < len(confs) else " | "
        add(f"| {a} |  | {b} |  | {c} |")
    add("")
    add("**Confiança** é o quanto o pipeline acredita que o achado é real. "
        "Confiança baixa em severidade crítica costuma ser falso positivo de "
        "ferramenta — o scoring rebaixa o item em vez de descartá-lo.")
    add("")

    add("## Achados priorizados")
    add("")
    add("| ID | DT | Prioridade | Score | Horizonte | Categoria | Nome | Local | Sev. | Conf. | SP | CWE |")
    add("|---|---|---|---:|---|---|---|---|---|---|---:|---|")
    for sf in scored:
        f = sf.finding
        add(f"| `{f.uid}` | {f.debt_id or '—'} | **{sf.priority.value}** | "
            f"{sf.score:g} | {sf.horizon.value} | {f.category.value} | {f.title} | "
            f"`{f.location}` | {f.severity.value} | {f.confidence.value} | "
            f"{f.effort_points:g} | {('CWE-' + str(f.cwe)) if f.cwe else '—'} |")
    add("")

    add("## Detalhe dos achados")
    add("")
    for sf in scored:
        f = sf.finding
        add(f"### `{f.uid}` — {f.title}")
        add("")
        add(f"- **Local:** `{f.location}`")
        add(f"- **Prioridade:** {sf.priority.value} · **Horizonte:** {sf.horizon.value}")
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
        add(f"**Como o score foi calculado:** {' · '.join(sf.breakdown)}")
        add("")
        if f.evidence:
            add("```")
            add(f.evidence)
            add("```")
            add("")
    return "\n".join(out)

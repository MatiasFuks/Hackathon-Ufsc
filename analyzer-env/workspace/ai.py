"""
Enriquecimento do relatório com IA (Google Gemini).

Três regras que este módulo NÃO viola
-------------------------------------
1. A IA escreve PROSA, nunca número e nunca prioridade. Toda contagem,
   severidade, esforço e ordenação do relatório vem do pipeline determinístico.
   O desafio desclassifica priorização por LLM, e com razão: prioridade que
   muda entre execuções não é priorização.

2. Nenhum trecho de código sai da máquina. O payload enviado ao Gemini leva
   título, categoria, local (arquivo:linha) e contagens — NUNCA o campo
   `evidence`. Motivo concreto: as linhas de evidência do repo-alvo contêm
   credenciais hardcoded (DT-04). Mandá-las para uma API de terceiro seria
   vazar o segredo do cliente para fora enquanto escrevemos o relatório que
   denuncia justamente esse problema.

3. A chave de API é lida SEMPRE de variável de ambiente (`GOOGLE_API_KEY`):
   `gerar_narrativa` não conhece nenhuma outra fonte. Um `.env` local pode
   SEMEAR essa variável no arranque (`carregar_dotenv`), mas esse arquivo é
   ignorado pelo git e nunca entra no repositório — é o mesmo caminho que o
   FERRAMENTAS.md indica. Este pipeline reporta credencial hardcoded como
   débito crítico (DT-04); hardcodear a própria seria patético.

Determinismo com IA no meio
---------------------------
`temperature=0` reduz a variação, mas não garante saída idêntica. Quem garante
é o cache: a chave é o hash do payload + modelo + versão do prompt. Mesmo
repositório -> mesmo payload -> mesmo hash -> mesmo texto, sem nova chamada.
Commitar `.ai-cache/` torna o relatório reproduzível por quem não tem chave.

Sem chave, sem rede ou com quota estourada, o relatório sai inteiro com a
narrativa estática do `report.py`. A IA é enfeite, não dependência.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

# Modelos testados nesta conta, em ordem de preferência.
#
# ATENÇÃO: o FERRAMENTAS.md manda usar "gemini-1.5-flash", que foi RETIRADO
# (404 na API). "gemini-2.5-flash" também responde 404 para contas novas.
#
# `gemini-flash-lite-latest` vem primeiro por medição, não por preferência:
# com o prompt completo deste relatório, `gemini-flash-latest` não respondeu
# dentro dos 90s de timeout (provavelmente orçamento de raciocínio), enquanto
# o lite respondeu em segundos com prosa de qualidade equivalente para este
# uso. Os outros ficam como fallback.
MODELOS = ("gemini-flash-lite-latest", "gemini-flash-latest", "gemini-3-flash-preview")

# Muda quando o prompt muda, para invalidar o cache.
# v4: Furacão dividido em plano_release (0–14d) + plano_furacao (15–30d).
PROMPT_VERSION = "v4"

CACHE_DIR_PADRAO = ".ai-cache"

# Arquivo que semeia GOOGLE_API_KEY quando ela não está exportada no shell.
# Fica fora do git (ver .gitignore); o template versionado é o .env.example.
ARQUIVO_ENV = ".env"

# Timeout da chamada HTTP ao Gemini, em segundos.
#
# Sem isso a biblioteca espera indefinidamente e a IA deixa de ser enfeite:
# uma API pendurada trava o pipeline inteiro. Com timeout, o pior caso é o
# relatório sair com a narrativa estática — que é um relatório completo.
TIMEOUT_S = 90

# Chaves que o relatório espera de volta. Faltando qualquer uma, a resposta é
# descartada inteira e cai no texto estático — melhor seção estática do que
# seção vazia no meio de um relatório para diretoria.
SECOES = (
    "resumo_executivo",
    "situacao_do_contrato",
    "riscos",
    "plano_release",
    "plano_furacao",
    "plano_curto_prazo",
    "plano_backlog",
    "nao_vamos_fazer",
    "recomendacao",
)

# Fatos de negócio do business-context.md. Vão no prompt como CONTEXTO, para a
# IA escrever em linguagem de negócio — não para ela calcular nada.
CONTEXTO_NEGOCIO = """\
Empresa: HourTrack Ltda., SaaS B2B de controle de horas faturáveis, fundada em 2021.
- 47 agências clientes, ~180 usuários, R$ 28.000 de receita recorrente mensal.
- Time de 8 pessoas, dos quais apenas 2 desenvolvedores. Capacidade real: 6 story
  points por semana. Não há QA nem DevOps.
- O desenvolvedor que escreveu 90% do código sai da empresa em 6 semanas.
- Release v2.1 prometida para 14 dias a 3 clientes grandes; dois ameaçaram
  cancelar se atrasar.
- Cliente enterprise em negociação (GlobalConsult, 200+ usuários, R$ 8.000/mês,
  dobraria a receita) exige respostas a um questionário de segurança em 30 dias.
  A seção de SQL Injection e XSS exige 100% de conformidade: qualquer "não"
  bloqueia a assinatura.
- 3 dos 47 clientes respondem por 60% da receita.
- Sem ambiente de staging: deploy é git pull direto em produção. Sem
  monitoramento: os clientes avisam quando cai. Zero cobertura de testes.
- O sistema guarda dados de contratos entre as agências e os clientes delas;
  um vazamento pode gerar processo judicial.
"""

INSTRUCOES = """\
Você é um consultor de engenharia escrevendo para o CEO, a diretoria e o time de
produto da HourTrack. NENHUM deles é técnico.

Regras de escrita:
- Português do Brasil. Tom direto, adulto, sem alarmismo e sem vender serviço.
- PROIBIDO jargão técnico sem tradução: não escreva "SQL Injection", "XSS",
  "hash MD5", "N+1" sem explicar em linguagem comum o que significa na prática.
- Fale de consequência para o negócio: contrato, receita, cliente, processo,
  prazo, capacidade do time. Não fale de elegância de código.
- Nunca invente número. Use apenas os números que aparecem nos dados abaixo.
- A prioridade e o horizonte de cada achado já vêm calculados nos dados. Respeite-os:
  não promova nem rebaixe nada, e não sugira fazer antes o que está no backlog.
- Não repita a mesma frase em seções diferentes.
- Frases curtas. Sem "é importante notar que", sem "vale ressaltar".

Responda SOMENTE com um objeto JSON válido, sem cercas de código, com estas chaves:

{
  "resumo_executivo": "3 a 5 frases. O que foi encontrado e o que isso significa para a empresa agora.",
  "situacao_do_contrato": "2 a 4 frases sobre o questionário de segurança do cliente enterprise: o que reprova hoje e o que isso custa.",
  "riscos": [
    {"titulo": "nome curto, sem jargão",
     "o_que_e": "1 ou 2 frases explicando o problema para quem não é técnico",
     "consequencia": "1 frase: o que acontece com o negócio se nada for feito",
     "debitos": ["os códigos DT-xx da lista de achados que este risco resume"]}
  ],
  "plano_release": ["itens curtos, no imperativo: o que fazer nos 14 dias da release — corrigir os bloqueadores de contrato (o SQL Injection confirmado) e congelar refatorações estruturais, porque não há ambiente de teste"],
  "plano_furacao": ["itens curtos, no imperativo: a segurança crítica restante, para os dias 15 a 30 (depois da release entregue e antes da auditoria do contrato)"],
  "plano_curto_prazo": ["itens curtos: o que fazer em 4 a 8 semanas, incluindo preparar a saída do desenvolvedor principal"],
  "plano_backlog": ["itens curtos: o que entra no roadmap estruturado, sem urgência"],
  "nao_vamos_fazer": ["2 a 4 itens, cada um no formato 'o quê — por quê não agora'"],
  "recomendacao": "4 a 6 frases respondendo: se você fosse o CTO por um dia, o que faria primeiro e o que deixaria para depois, e por quê."
}

Em "riscos", escreva entre 4 e 6 itens, ordenados do mais grave para o menos grave.

Restrições de fidelidade — o relatório é auditado contra os dados:
- Todo risco tem que corresponder a achados REAIS da lista, e o campo "debitos"
  tem que citar os códigos DT-xx correspondentes. Risco que não cita débito
  válido é descartado automaticamente.
- NÃO transforme fato do contexto de negócio em risco. A saída do desenvolvedor,
  a falta de staging e a ausência de monitoramento são condições conhecidas da
  empresa, não achados desta análise. Use-as para justificar prioridade, nunca
  como item da lista de riscos.
- "nao_vamos_fazer" é sobre trabalho que ESTÁ nos achados e fica para depois.
  Não liste contratação, orçamento ou infraestrutura que não aparece nos dados.
- Não se contradiga entre seções: se o plano diz para fazer algo, a lista do
  que não será feito não pode dizer o contrário.
"""


def carregar_dotenv(caminho: str = ARQUIVO_ENV) -> list[str]:
    """
    Semeia variáveis de ambiente a partir de um `.env` local.

    Chamado uma vez no arranque do `main.py`. Existe só para poupar o
    `export` manual a cada shell novo — `gerar_narrativa` continua lendo
    exclusivamente de `os.environ`, e é isso que mantém a regra 3 do topo
    do módulo verdadeira: a chave não é lida de arquivo, ela é EXPORTADA
    por um arquivo antes de o pipeline começar.

    Duas decisões que importam:

    - Variável já definida (e não vazia) NUNCA é sobrescrita. Quem exporta
      na mão, ou passa pelo docker-compose, manda mais que o arquivo. O
      contrário faria um `.env` esquecido no disco vencer em silêncio a
      chave que você acabou de digitar — o pior tipo de bug de configuração,
      porque parece que funcionou.
    - Arquivo ausente, ilegível ou malformado não é erro. Quebrar aqui
      contrariaria a regra de que a IA é enfeite, não dependência: sem
      `.env` o relatório sai inteiro com a narrativa estática.

    Devolve os nomes das variáveis efetivamente definidas. O `main.py`
    ignora o retorno; o teste usa para distinguir "definiu" de "respeitou o
    que já estava no ambiente".
    """
    definidas: list[str] = []
    try:
        with open(caminho, encoding="utf-8") as fh:
            linhas = fh.readlines()
    except OSError:
        return definidas

    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        nome, _, valor = linha.partition("=")
        nome = nome.strip()
        if nome.startswith("export "):          # tolera a forma copiada do shell
            nome = nome[len("export "):].strip()
        valor = valor.strip()
        # Aspas são delimitador do arquivo, não parte do segredo. Uma chave
        # gravada como "AIza..." precisa chegar à API sem as aspas.
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "\"'":
            valor = valor[1:-1]
        # `.strip()` no que já existe: ambiente com valor vazio conta como
        # ausente, exatamente como `gerar_narrativa` o trata mais abaixo.
        if not nome or os.environ.get(nome, "").strip():
            continue
        os.environ[nome] = valor
        definidas.append(nome)
    return definidas


def montar_payload(
    findings: list[dict[str, Any]],
    resumo: dict[str, Any],
    questionario: list[dict[str, Any]],
    repo: dict[str, Any],
) -> dict[str, Any]:
    """
    Monta o que é enviado à IA. Determinístico e sem código-fonte.

    `evidence` é deliberadamente removido de cada achado — ver regra 2 no
    topo do módulo. Também não vai `description` bruta da ferramenta, que às
    vezes embute o trecho da query.
    """
    achados_limpos = [
        {
            "titulo": f["title"],
            "categoria": f["category"],
            "local": f"{f['file']}:{f['line']}",
            "severidade": f["severity"],
            "confianca": f["confidence"],
            "esforco_sp": f["effort_points"],
            "item_questionario": f["questionnaire_item"],
            "debito": f["debt_id"],
            # Prioridade e horizonte vêm do scoring determinístico. A IA os
            # RECEBE para escrever coerente com eles; ela não os calcula nem
            # tem autoridade para contestá-los.
            "prioridade": f.get("priority"),
            "horizonte": f.get("horizon"),
        }
        for f in findings
    ]
    return {
        "repositorio": {"nome": repo["name"], "linguagens": repo["languages"]},
        "resumo": resumo,
        "questionario": [
            {"item": q["item"], "pergunta": q["pergunta"],
             "estado": q["estado"], "bloqueante": q["bloqueante"]}
            for q in questionario
        ],
        "achados": achados_limpos,
    }


def _chave_de_cache(payload: dict[str, Any], modelo: str) -> str:
    bruto = json.dumps(
        {"payload": payload, "modelo": modelo, "prompt": PROMPT_VERSION},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(bruto.encode("utf-8")).hexdigest()[:16]


def _validar(dados: Any) -> dict[str, Any] | None:
    """Resposta da IA só é aceita completa. Meia resposta = texto estático."""
    if not isinstance(dados, dict):
        return None
    if any(chave not in dados for chave in SECOES):
        return None
    if not isinstance(dados["riscos"], list) or not dados["riscos"]:
        return None
    for risco in dados["riscos"]:
        if not isinstance(risco, dict):
            return None
        if not all(k in risco for k in ("titulo", "o_que_e", "consequencia", "debitos")):
            return None
        if not isinstance(risco["debitos"], list):
            return None
    for chave in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
        if not isinstance(dados[chave], list):
            return None
    return dados


def _extrair_json(texto: str) -> Any:
    """A IA às vezes devolve o JSON dentro de cercas ```json. Tolera os dois."""
    limpo = texto.strip()
    if limpo.startswith("```"):
        limpo = limpo.split("\n", 1)[1] if "\n" in limpo else limpo
        limpo = limpo.rsplit("```", 1)[0]
    inicio, fim = limpo.find("{"), limpo.rfind("}")
    if inicio == -1 or fim == -1:
        raise ValueError("resposta sem objeto JSON")
    return json.loads(limpo[inicio:fim + 1])


def gerar_narrativa(
    payload: dict[str, Any],
    cache_dir: str = CACHE_DIR_PADRAO,
    modelo: str | None = None,
    permitir_chamada: bool = True,
) -> tuple[dict[str, Any] | None, str]:
    """
    Devolve (narrativa, status). `narrativa=None` faz o relatório usar o
    texto estático — nunca é erro fatal.

    Ordem: cache -> API -> nada. O cache é consultado antes de qualquer
    chamada, então rodar duas vezes seguidas não gasta quota nem muda o texto.
    """
    modelos = (modelo,) if modelo else MODELOS
    chave = _chave_de_cache(payload, modelos[0])
    destino = os.path.join(cache_dir, f"{chave}.json")

    if os.path.isfile(destino):
        try:
            with open(destino, encoding="utf-8") as fh:
                dados = _validar(json.load(fh))
            if dados:
                return dados, f"cache ({chave})"
        except (OSError, json.JSONDecodeError):
            pass

    if not permitir_chamada:
        return None, "IA desativada (--no-ai); narrativa estática"

    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not api_key:
        return None, "GOOGLE_API_KEY não definida; narrativa estática"

    try:
        import google.generativeai as genai
    except ImportError:
        return None, "google-generativeai não instalado; narrativa estática"

    genai.configure(api_key=api_key)
    prompt = (
        f"{INSTRUCOES}\n\n=== CONTEXTO DE NEGÓCIO ===\n{CONTEXTO_NEGOCIO}\n"
        f"=== DADOS DA ANÁLISE (não invente nada fora daqui) ===\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)}\n"
    )

    erros = []
    for nome in modelos:
        try:
            cliente = genai.GenerativeModel(nome)
            resposta = cliente.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.0,        # menos variação entre execuções
                    "max_output_tokens": 8000,
                    "response_mime_type": "application/json",
                },
                request_options={"timeout": TIMEOUT_S},
            )
            dados = _validar(_extrair_json(resposta.text))
            if dados is None:
                erros.append(f"{nome}: resposta incompleta")
                continue
            os.makedirs(cache_dir, exist_ok=True)
            with open(destino, "w", encoding="utf-8") as fh:
                json.dump(dados, fh, ensure_ascii=False, indent=2, sort_keys=True)
            return dados, f"{nome} (novo, cacheado em {chave})"
        except Exception as exc:                # noqa: BLE001 - IA nunca derruba o pipeline
            erros.append(f"{nome}: {type(exc).__name__}")

    return None, "IA falhou (" + "; ".join(erros) + "); narrativa estática"

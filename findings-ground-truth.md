# Findings Ground Truth — HourTrack (`bad-codebase-python`)

> **O que é este documento.** Inventário **manual e verificado** dos débitos técnicos reais do
> código-alvo Python. Ele serve a dois propósitos:
>
> 1. **Espinha dorsal da Entrega 1** (relatório) — a lista de débitos com evidência (arquivo:linha).
> 2. **Oráculo de validação da Entrega 2** (pipeline) — referência para medir se o
>    `bandit`/`radon`/`pylint`/`semgrep` detectam os achados reais, e o que só o julgamento humano pega.
>
> **A prioridade final NÃO é definida aqui.** Ela é calculada pelo `scoring.py` determinístico.
> Este documento entrega: *detecção* (o que existe e onde), *mapeamento ferramenta × julgamento*,
> *impacto de negócio* e *horizonte sugerido*. A severidade listada é a severidade-base de entrada
> do scoring, não a prioridade de saída.

---

## Como ler

- **Detectável por:** quais ferramentas pegam o achado (com ID/severidade esperados) — coluna que
  vira teste de regressão do pipeline. `—` = nenhuma ferramenta pega; é **julgamento humano/IA**.
- **Questionário:** se o achado derruba uma resposta do `security-questionnaire.md` / do deck.
- **Horizonte:** 🌀 Furacão (0–30d, desbloqueia release/contrato) · 🔧 4–8 semanas (destrava a
  próxima feature / prepara a saída do dev) · 🚀 Backlog (roadmap estruturado).

> ⚠️ Os débitos que só o julgamento humano pega (`—` na coluna de detecção) são os de **maior valor
> de pontuação**: são a matéria-prima da seção obrigatória *"o que a IA/ferramenta errou"*.

---

## Scorecard do questionário de segurança (cliente enterprise — 30 dias)

O comercial respondeu **"Sim" para tudo**. O código diz outra coisa. Conformidade honesta **hoje**:

| # | Pergunta | Resposta real | Débito |
|---|---|:---:|---|
| Q1 | Protegido contra **SQL Injection**? | ❌ **NÃO** | DT-01 |
| Q2 | Protegido contra **XSS**? | ❌ **NÃO** | DT-02 |
| Q3 | Senhas com hash seguro (bcrypt/PBKDF2/Argon2)? | ❌ **NÃO** | DT-03 |
| Q4 | Credenciais/API keys **fora do código-fonte**? | ❌ **NÃO** | DT-04 |
| Q5 | Repo **sem `.env` com valores reais** commitado? | ✅ **SIM** | — (ver FP-02) |
| Q6 | Modo **debug desativado** em produção? | ❌ **NÃO** | DT-05 |
| Q7 | Não usa **MD5/SHA-1** para dados sensíveis? | ❌ **NÃO** | DT-03 |
| 1.1\* | Exige **autenticação** para acessar dados de clientes? | ❌ **NÃO** | DT-06 / DT-07 |

**Resultado: 6 dos 7 "Sim" do comercial estão errados** (+ o item de autenticação do deck).
O único honesto — Q5 — está certo por acaso: não há `.env` commitado… porque os segredos estão
**hardcoded direto no `.py`** (o que é pior, e cai no Q4).

> \* Item 1.1 aparece na seccionada do deck (slide s2b), não na lista plana do `.md`. O deck também
> afirma: **Seção 2 (OWASP: SQLi + XSS) exige 100% de conformidade — qualquer "Não" bloqueia o
> contrato.** Ou seja, DT-01 e DT-02 não são "alta prioridade": são **bloqueadores absolutos**.

---

## 🔒 Segurança

| ID | Nome | Onde (arquivo:linha) | O que está errado | Detectável por | Quest. | Horizonte |
|---|---|---|---|---|:---:|:---:|
| **DT-01** | SQL Injection via f-string | `app/routes/report_routes.py:38` (`customer_id`), `:39,:52` (`month`), `:109`; `app/everything.py:226`; `app/models/customer.py:38-44`; `app/services/billing_service.py:27-33` | Parâmetros de request interpolados direto na query com f-string. O pior: `report_routes.py:38` injeta `customer_id` cru, alcançável via `GET /api/reports/monthly?customer_id=...` | `bandit` **B608** · `semgrep` `formatted-sql-query` | Q1 | 🌀 |
| **DT-02** | XSS armazenado | `app/everything.py` (dashboard inteiro, HTML por f-string s/ escape, ex. `:99,:116-128,:143-144`); `app/routes/report_routes.py:71-78` (`format=html`) | Dados do banco renderizados sem `escape()`. A seed inclui um cliente `<script>alert(1)</script>` (`Dockerfile:53`) → XSS **confirmado**, não teórico | `semgrep` (parcial) · `bandit` **não pega** HTML artesanal | Q2 | 🌀 |
| **DT-03** | Hash de senha MD5 | `app/everything.py:165-168` (`hashlib.md5`); seed `e10adc...` = `md5("123456")` em `Dockerfile:55-56` | MD5 é criptograficamente quebrado; sem salt. Derruba Q3 **e** Q7 de uma vez | `bandit` **B324** (HIGH) | Q3,Q7 | 🌀 |
| **DT-04** | Segredos hardcoded no código | `app/services/notification_service.py:9-15` (SMTP/SMS/OneSignal); `app/routes/report_routes.py:103` (token Contabilizei); `sync_data.py:10,13,15` (ERP/CRM/Slack); `app/everything.py:6` (`DEFAULT_PASSWORD='123456'`) | Chaves de produção versionadas no Git. `sync_data.py:27` ainda **loga o token em texto plano** no erro | `bandit` **B105/B106** (pega a senha; chaves parcial) · `semgrep` (regras de secret) | Q4 | 🌀 |
| **DT-05** | Debug ligado em produção | `run.py:4` (`app.run(debug=True)`) | Expõe o console interativo do Werkzeug (**RCE** via PIN) e stack traces com dados. Correção trivial, impacto enorme | `bandit` **B201** | Q6 | 🌀 |
| **DT-06** | Ausência de autenticação | `app/everything.py:152` (`save`), `:195` (`delete`), todas as rotas de `report_routes.py` | Nenhum login. Qualquer pessoa na rede cria, lê e apaga dados | **—** (regra de negócio; ferramenta não infere) | 1.1 | 🌀→🔧 |
| **DT-07** | Sem autorização / isolamento multi-tenant | `app/everything.py:195-207` (`delete` sem checar dono); dados de 47 clientes no mesmo banco sem escopo | "Qualquer usuário pode ver e **deletar** dados de qualquer cliente" (business-context). **Maior risco de negócio**: vazamento → processo; 3 clientes = 60% da receita | **—** (julgamento) | 1.1 | 🌀→🔧 |
| **DT-08** | Exposição de dado sensível | `app/everything.py:44-45` (`SELECT *` em `users` devolve hash de senha) | Hash de senha trafega para a view/resposta. `SELECT *` em toda query | **—** (parcial `semgrep`) | — | 🔧 |

---

## 🏗️ Design / Arquitetura / Manutenibilidade

| ID | Nome | Onde | O que está errado | Detectável por | Horizonte |
|---|---|---|---|---|:---:|
| **DT-09** | God object `everything.py` | `app/everything.py` (arquivo todo); `dashboard():39` | Rota + SQL + HTML + regra de negócio no mesmo módulo | `radon` CC `dashboard`=**16** · `pylint` too-many-* | 🔧→🚀 |
| **DT-10** | Lógica de negócio na view | `app/everything.py:116-128` | Recalcula `hours * hourly_rate` no HTML em vez de usar `e['total']` já computado | **—** | 🚀 |
| **DT-11** | `handle_date` faz tudo | `app/helpers/date_helper.py:8` | Dispatcher gigante por string. **CC=29 (F)**. Falhas silenciosas: `diff_days` retorna `-1` (colide com valor válido); `format` devolve a entrada em parse ruim. Usado no faturamento → risco de correção | `radon` CC=**29 (F)** · `pylint` too-many-branches/returns | 🔧 |
| **DT-12** | Duplicação divergente | `report_routes.monthly()` vs `everything.report()` (queries diferentes → **números divergentes**); `notification_service.py:86` `format_message` vs `:98` `build_message`; `date_helper.py:91` `is_valid` vs `handle_date`; `sync_data.py:77` copia `:18` | Mesma lógica reimplementada com variações → inconsistência de dados | `pylint` **R0801** (duplicate-code) | 🔧 |
| **DT-13** | Polimorfismo quebrado | `app/models/customer.py:12-16`, `app/models/billing_category.py:12-17` (`get_display_name` com formatos diferentes); `billing_category.py:38-52` (`get_most_used` devolve `dict`, não o objeto) | Código que chama o "mesmo" método em entidades diferentes quebra silenciosamente | **—** (julgamento) | 🚀 |
| **DT-14** | Acesso a banco espalhado (sem repository) | `customer.py:18,35`; `billing_category.py:38` | Models/services abrem a própria conexão SQLite → sem camada de dados, acopla tudo ao SQLite | **—** (parcial `pylint`) | 🔧→🚀 |

---

## 🐛 Correção / Integridade de dados — *os que ferramenta nenhuma pega*

> Esta seção é o **diferencial competitivo**: bandit/radon/pylint/semgrep **não detectam** nada aqui,
> porque exigem entender o schema e a intenção de negócio. São os achados mais valiosos do relatório.

| ID | Nome | Onde | O que está errado | Impacto de negócio | Horizonte |
|---|---|---|---|---|:---:|
| **DT-15** | Escreve em tabela inexistente (erro engolido) | `billing_service.py:71-78` (`INSERT INTO invoices`); `notification_service.py:74-82` (`INSERT INTO notifications`) | As tabelas `invoices`/`notifications` **não existem** no schema (`Dockerfile`), e o `except: pass` engole o erro | **Fatura é calculada mas nunca salva.** Feature de faturamento silenciosamente meia-quebrada — o negócio é faturamento | 🌀→🔧 |
| **DT-16** | Taxa hardcoded no export contábil | `app/routes/report_routes.py:121` (`'valor': row['hours'] * 150`) | Usa `150` fixo em vez da `hourly_rate` da categoria (que varia 100/150/200) | **Envia valores errados para o sistema fiscal/contábil** — risco financeiro e de compliance | 🔧 |
| **DT-17** | Falhas silenciosas (`except: pass`) | `billing_service.py:77`; `notification_service.py:41,50,62,81`; `report_routes.py:127`; `sync_data.py:73,85` | Exceções engolidas em toda parte | Perda de dados e falhas sem nenhum sinal — impossível diagnosticar em prod (que não tem monitoramento) | 🔧 |
| **DT-18** | Regras de desconto mágicas | `app/services/billing_service.py:56-59` | Descontos por **nome de cliente** hardcoded (`'Cogna'` 15%, `'special_discount'` 8%) enterrados no `if` | Regra de faturamento não-testável e frágil; muda receita de cliente específico | 🚀 |
| **DT-19** | HTTP fire-and-forget | `report_routes.py:116`; `notification_service.py:44,53` | Ignora a resposta HTTP e não tem `timeout`; `exported` conta tentativas, não sucessos | Export "bem-sucedido" que não chegou; relatório mente para o usuário | 🚀 |

---

## 🐢 Performance

| ID | Nome | Onde | O que está errado | Detectável por | Horizonte |
|---|---|---|---|---|:---:|
| **DT-20** | N+1 queries | `everything.py:55-65` (3 queries/lançamento); `billing_service.py:112-113` (1 `calculate_invoice`/cliente); `report_routes.py:89-93` (`annual` = **O(12·n)**); `customer.py:18,35` por linha | Explosão de queries ao banco | **—** (ferramenta não detecta N+1) | 🚀 |
| **DT-21** | Sem paginação | `everything.py:83` (TODO), `MAX_ROWS:8` definido e nunca usado | Dashboard carrega todas as linhas | `pylint` fixme/unused | 🚀 |
| **DT-22** | Conexões sem gerenciamento | `everything.py:31-35` (`get_db` sem context manager, rotas nunca fecham) | Conexão por chamada, sem pool; pode vazar | `pylint` consider-using-with | 🔧 |
| **DT-23** | Sem cache, query por request | `everything.py:211` (`/api/report`) | Recomputa tudo a cada chamada | **—** | 🚀 |
| **DT-24** | Ordenação/agregação em Python | `billing_service.py:118` (`report.sort(...)`) | Ordena em Python em vez de `ORDER BY` | **—** | 🚀 |

> **Nota de priorização:** uptime é 99,1% e a base é pequena (180 usuários). Performance **não está
> pegando fogo** hoje → quase tudo aqui é 🚀 Backlog. Reportar perf como "Crítica" sem incidente
> seria priorização fraca. (`DT-22` sobe para 🔧 por risco de vazamento de conexão em prod.)

---

## ⚙️ Processo / Qualidade

| ID | Nome | Onde | O que está errado | Detectável por | Horizonte |
|---|---|---|---|---|:---:|
| **DT-25** | Zero testes | `requirements.txt:4` (`pytest` listado, nada escrito) | Sem rede de segurança + sem staging + deploy direto em prod + **dev que escreveu 90% sai em 6 semanas** | **—** (ausência) | 🔧 |
| **DT-26** | Sem versionamento de API | `everything.py:230` | `/api/report` em vez de `/api/v1/report` | **—** | 🚀 |
| **DT-27** | Sem log de auditoria | `everything.py:190` (comentário); `save`/`delete` sem trilha | Não há rastro de quem criou/deletou dado de contrato | **—** | 🔧 |
| **DT-28** | Dead code | `everything.py:76-79` (4 vars não usadas); `billing_category.py:19` (`get_effective_rate` não usado) | Código morto confunde manutenção | `pylint` **W0612** unused-variable | 🚀 |
| **DT-29** | Sem validação de input | `everything.py:152` (`save` aceita `hours`/`date`/`rate` crus) | Dados inválidos entram no banco | **—** (parcial) | 🔧 |

---

## 🚫 Armadilhas de falso positivo (NÃO reportar — ou reportar com cuidado)

> Falso positivo **desconta ponto**. O desafio plantou estas armadilhas de propósito.

| ID | Armadilha | Por que é FALSO no repo Python |
|---|---|---|
| **FP-01** | "`database.sqlite` commitado no repo" | **Não está.** É criado em build time no `Dockerfile`. O business-context fala disso de forma **geral** (vale para o PHP). Reportar no Python = penalidade |
| **FP-02** | "`.env` com valores reais commitado" | **Não há `.env`** no repo Python. O `docker-compose.yml:6` referencia `env_file: .env`, mas o arquivo não existe. Os segredos estão hardcoded no `.py` (isso é o DT-04, não um `.env`) |
| **FP-03** | "Todo SQL é injetável" | **Falso.** Os `INSERT` de `everything.py:159-187` e de `sync_data.py` usam `?` (parametrizados, **seguros**). Só os que usam **f-string** (DT-01) injetam. Um scan que marca tudo gera FP |
| **FP-04** | `phpstan`: "unknown class `Illuminate\*`" (bônus PHP) | Ruído por faltarem as deps do Laravel no container. **Filtrar no pipeline** — não é débito real (documentado no `FERRAMENTAS.md`) |
| **FP-05** | Ruído de ferramenta elevado a "débito crítico" | `fixme`/TODO (`pylint`), `request_without_timeout` (`bandit` B113 em `notification_service`): são sinais válidos, mas **baixo impacto de negócio**. Mantê-los no JSON do pipeline, **sem elevar** a prioridade |

---

## Matriz de cobertura — ferramenta × achado (oráculo de regressão do pipeline)

Use esta tabela para validar o pipeline: se o `bandit` não reportar B324/B201/B105, há bug.

| Ferramenta | Achados que **deve** pegar | IDs esperados |
|---|---|---|
| `bandit` | MD5 (DT-03), debug (DT-05), senha hardcoded (DT-04), SQLi por string (DT-01), except-pass (DT-17), requests s/ timeout (DT-19) | B324, B201, B105/B106, B608, B110, B113 |
| `radon cc` | `handle_date`=29(F), `dashboard`=16, `send`=12, `monthly`=12, `calculate_invoice`=10 → DT-09, DT-11 | CC por função |
| `pylint` | Dead code (DT-28), duplicação (DT-12), broad-except (DT-17), fixme (DT-21) | W0612, R0801, W0718/W0702, W0511 |
| `semgrep` | SQLi (DT-01), XSS parcial (DT-02), secrets (DT-04) — **mesmo schema em Python e PHP** | `formatted-sql-query`, owasp-top-ten |
| **Nenhuma** | DT-06, DT-07, DT-08, DT-10, DT-13, DT-14, DT-15, DT-16, DT-18, DT-20, DT-23, DT-24, DT-25, DT-26, DT-27, DT-29 | **Julgamento humano/IA** |

> **Leitura estratégica:** das 29 dívidas, **16 não são detectáveis por nenhuma ferramenta** — e
> incluem o maior risco de negócio (DT-07, isolamento multi-tenant) e a feature silenciosamente
> quebrada (DT-15). É exatamente onde um pipeline "dump bruto de ferramentas" falha e onde a
> análise com contexto de negócio ganha os pontos.

---

## Prévia da resposta "CTO por um dia"

Mapeando os 29 débitos nos 3 horizontes do briefing (slide s2c):

- **🌀 Furacão (0–30 dias) — desbloquear contrato + release:** DT-05 (debug, trivial), DT-03 (MD5),
  DT-01 (SQLi), DT-02 (XSS), DT-04 (segredos), e o **plano de remediação** de DT-06/DT-07 (auth +
  isolamento) — os quatro primeiros fecham a Seção 2 do questionário (bloqueante); auth precisa ao
  menos de plano crível em 30 dias.
- **🔧 4–8 semanas — destravar a próxima feature e a saída do dev:** DT-15 (faturamento quebrado),
  DT-11 (`handle_date`), DT-12 (duplicação), DT-25 (testes como rede de segurança **antes** do dev
  sair), DT-14/DT-22/DT-27/DT-29.
- **🚀 Backlog estruturado:** performance (DT-20/21/23/24), DT-09/10/13/18, DT-16 (reavaliar),
  DT-26/28.

> A argumentação-chave: durante o furacão, fazer **só** o que desbloqueia os prazos; o caro
> (reescrever o god object, perf) espera. Mas **testes sobem de horizonte** por causa da saída do
> dev — sem eles, em 6 semanas ninguém consegue mexer no código com segurança.

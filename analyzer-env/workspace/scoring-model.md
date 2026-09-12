# Modelo de Scoring — Radar de Débitos Técnicos

Referência do `scoring.py`. Descreve **como a prioridade de cada débito é
decidida** e em que ela se baseia. Os números aqui são os da implementação —
se o código mudar, esta tabela muda junto.

## Glossário rápido (leia antes)

Termos que aparecem no resto do documento:

| Termo | O que é |
|-------|---------|
| **Débito técnico / achado** | um problema que um detector encontrou no código (um SQLi, uma credencial exposta, falta de teste…). Cada achado é um `Finding`. |
| **SP (Story Points)** | unidade de **esforço** pra corrigir o débito — "quão grande é o trabalho". É **relativa**, não são horas. Escala tipo Fibonacci: 1–2 = trivial, 3–5 = cabe numa sprint, 8 = grande, 13+ = muito grande. No código é o campo `effort_points`. |
| **Severidade** | quão grave é o problema **em si** (Crítica / Alta / Média / Baixa). Vem do detector. É o ponto de partida do score. |
| **Confiança** | o quanto o detector tem **certeza** de que o achado é real (Alta / Média / Baixa). Confiança baixa = pode ser falso positivo. |
| **Prioridade** | a **saída** do scoring: o quão urgente tratar (Crítica / Alta / Média / Baixa). **É o que o relatório mostra.** |
| **Horizonte** | **quando** atacar: Furacão (0–30d), 4–8 semanas ou Backlog. É um eixo **separado** da prioridade (ver nota abaixo). |
| **Q1 / Q2** | itens do questionário de segurança (SQL Injection / XSS). São os **bloqueantes** — travam o contrato da HourTrack se falharem. |
| **Bus factor** | risco de concentrar conhecimento numa só pessoa: se ela sai, o time trava. Falta de testes/documentação aumenta o bus factor. |
| **Override** | regra "dura" que **força** uma prioridade, ignorando o cálculo numérico (ver seção 5). |
| **Determinístico** | rodar o mesmo input sempre dá exatamente o mesmo output. Sem isso, a avaliação do desafio não confia no resultado. |

> 💡 **Prioridade ≠ Horizonte.** São duas perguntas diferentes:
> *"quão urgente é?"* (prioridade) e *"em qual janela cabe o conserto?"*
> (horizonte). Um débito pode ser prioridade **Baixa** mas entrar no horizonte
> **4–8 semanas** — é o caso #8 da matriz.

## Princípios

1. **100% determinístico.** Nenhuma dependência de relógio. As pressões de
   negócio entram como dado fixo (`ScoringContext`), não são calculadas de
   `datetime.now()`. Rodar N vezes → N saídas byte-idênticas.
2. **Agnóstico de linguagem.** O scoring nunca lê `source`, `language`,
   `rule_id` ou `metrics`. Só o vocabulário normalizado do `Finding`. É por
   isso que o **mesmo** modelo pontua Python e PHP igual (viabiliza o bônus).
3. **Prioridade = severidade × contexto de negócio**, não severidade sozinha.
   Um débito "médio" tecnicamente pode ser o que trava o contrato.

---

## O fluxo (`score_one`)

Cada achado passa por 6 passos, nesta ordem:

```
base(severidade)
  × multiplicadores de contexto
  × fator de confiança
  = score  →  limiar  →  Prioridade
  →  override de contrato (pode forçar Crítica)
  →  Horizonte
```

---

## 1. Base por severidade

A severidade **de entrada** (vinda do detector) define os pontos iniciais.

| Severidade (entrada) | Pontos-base |
|----------------------|------------:|
| Crítica              | 100         |
| Alta                 | 70          |
| Média                | 40          |
| Baixa                | 15          |

> Crítica=100 e Alta=70 vêm fixados do slide s9; Média/Baixa preenchem as
> faixas intermediárias com folga defensável.

---

## 2. Multiplicadores de contexto

Aplicados **multiplicativamente** sobre a base, na ordem abaixo. Só atuam se a
condição for verdadeira.

| Condição | Fator | Por quê |
|----------|:-----:|---------|
| `categoria = Segurança` **e** auditoria em ≤ 30 dias | **× 2.0** | auditoria chegando torna falha de segurança inegociável |
| release em ≤ 14 dias **e** esforço **> 8 SP** | **× 0.5** | não é "menos grave" — é **inviável** na janela; desce de horizonte em vez de competir com quick wins |
| `publicly_reachable` **e** deal enterprise ativo | **× 1.5** | exposto sem auth, com contrato em risco |
| `impacts_revenue` | **× 1.5** | corrompe faturamento |
| `mitigates_bus_factor` | **× 1.25** | mitiga a saída do dev (concentração de conhecimento) |

> **Sobre o "> 8 SP" da 2ª regra:** SP = *Story Points* (ver glossário). O
> corte é **estritamente maior que 8** — um achado de **exatamente 8 SP não é
> penalizado** (ex.: o cenário #10). Na escala Fibonacci, `> 8` quer dizer
> "13 pra cima", ou seja: conserto grande demais pra fechar nos 14 dias até a
> release. Por isso ele perde metade do score e escorrega pra um horizonte
> mais longo, em vez de roubar foco dos quick wins.

> Os três últimos multiplicadores são **flags de negócio**, setados pela camada
> de detecção — o scoring só os lê.

---

## 3. Fator de confiança (defesa anti-falso-positivo)

Aplicado depois dos multiplicadores. É a peça que protege a nota: um achado de
baixa confiança **afunda no ranking** em vez de virar "Crítica" e custar ponto
por falso positivo.

| Confiança | Fator |
|-----------|:-----:|
| Alta      | 1.0   |
| Média     | 0.8   |
| Baixa     | 0.5   |

---

## 4. Score → Prioridade (limiares)

| Score final | Prioridade |
|-------------|------------|
| ≥ 120       | Crítica    |
| ≥ 70        | Alta       |
| ≥ 35        | Média      |
| < 35        | Baixa      |

---

## 5. Override de contrato (regra dura — opção B)

Independente do score calculado:

> Se o achado derruba um **item bloqueante** (`Q1` ou `Q2` — SQLi / XSS da
> Seção 2 do questionário) **E** a confiança é **Alta** → trava em **Crítica**.

O contrato de R$ 8k/mês é inegociável, então o cálculo numérico não pode
"rebaixar" um bloqueador. A exigência de **confiança Alta** é proposital:
impede travar um **falso positivo** em Crítica — ex.: o `DELETE` sem `WHERE`
de `everything.py:205`, que o detector já marcou como confiança Baixa, **não**
dispara o override.

Itens bloqueantes: `{Q1, Q2}` (espelha `report.ITENS_BLOQUEANTES`; um teste
garante que os dois não divergem).

---

## 6. Horizonte (quando atacar — slide s2c)

| Horizonte | Entra aqui quem… |
|-----------|------------------|
| 🌀 **Furacão (0–30 dias)** | é bloqueador de contrato **ou** é Crítica barata (≤ 5 SP — quick wins tipo `debug=True`) |
| 🔧 **4–8 semanas** | é Alta; é Crítica cara demais pra janela (> 5 SP); **ou** mitiga bus factor |
| 🚀 **Backlog estruturado** | o resto (Média / Baixa, performance, refatoração grande) |

---

## Contexto de negócio (entrada fixa)

Valores default do `ScoringContext` — refletem a situação da HourTrack no deck:

| Parâmetro | Valor default | Significado |
|-----------|--------------:|-------------|
| `days_until_release`    | 14       | crunch de release em 14 dias |
| `days_until_audit`      | 30       | auditoria em 30 dias |
| `enterprise_deal_active`| `True`   | contrato enterprise em risco |
| `blocking_items`        | `{Q1, Q2}` | itens que travam o contrato |

---

## Matriz de cenários

Todos calculados com o **contexto default** acima (release 14d, auditoria 30d,
deal ativo). Cobre cada regra pelo menos uma vez.

| # | Cenário | Sev. | Categoria | Contexto / Flags | Confiança | Cálculo | Score | **Prioridade** | **Horizonte** |
|---|---------|------|-----------|------------------|-----------|---------|------:|----------------|---------------|
| 1 | SQLi no login (exposto) | Alta | Segurança | público + enterprise, **Q1**, 3 SP | Alta | 70 × 2.0 × 1.5 × 1.0 | **210** | Crítica | 🌀 Furacão *(override Q1)* |
| 2 | XSS refletido | Alta | Segurança | público + enterprise, **Q2**, 2 SP | Alta | 70 × 2.0 × 1.5 × 1.0 | **210** | Crítica | 🌀 Furacão *(override Q2)* |
| 3 | `debug=True` em produção | Crítica | Segurança | 1 SP | Alta | 100 × 2.0 × 1.0 | **200** | Crítica | 🌀 Furacão *(≤ 5 SP)* |
| 4 | Credencial hardcoded | Crítica | Segurança | 2 SP | Média | 100 × 2.0 × 0.8 | **160** | Crítica | 🌀 Furacão *(≤ 5 SP)* |
| 5 | Refatorar auth vulnerável | Crítica | Segurança | 7 SP | Alta | 100 × 2.0 × 1.0 | **200** | Crítica | 🔧 4–8 semanas *(> 5 SP, cara pra janela)* |
| 6 | Cálculo de cobrança sem teste | Alta | Correção | `impacts_revenue`, 5 SP | Alta | 70 × 1.5 × 1.0 | **105** | Alta | 🔧 4–8 semanas |
| 7 | SQLi com **confiança baixa** (provável FP) | Alta | Segurança | público + enterprise, Q1, 3 SP | **Baixa** | 70 × 2.0 × 1.5 × 0.5 | **105** | Alta | 🔧 4–8 semanas *(**sem** override!)* |
| 8 | Ausência de testes (bus factor) | Média | Manutenibilidade | `mitigates_bus_factor`, 13 SP | Alta | 40 × 0.5 × 1.25 × 1.0 | **25** | Baixa | 🔧 4–8 semanas *(bus factor puxa o horizonte)* |
| 9 | Gargalo de performance | Média | Performance | 5 SP | Alta | 40 × 1.0 | **40** | Média | 🚀 Backlog |
| 10 | Code smell / refatoração pequena | Baixa | Manutenibilidade | 8 SP | Média | 15 × 0.8 | **12** | Baixa | 🚀 Backlog |

### Contrastes que a matriz revela

- **#1 vs #7** — o *mesmo* SQLi. Com confiança Alta vira Crítica/Furacão (override).
  Com confiança Baixa cai pra Alta/4–8 semanas e **não** dispara o override: a
  defesa anti-falso-positivo em ação.
- **#3** — chega a Crítica **sem** override (o score já basta): o override não é
  o único caminho pra Crítica.
- **#4 vs #5** — duas Críticas de segurança; o esforço decide o horizonte
  (2 SP → Furacão; 7 SP → 4–8 semanas, porque não cabe na janela de release).
- **#8** — prioridade **Baixa** mas horizonte **4–8 semanas**: o `mitigates_bus_factor`
  eleva o horizonte mesmo com score baixo. Prioridade e horizonte são eixos distintos.

---

## Exemplo passo a passo (cenário #1)

SQLi no login: severidade **Alta (70)**, categoria **Segurança**,
`publicly_reachable = True`, confiança **Alta**, questionário **Q1**, esforço 3 SP.

```
base(Alta)                               = 70
× 2.0   (segurança + auditoria em ≤ 30d) → 140
× 1.5   (alcançável + deal enterprise)   → 210
× confiança(Alta) = 1.0                  → 210
score = 210 ≥ 120                        → Crítica
override: bloqueador Q1 (confiança Alta) → Crítica  (confirma)
horizonte: é bloqueador                  → 🌀 Furacão (0–30 dias)
```

Troque só a confiança para **Baixa** (cenário #7) e o resultado muda para
`score = 105 → Alta`, **sem** override → horizonte 🔧 4–8 semanas. Exatamente o
comportamento que queremos contra falso positivo.

---

## Determinismo da ordenação

A ordenação final é **`(score desc, uid asc)`**. O `uid`
(`sha1(rule_id|file|line)[:8]`) no desempate garante que dois achados de mesmo
score **nunca** troquem de lugar entre execuções — independente da ordem em que
o detector os emitiu. Verificado no dado real: embaralhar a entrada produz o
mesmo payload (mesmo hash).

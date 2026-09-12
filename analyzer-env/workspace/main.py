#!/usr/bin/env python3
"""
Radar de Débitos Técnicos — entry point do pipeline.

    python3 main.py <repositório> --python    # roda o analisador de Python
    python3 main.py <repositório> --php       # roda o analisador de PHP

A flag escolhe o analisador; ela é obrigatória para não haver dúvida sobre o
que rodou. A detecção de linguagem continua acontecendo, mas só para avisar
quando a flag não combina com o conteúdo do repositório.

Fluxo: escolhe o detector -> normaliza em Finding -> deduplica -> renderiza
Markdown + JSON em `output/`.

O pipeline nunca aborta por ferramenta ausente. Se nada estiver instalado, ele
ainda produz relatório válido (com menos achados) e registra no relatório o
que não rodou — requisito do README do desafio.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

import report
import scoring
from detectors.base import IGNORAR_DIRS
from models import Language, deduplicate

# Registro de analisadores: linguagem -> módulo que expõe `analyze()`.
# Suportar uma linguagem nova é uma linha aqui + um módulo novo.
ANALISADORES: dict[Language, str] = {
    Language.PYTHON: "detectors.python",
    Language.PHP: "detectors.php",
}


def detectar_linguagens(repo: str) -> set[Language]:
    """Quais linguagens existem de fato no repositório (usado só para avisar)."""
    encontradas: set[Language] = set()
    marcadores_py = {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"}

    for _, dirs, arquivos in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in IGNORAR_DIRS and not d.startswith(".")]
        for nome in arquivos:
            if nome in marcadores_py or nome.endswith(".py"):
                encontradas.add(Language.PYTHON)
            elif nome == "composer.json" or nome.endswith(".php"):
                encontradas.add(Language.PHP)
    return encontradas


def analisar(repo: str, lang: Language, usar_semgrep: bool):
    """Roda o analisador da linguagem escolhida e devolve achados deduplicados."""
    nome_modulo = ANALISADORES[lang]
    try:
        modulo = importlib.import_module(nome_modulo)
    except ImportError as exc:
        status = [{
            "tool": f"analisador:{lang.value}", "available": False, "ok": False,
            "findings": 0, "error": str(exc),
            "notes": [f"analisador de {lang.value} ainda não implementado"],
        }]
        return [], status, set()

    achados, runs = modulo.analyze(repo, use_semgrep=usar_semgrep)
    status = [r.to_dict() for r in runs]

    # Cobertura do questionário vale só para ferramenta que REALMENTE rodou.
    # Sem isso, um run sem bandit instalado reportaria Q1/Q3/Q4/Q7 como
    # "conforme" — afirmar conformidade sem ter verificado é o erro que o
    # comercial da HourTrack cometeu ao responder "Sim" para tudo.
    cobertos: set[str] = set()
    if hasattr(modulo, "cobertura_questionario"):
        cobertos = modulo.cobertura_questionario({r.name for r in runs if r.ok})

    return deduplicate(achados), status, cobertos


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analisa um repositório e gera relatório de débitos técnicos em output/.",
        epilog="exemplo: python3 main.py /repos/python --python",
    )
    parser.add_argument("repo", help="caminho do repositório a analisar")

    analisador = parser.add_mutually_exclusive_group(required=True)
    analisador.add_argument("--python", dest="lang", action="store_const",
                            const=Language.PYTHON, help="usa o analisador de Python")
    analisador.add_argument("--php", dest="lang", action="store_const",
                            const=Language.PHP, help="usa o analisador de PHP")

    parser.add_argument("-o", "--output", default="output",
                        help="diretório de saída (padrão: output)")
    parser.add_argument("--no-semgrep", action="store_true",
                        help="pula o semgrep (evita dependência de rede)")
    parser.add_argument("--stamp", metavar="TEXTO",
                        help="inclui esta marca de geração no relatório; por padrão "
                             "a saída não tem data, para ser byte-idêntica entre execuções")
    parser.add_argument("-q", "--quiet", action="store_true", help="não imprime resumo")
    args = parser.parse_args(argv)

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"erro: {args.repo} não é um diretório", file=sys.stderr)
        return 2

    presentes = detectar_linguagens(repo)
    if args.lang not in presentes:
        outras = ", ".join(sorted(l.value for l in presentes)) or "nenhuma"
        print(f"aviso: pediu --{args.lang.value} mas o repositório parece conter: "
              f"{outras}. Rodando de qualquer forma.", file=sys.stderr)

    achados, status, cobertos = analisar(repo, args.lang, usar_semgrep=not args.no_semgrep)

    meta = {
        "path": args.repo,                      # o path COMO FOI PASSADO, não o absoluto:
        "name": os.path.basename(repo),         # caminho absoluto quebraria o determinismo
        "languages": [args.lang.value],
    }

    os.makedirs(args.output, exist_ok=True)
    destino_md = os.path.join(args.output, "relatorio.md")
    destino_json = os.path.join(args.output, "findings.json")
    destino_scoring = os.path.join(args.output, "scoring.json")

    with open(destino_md, "w", encoding="utf-8") as fh:
        fh.write(report.render_markdown(achados, meta, status, cobertos, stamp=args.stamp))
    with open(destino_json, "w", encoding="utf-8") as fh:
        fh.write(report.render_json(achados, meta, status, cobertos, stamp=args.stamp))

    # Etapa de scoring: prioriza os achados (determinístico) e grava o artefato
    # de handoff. O report fica por conta de outra pessoa — ela lê a
    # Prioridade/Horizonte daqui (ou importa `scoring`) sem o scoring tocar nele.
    scored_payload = scoring.build_scoring_payload(achados, scoring.ScoringContext(), meta)
    if args.stamp:
        scored_payload["generated_at"] = args.stamp
    with open(destino_scoring, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(scored_payload, indent=2, ensure_ascii=False) + "\n")

    if not args.quiet:
        resumo = report.resumo(achados)
        print(f"repo:         {meta['name']}  (analisador: {args.lang.value})")
        print(f"achados:      {resumo['total']} "
              f"(esforço somado: {resumo['esforco_total_story_points']} SP)")
        for t in status:
            marca = "ok " if t["ok"] else ("-- " if not t["available"] else "!! ")
            detalhe = t["error"] or "; ".join(t.get("notes") or [])
            print(f"  {marca}{t['tool']:22} {t['findings']:3} achados  {detalhe}")
        falhas = [q for q in report.scorecard(achados, cobertos) if q["estado"] == "falha"]
        bloqueantes = [q["item"] for q in falhas if q["bloqueante"]]
        print(f"questionário: {len(falhas)} de {len(report.QUESTIONARIO)} itens em falha"
              + (f" — BLOQUEANTES: {', '.join(bloqueantes)}" if bloqueantes else ""))
        print(f"saída:        {destino_md}")
        print(f"              {destino_json}")
        print(f"              {destino_scoring}  (scoring: {scored_payload['summary']['total']} achados priorizados)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

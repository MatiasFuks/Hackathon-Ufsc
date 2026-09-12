"""
Primitivos compartilhados entre detectores de linguagem.

Por que este módulo existe
--------------------------
`ToolRun`, a invocação tolerante a falha e os helpers de caminho/evidência são
idênticos em qualquer linguagem — quem muda é o catálogo de regras, não a
mecânica de rodar a ferramenta. Duplicar isso por detector seria reproduzir no
nosso pipeline o DT-12 do código-alvo (duplicação divergente), que é
justamente o débito que estamos reportando.

Consumidores
------------
`detectors/python.py` e `detectors/php.py` importam estes primitivos daqui.
As cópias locais que existiam no detector de Python foram removidas.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

# Diretórios que nenhum detector deve varrer: dependência de terceiro e lixo
# de build. Analisar `vendor/` no repo PHP acharia centenas de "débitos" que
# não são do time — falso positivo em escala industrial.
IGNORAR_DIRS = {
    ".git", "vendor", "node_modules", "__pycache__", ".venv", "venv",
    "output", ".pytest_cache", "storage", "bootstrap", "build", "dist",
}


@dataclass
class ToolRun:
    """
    Status de uma ferramenta externa — vai para o relatório.

    `available=False` e `ok=False` são estados diferentes e ambos importam:
    ferramenta ausente é uma lacuna de cobertura honesta; ferramenta presente
    que falhou é um bug a investigar. O relatório distingue os dois.
    """
    name: str
    available: bool
    ok: bool
    findings: int = 0
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.name, "available": self.available, "ok": self.ok,
            "findings": self.findings, "error": self.error, "notes": self.notes,
        }


def run_tool(cmd: list[str], timeout: int = 120) -> tuple[bool, str, str]:
    """
    Executa a ferramenta. Nunca levanta exceção, nunca olha returncode.

    Ferramenta de análise usa exit code para sinalizar "achei algo", não
    "falhei": phpstan sai com 1 quando encontra erros, bandit também. Tratar
    returncode como falha descartaria justamente as execuções úteis. O
    critério de sucesso é "stdout parseável", validado por quem chama.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return True, p.stdout, p.stderr
    except FileNotFoundError:
        return False, "", "ferramenta não instalada"
    except subprocess.TimeoutExpired:
        return False, "", f"timeout após {timeout}s"
    except OSError as exc:
        return False, "", str(exc)


def rel_path(path: str, repo: str) -> str:
    """Caminho relativo ao repo. Caminho absoluto na saída quebra determinismo."""
    try:
        return os.path.relpath(os.path.realpath(path), os.path.realpath(repo))
    except ValueError:
        return path


def snippet(repo: str, rel: str, line: int) -> str:
    """Evidência: a linha do achado, sem indentação e truncada."""
    try:
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as fh:
            linhas = fh.readlines()
        if 1 <= line <= len(linhas):
            return linhas[line - 1].strip()[:200]
    except OSError:
        pass
    return ""


def listar_arquivos(repo: str, extensoes: tuple[str, ...]) -> list[str]:
    """
    Arquivos do repo com as extensões dadas, em caminho relativo e ORDENADOS.

    A ordenação não é cosmética: `os.walk` devolve na ordem do sistema de
    arquivos, que varia entre máquinas. Sem `sorted`, dois runs do mesmo repo
    poderiam emitir achados em ordem diferente — e pipeline não determinístico
    é desclassificado pelo desafio.
    """
    encontrados: list[str] = []
    for raiz, dirs, arquivos in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in IGNORAR_DIRS and not d.startswith("."))
        for nome in sorted(arquivos):
            if nome.endswith(extensoes):
                encontrados.append(rel_path(os.path.join(raiz, nome), repo))
    return sorted(encontrados)


def ler(repo: str, rel: str) -> str:
    """Conteúdo de um arquivo do repo; string vazia se ilegível."""
    try:
        with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def numero_da_linha(source: str, offset: int) -> int:
    """Linha 1-indexada do caractere em `offset`."""
    return source.count("\n", 0, offset) + 1

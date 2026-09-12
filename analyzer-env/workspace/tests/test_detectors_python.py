"""
Testes do adaptador de ferramentas Python.

Rodam SEM bandit/radon/pylint instalados: as funções `normalize_*` são puras e
recebem o JSON já pronto, e a classificação de origem de SQL só precisa de AST.
O teste de integração no fim é pulado automaticamente quando as ferramentas
não estão no PATH.
"""
import os
import shutil
import tempfile
import unittest

from detectors.base import run_tool
from detectors.python import (
    CC_BANDS, _sqli_origin, analyze,
    normalize_bandit, normalize_pylint, normalize_radon,
)
from models import Confidence, Severity, deduplicate

# Fixture com os três padrões de SQL montado por string que existem no alvo.
FIXTURE = '''import sqlite3
from flask import request

TABLE_MAP = {"customer": "customers", "usuario": "users"}


def consulta_com_dado_do_request(db):
    month = request.args.get("month", "")
    return db.execute(f"SELECT * FROM h WHERE m = '{month}'")  # MARK-TAINTED


def apaga_por_mapa_literal(db, thing, ident):
    return db.execute(f"DELETE FROM {TABLE_MAP[thing]} WHERE id = ?", (ident,))  # MARK-LITERAL


class Modelo:
    def consulta_interna(self, db, competencia):
        return db.execute(f"SELECT * FROM h WHERE c = {self.id} AND m = '{competencia}'")  # MARK-INTERNAL
'''


class OrigemDeSQL(unittest.TestCase):
    """
    O cross-check anti-falso-positivo. Medido no repo-alvo: o bandit marca 7
    B608, dos quais 2 não são atacáveis. Esta classificação é o que os separa.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = cls.tmp.name
        with open(os.path.join(cls.repo, "alvo.py"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE)
        cls.linhas = {
            marca: i
            for i, texto in enumerate(FIXTURE.splitlines(), start=1)
            for marca in ("MARK-TAINTED", "MARK-LITERAL", "MARK-INTERNAL")
            if marca in texto
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_valor_do_request_e_tainted(self):
        origem, _ = _sqli_origin(self.repo, "alvo.py", self.linhas["MARK-TAINTED"])
        self.assertEqual(origem, "tainted")

    def test_lookup_em_dict_literal_nao_e_injetavel(self):
        """
        `f'DELETE FROM {TABLE_MAP[thing]}'` — everything.py:205 no alvo.
        `thing` vem da URL, mas o dict tem chaves constantes: domínio fechado.
        O semgrep marca esta linha como tainted; nós não. Este teste trava
        essa decisão para que ninguém a desfaça sem perceber.
        """
        origem, detalhe = _sqli_origin(self.repo, "alvo.py", self.linhas["MARK-LITERAL"])
        self.assertEqual(origem, "literal")
        self.assertIn("não injetável", detalhe)

    def test_valor_interno_fica_em_interno(self):
        origem, _ = _sqli_origin(self.repo, "alvo.py", self.linhas["MARK-INTERNAL"])
        self.assertEqual(origem, "internal")

    def test_arquivo_ilegivel_nao_quebra(self):
        origem, detalhe = _sqli_origin(self.repo, "nao-existe.py", 1)
        self.assertEqual(origem, "internal")
        self.assertIn("MÉDIA", detalhe)

    def test_limitacao_conhecida_colisao_de_nome_entre_escopos(self):
        """
        Limitação documentada: o índice de origem varre o módulo inteiro
        ignorando escopo. Se um nome é tainted em qualquer função, ele conta
        como tainted nas outras. Erra para o lado seguro (mais severo), mas
        está registrado aqui para não ser descoberto como surpresa.
        """
        colisao = (
            "from flask import request\n"
            "def a():\n"
            "    mes = request.args.get('mes')\n"
            "    return mes\n"
            "def b(db, mes):\n"
            "    return db.execute(f\"SELECT 1 WHERE m = '{mes}'\")  # param, não request\n"
        )
        with open(os.path.join(self.repo, "colisao.py"), "w", encoding="utf-8") as fh:
            fh.write(colisao)
        origem, _ = _sqli_origin(self.repo, "colisao.py", 6)
        self.assertEqual(origem, "tainted")  # conservador: superestima


class MandatoBandit(unittest.TestCase):
    def payload(self, *results):
        return {"results": list(results)}

    def issue(self, test_id, line=10, text="texto", sev="HIGH"):
        return {
            "test_id": test_id, "filename": "/repo/app/x.py", "line_number": line,
            "issue_text": text, "issue_severity": sev,
        }

    def test_descarta_test_id_fora_da_whitelist(self):
        """B101 (assert_used) não tem valor de negócio aqui: fora do mandato."""
        findings, descartados = normalize_bandit(
            self.payload(self.issue("B324"), self.issue("B101")), "/repo"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(descartados, 1)

    def test_mapeia_cwe_e_item_do_questionario(self):
        findings, _ = normalize_bandit(self.payload(self.issue("B324")), "/repo")
        self.assertEqual(findings[0].cwe, 327)
        self.assertEqual(findings[0].questionnaire_item, "Q3,Q7")
        self.assertEqual(findings[0].severity, Severity.CRITICA)
        self.assertEqual(findings[0].debt_id, "DT-03")

    def test_caminho_sai_relativo_ao_repo(self):
        findings, _ = normalize_bandit(self.payload(self.issue("B324")), "/repo")
        self.assertEqual(findings[0].file, "app/x.py")


class BandasDeComplexidade(unittest.TestCase):
    def test_usa_limiar_proprio_e_ignora_o_rank_do_radon(self):
        """
        O `rank` do radon discorda da tabela do FERRAMENTAS.md (CC=29 sai "D"
        na ferramenta e "F" na doc). Usamos o número; guardamos o rank só como
        metadado de auditoria.
        """
        payload = {"/repo/h.py": [
            {"name": "handle_date", "complexity": 29, "rank": "D", "lineno": 8},
            {"name": "dashboard", "complexity": 16, "rank": "C", "lineno": 40},
            {"name": "calculate_invoice", "complexity": 10, "rank": "B", "lineno": 12},
        ]}
        findings = normalize_radon(payload, "/repo")
        self.assertEqual(len(findings), 2)          # CC=10 fica abaixo do piso
        por_nome = {f.metrics["symbol"]: f for f in findings}
        self.assertEqual(por_nome["handle_date"].severity, Severity.ALTA)
        self.assertEqual(por_nome["handle_date"].effort_points, 8.0)
        self.assertEqual(por_nome["handle_date"].metrics["radon_rank"], "D")
        self.assertEqual(por_nome["dashboard"].severity, Severity.MEDIA)

    def test_bandas_em_ordem_decrescente(self):
        """A seleção usa o primeiro limiar que casa — a ordem importa."""
        limiares = [lo for lo, *_ in CC_BANDS]
        self.assertEqual(limiares, sorted(limiares, reverse=True))


class MandatoPylint(unittest.TestCase):
    def test_descarta_import_error_como_ruido_de_ambiente(self):
        """
        import-error de flask é ruído do container de análise, não débito do
        alvo. Reportar seria falso positivo — e falso positivo desconta ponto.
        """
        payload = [
            {"symbol": "import-error", "path": "/repo/app/e.py", "line": 2,
             "message": "Unable to import 'flask'", "type": "error"},
            {"symbol": "unused-variable", "path": "/repo/app/e.py", "line": 76,
             "message": "Unused variable 'total_hours'", "type": "warning"},
        ]
        findings, descartados = normalize_pylint(payload, "/repo")
        self.assertEqual([f.rule_id for f in findings], ["pylint:unused-variable"])
        self.assertEqual(descartados, 1)


class DegradacaoSemFerramenta(unittest.TestCase):
    def test_binario_ausente_nao_levanta_excecao(self):
        ok, out, err = run_tool(["ferramenta-que-nao-existe-xyz"])
        self.assertFalse(ok)
        self.assertEqual(err, "ferramenta não instalada")

    def test_analyze_sem_nenhuma_ferramenta_devolve_lista_vazia(self):
        """
        Requisito do README do desafio: tem que haver caminho que funcione sem
        as ferramentas instaladas. Simulamos PATH vazio.
        """
        path_original = os.environ.get("PATH", "")
        os.environ["PATH"] = ""
        try:
            findings, runs = analyze(".", use_semgrep=False)
        finally:
            os.environ["PATH"] = path_original
        self.assertEqual(findings, [])
        self.assertEqual(len(runs), 3)
        self.assertTrue(all(not r.available for r in runs))


REPO_ALVO = os.environ.get("ANALYZER_TEST_REPO", "/repos/python")


@unittest.skipUnless(
    shutil.which("bandit") and os.path.isdir(REPO_ALVO),
    "integração: precisa de bandit no PATH e do repo-alvo montado",
)
class IntegracaoNoRepoAlvo(unittest.TestCase):
    """
    Oráculo de regressão contra o findings-ground-truth.md.

    Compara por (regra, arquivo, linha) e nunca por contagem total: a contagem
    muda quando a whitelist muda, e isso não é regressão.
    """

    @classmethod
    def setUpClass(cls):
        cls.findings, cls.runs = analyze(REPO_ALVO, use_semgrep=False)
        cls.por_local = {(f.rule_id, f.file, f.line): f for f in cls.findings}

    def test_md5_detectado_como_critico(self):
        chave = ("bandit:B324", "app/everything.py", 168)
        self.assertIn(chave, self.por_local)
        self.assertEqual(self.por_local[chave].severity, Severity.CRITICA)

    def test_sqli_alcancavel_por_request_tem_confianca_alta(self):
        for arquivo, linha in [
            ("app/everything.py", 219),
            ("app/routes/report_routes.py", 29),
            ("app/routes/report_routes.py", 44),
            ("app/routes/report_routes.py", 107),
        ]:
            with self.subTest(local=f"{arquivo}:{linha}"):
                f = self.por_local[("bandit:B608", arquivo, linha)]
                self.assertEqual(f.confidence, Confidence.ALTA)

    def test_falso_positivo_do_table_map_fica_com_confianca_baixa(self):
        f = self.por_local[("bandit:B608", "app/everything.py", 205)]
        self.assertEqual(f.confidence, Confidence.BAIXA)

    def test_sqli_de_origem_interna_nao_vira_confianca_alta(self):
        for arquivo, linha in [("app/models/customer.py", 38),
                               ("app/services/billing_service.py", 27)]:
            with self.subTest(local=f"{arquivo}:{linha}"):
                f = self.por_local[("bandit:B608", arquivo, linha)]
                self.assertEqual(f.confidence, Confidence.MEDIA)

    def test_b201_ausente_e_esperado_e_documentado(self):
        """
        Cegueira medida: bandit não reconhece o app Flask em run.py. O ground
        truth erra ao prometer B201 aqui. O adaptador registra a nota.
        """
        self.assertNotIn("bandit:B201", {f.rule_id for f in self.findings})
        bandit = next(r for r in self.runs if r.name == "bandit")
        self.assertTrue(any("B201 ausente" in n for n in bandit.notes))

    def test_complexidade_do_handle_date(self):
        f = self.por_local[("radon:CC", "app/helpers/date_helper.py", 8)]
        self.assertEqual(f.metrics["cc"], 29)
        self.assertEqual(f.severity, Severity.ALTA)

    def test_deduplicacao_reduz_sem_perder_debito(self):
        antes = {f.debt_id for f in self.findings if f.debt_id}
        merged = deduplicate(list(self.findings))
        depois = {f.debt_id for f in merged if f.debt_id}
        self.assertLess(len(merged), len(self.findings))
        self.assertEqual(antes, depois)   # funde achado, não perde débito

    def test_determinismo_entre_execucoes(self):
        outra, _ = analyze(REPO_ALVO, use_semgrep=False)
        self.assertEqual([f.uid for f in self.findings], [f.uid for f in outra])


if __name__ == "__main__":
    unittest.main()


class CoberturaDoQuestionario(unittest.TestCase):
    """
    Cobertura declarada != cobertura efetiva. Estes testes travam a distinção.
    """

    def test_sem_ferramenta_nao_declara_cobertura(self):
        from detectors.python import cobertura_questionario
        self.assertEqual(cobertura_questionario(set()), set())

    def test_bandit_cobre_q1_q3_q4_q7(self):
        from detectors.python import cobertura_questionario
        self.assertEqual(cobertura_questionario({"bandit"}), {"Q1", "Q3", "Q4", "Q7"})

    def test_q6_nunca_e_declarado_coberto(self):
        """
        B201 está mapeado no catálogo, mas foi medido que o bandit não o
        dispara neste repo. Declarar Q6 coberto produziria "sem achado" para
        uma pergunta não verificada — falso negativo no questionário.
        """
        from detectors.python import cobertura_questionario
        self.assertNotIn("Q6", cobertura_questionario({"bandit", "pylint"}))

    def test_q2_xss_tambem_nao_e_coberto(self):
        from detectors.python import cobertura_questionario
        self.assertNotIn("Q2", cobertura_questionario({"bandit", "pylint"}))

"""
Testes do enriquecimento por IA.

Nenhum destes testes faz chamada de rede: o que interessa validar é a
fronteira (o que sai da máquina), o cache (determinismo) e a degradação
(relatório completo sem chave). A qualidade da prosa não é testável — a
integridade do payload é.
"""
import json
import os
import tempfile
import unittest

import ai
import report
import scoring
from models import Category, Confidence, Finding, Language, Severity


def mk(**kw) -> Finding:
    base = dict(
        rule_id="bandit:B105", source="bandit", language=Language.PYTHON,
        category=Category.SEGURANCA, title="Credencial hardcoded",
        description="Possible hardcoded password: 'gmail_app_password_hardcoded_123'",
        file="app/services/notification_service.py", line=15,
        evidence="SMTP_PASS = 'gmail_app_password_hardcoded_123'",
        severity=Severity.ALTA, confidence=Confidence.MEDIA, effort_points=2.0,
        questionnaire_item="Q4", cwe=798, debt_id="DT-04",
    )
    base.update(kw)
    return Finding(**base)


class FronteiraDeDados(unittest.TestCase):
    """
    O payload enviado ao Gemini não pode levar código-fonte.

    Não é preciosismo: as linhas de evidência do repo-alvo SÃO as credenciais
    hardcoded (DT-04). Mandá-las para uma API de terceiro vazaria o segredo do
    cliente no mesmo ato de escrever o relatório que o denuncia.
    """

    def setUp(self):
        self.findings = [mk().to_dict()]
        self.payload = ai.montar_payload(
            self.findings, {"total": 1}, [], {"name": "python", "languages": ["python"]}
        )

    def test_evidencia_nao_sai_da_maquina(self):
        serializado = json.dumps(self.payload, ensure_ascii=False)
        self.assertNotIn("gmail_app_password_hardcoded_123", serializado)
        self.assertNotIn("SMTP_PASS", serializado)

    def test_descricao_bruta_da_ferramenta_nao_sai(self):
        """A description do bandit às vezes embute o próprio segredo."""
        serializado = json.dumps(self.payload, ensure_ascii=False)
        self.assertNotIn("Possible hardcoded password", serializado)

    def test_payload_leva_o_que_a_ia_precisa(self):
        achado = self.payload["achados"][0]
        self.assertEqual(achado["titulo"], "Credencial hardcoded")
        self.assertEqual(achado["local"], "app/services/notification_service.py:15")
        self.assertEqual(achado["item_questionario"], "Q4")
        self.assertEqual(achado["debito"], "DT-04")

    def test_payload_leva_prioridade_do_scoring(self):
        """A IA recebe a prioridade calculada; ela não recalcula nem contesta."""
        scored = scoring.build_scoring_payload([mk()], scoring.ScoringContext())
        payload = ai.montar_payload(
            scored["findings"], {"total": 1}, [], {"name": "x", "languages": ["python"]}
        )
        self.assertIn(payload["achados"][0]["prioridade"],
                      [p.value for p in scoring.Priority])


class Cache(unittest.TestCase):
    def test_mesmo_payload_gera_mesma_chave(self):
        a = ai.montar_payload([mk().to_dict()], {"total": 1}, [], {"name": "x", "languages": []})
        b = ai.montar_payload([mk().to_dict()], {"total": 1}, [], {"name": "x", "languages": []})
        self.assertEqual(ai._chave_de_cache(a, "m"), ai._chave_de_cache(b, "m"))

    def test_payload_diferente_gera_chave_diferente(self):
        a = ai.montar_payload([mk().to_dict()], {"total": 1}, [], {"name": "x", "languages": []})
        b = ai.montar_payload([mk(line=99).to_dict()], {"total": 1}, [], {"name": "x", "languages": []})
        self.assertNotEqual(ai._chave_de_cache(a, "m"), ai._chave_de_cache(b, "m"))

    def test_cache_e_lido_sem_chamar_a_api(self):
        """
        Com cache preenchido, `gerar_narrativa` não precisa de chave nem de rede.
        É o que torna o relatório reproduzível por quem não tem API key.
        """
        payload = ai.montar_payload([mk().to_dict()], {"total": 1}, [], {"name": "x", "languages": []})
        completo = {chave: ("texto" if chave != "riscos" else
                            [{"titulo": "t", "o_que_e": "o", "consequencia": "c",
                              "debitos": ["DT-04"]}])
                    for chave in ai.SECOES}
        for lista in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
            completo[lista] = ["item"]

        with tempfile.TemporaryDirectory() as tmp:
            chave = ai._chave_de_cache(payload, ai.MODELOS[0])
            with open(os.path.join(tmp, f"{chave}.json"), "w", encoding="utf-8") as fh:
                json.dump(completo, fh)
            anterior = os.environ.pop("GOOGLE_API_KEY", None)
            try:
                narrativa, status = ai.gerar_narrativa(payload, cache_dir=tmp)
            finally:
                if anterior is not None:
                    os.environ["GOOGLE_API_KEY"] = anterior
            self.assertIsNotNone(narrativa)
            self.assertIn("cache", status)


class Degradacao(unittest.TestCase):
    def test_sem_chave_devolve_none_sem_quebrar(self):
        payload = ai.montar_payload([], {"total": 0}, [], {"name": "x", "languages": []})
        anterior = os.environ.pop("GOOGLE_API_KEY", None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                narrativa, status = ai.gerar_narrativa(payload, cache_dir=tmp)
        finally:
            if anterior is not None:
                os.environ["GOOGLE_API_KEY"] = anterior
        self.assertIsNone(narrativa)
        self.assertIn("GOOGLE_API_KEY", status)

    def test_no_ai_nao_chama_nem_com_chave(self):
        payload = ai.montar_payload([], {"total": 0}, [], {"name": "x", "languages": []})
        os.environ["GOOGLE_API_KEY"] = "chave-falsa-que-nao-deve-ser-usada"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                narrativa, status = ai.gerar_narrativa(
                    payload, cache_dir=tmp, permitir_chamada=False
                )
        finally:
            os.environ.pop("GOOGLE_API_KEY", None)
        self.assertIsNone(narrativa)
        self.assertIn("desativada", status)

    def test_relatorio_fica_completo_sem_ia(self):
        """Sem IA o Markdown tem que sair com todas as seções, não com buracos."""
        md = report.render_markdown(
            [mk()], {"name": "x", "languages": ["python"]}, [], {"Q4"},
        )
        for secao in ("Resumo executivo", "O contrato de R$ 8.000/mês",
                      "Os principais riscos", "Quanto custa, e quando",
                      "Plano", "Recomendação", "Anexo técnico"):
            with self.subTest(secao=secao):
                self.assertIn(secao, md)

    def test_plano_separa_release_da_janela_de_auditoria(self):
        """O relatório mostra a janela de 14 dias (Release) separada do Furacão (15–30d)."""
        md = report.render_markdown(
            [mk()], {"name": "x", "languages": ["python"]}, [], {"Q4"},
        )
        self.assertIn(scoring.Horizon.RELEASE.value, md)
        self.assertIn(scoring.Horizon.FURACAO.value, md)


class ValidacaoDaResposta(unittest.TestCase):
    def test_resposta_incompleta_e_descartada(self):
        """Meia resposta da IA = seção vazia no relatório. Melhor o texto estático."""
        self.assertIsNone(ai._validar({"resumo_executivo": "só isso"}))

    def test_risco_sem_debitos_invalida_tudo(self):
        """
        `debitos` é obrigatório: é o que amarra cada risco a um achado real.
        """
        dados = {chave: "t" for chave in ai.SECOES}
        dados["riscos"] = [{"titulo": "t", "o_que_e": "o", "consequencia": "c"}]
        for lista in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
            dados[lista] = ["x"]
        self.assertIsNone(ai._validar(dados))

    def test_risco_malformado_invalida_tudo(self):
        dados = {chave: "t" for chave in ai.SECOES}
        dados["riscos"] = [{"titulo": "sem os outros campos"}]
        for lista in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
            dados[lista] = ["x"]
        self.assertIsNone(ai._validar(dados))

    def test_plano_release_e_secao_obrigatoria(self):
        """A janela de 14 dias (Release) virou seção própria; sua ausência invalida a resposta."""
        dados = {chave: "t" for chave in ai.SECOES}
        dados["riscos"] = [{"titulo": "t", "o_que_e": "o", "consequencia": "c", "debitos": ["DT-04"]}]
        for lista in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
            dados[lista] = ["x"]
        self.assertIsNotNone(ai._validar(dados))       # resposta completa valida
        dados.pop("plano_release")
        self.assertIsNone(ai._validar(dados))           # sem a seção nova, rejeita

    def test_json_dentro_de_cerca_de_codigo_e_aceito(self):
        bruto = '```json\n{"a": 1}\n```'
        self.assertEqual(ai._extrair_json(bruto), {"a": 1})

    def test_prompt_version_invalida_cache(self):
        """Mudar o prompt tem que invalidar o cache, senão o texto fica velho."""
        payload = {"x": 1}
        original = ai.PROMPT_VERSION
        chave_antes = ai._chave_de_cache(payload, "m")
        ai.PROMPT_VERSION = original + "-teste"
        try:
            self.assertNotEqual(chave_antes, ai._chave_de_cache(payload, "m"))
        finally:
            ai.PROMPT_VERSION = original


if __name__ == "__main__":
    unittest.main()


class AterramentoDosRiscos(unittest.TestCase):
    """
    O filtro contra risco alucinado.

    Medido com o Gemini: ele listou "saída do desenvolvedor principal" como
    risco. É fato do business-context, não achado desta análise. Sem filtro, o
    relatório afirmaria à diretoria que o diagnóstico detectou algo que não
    detectou.
    """

    def test_risco_sem_debito_real_e_descartado(self):
        riscos = [
            {"titulo": "Credenciais no código", "o_que_e": "x",
             "consequencia": "y", "debitos": ["DT-04"]},
            {"titulo": "Saída do desenvolvedor principal", "o_que_e": "x",
             "consequencia": "y", "debitos": []},
            {"titulo": "Débito que não existe no repo", "o_que_e": "x",
             "consequencia": "y", "debitos": ["DT-99"]},
        ]
        sobreviventes = report.riscos_validados(riscos, [mk()])
        self.assertEqual([r["titulo"] for r in sobreviventes], ["Credenciais no código"])

    def test_ocorrencias_vem_do_pipeline_nao_da_ia(self):
        """A IA escreve a frase; o número é contado aqui."""
        riscos = [{"titulo": "t", "o_que_e": "x", "consequencia": "y",
                   "debitos": ["DT-04"], "ocorrencias": 999}]
        achados = [mk(line=1), mk(line=2), mk(line=3)]
        self.assertEqual(report.riscos_validados(riscos, achados)[0]["ocorrencias"], 3)

    def test_sem_risco_valido_cai_no_estatico(self):
        """Seção vazia num relatório para diretoria é pior que texto estático."""
        narrativa = {chave: "texto" for chave in ai.SECOES}
        narrativa["riscos"] = [{"titulo": "inventado", "o_que_e": "x",
                                "consequencia": "y", "debitos": ["DT-99"]}]
        for lista in ("plano_release", "plano_furacao", "plano_curto_prazo", "plano_backlog", "nao_vamos_fazer"):
            narrativa[lista] = ["item"]
        md = report.render_markdown(
            [mk()], {"name": "x", "languages": ["python"]}, [], {"Q4"},
            narrativa=narrativa,
        )
        self.assertIn("Credencial hardcoded", md)   # verbete estático do glossário
        self.assertNotIn("inventado", md)

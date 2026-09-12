"""Testes do contrato Finding e da deduplicação. Zero dependência externa."""
import unittest

from models import Category, Confidence, Finding, Language, Severity, deduplicate


def mk(rule_id="t:1", file="a.py", line=1, source="t", **kw) -> Finding:
    base = dict(
        rule_id=rule_id, source=source, language=Language.PYTHON,
        category=Category.SEGURANCA, title="t", description="d",
        file=file, line=line,
    )
    base.update(kw)
    return Finding(**base)


class TestUid(unittest.TestCase):
    def test_uid_estavel_entre_instancias(self):
        self.assertEqual(mk().uid, mk().uid)

    def test_uid_muda_com_a_localizacao(self):
        self.assertNotEqual(mk(line=1).uid, mk(line=2).uid)

    def test_uid_ignora_campos_mutaveis(self):
        """Corroboração e descrição enriquecida por IA não podem mexer no uid."""
        a = mk()
        b = mk(description="descrição reescrita pela IA", corroborated_by=["semgrep:x"])
        self.assertEqual(a.uid, b.uid)


class TestDeduplicacao(unittest.TestCase):
    def test_funde_par_do_mesmo_debito_na_mesma_linha(self):
        """bandit:B110 e pylint:broad-exception-caught são um achado só."""
        par = [
            mk(rule_id="bandit:B110", debt_id="DT-17", cwe=703, line=77,
               category=Category.MANUTENIBILIDADE, confidence=Confidence.MEDIA),
            mk(rule_id="pylint:broad-exception-caught", debt_id="DT-17", line=77,
               category=Category.MANUTENIBILIDADE, confidence=Confidence.ALTA),
        ]
        merged = deduplicate(par)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].corroborated_by, ["bandit:B110"])

    def test_vencedor_herda_cwe_de_quem_perdeu(self):
        """Sem isso, fundir perde a rastreabilidade do questionário."""
        par = [
            mk(rule_id="bandit:B110", debt_id="DT-17", cwe=703, line=77,
               questionnaire_item="Q4", confidence=Confidence.MEDIA),
            mk(rule_id="pylint:broad-exception-caught", debt_id="DT-17", line=77,
               cwe=None, confidence=Confidence.ALTA),
        ]
        winner = deduplicate(par)[0]
        self.assertEqual(winner.rule_id, "pylint:broad-exception-caught")
        self.assertEqual(winner.cwe, 703)
        self.assertEqual(winner.questionnaire_item, "Q4")

    def test_nao_funde_debitos_diferentes_na_mesma_linha(self):
        dois = [
            mk(rule_id="bandit:B608", debt_id="DT-01", line=27),
            mk(rule_id="bandit:B110", debt_id="DT-17", line=27),
        ]
        self.assertEqual(len(deduplicate(dois)), 2)

    def test_severidade_maior_vence(self):
        par = [
            mk(rule_id="a", debt_id="DT-01", severity=Severity.BAIXA),
            mk(rule_id="b", debt_id="DT-01", severity=Severity.CRITICA),
        ]
        self.assertEqual(deduplicate(par)[0].rule_id, "b")


class TestDeterminismo(unittest.TestCase):
    def test_ordem_de_entrada_nao_altera_a_saida(self):
        """
        Requisito do desafio: pipeline não determinístico é desclassificado.
        A ordem em que os detectores rodam não pode mudar o resultado.
        """
        entrada = [
            mk(rule_id="bandit:B110", debt_id="DT-17", line=77, cwe=703),
            mk(rule_id="pylint:broad-exception-caught", debt_id="DT-17", line=77),
            mk(rule_id="radon:CC", debt_id="DT-09", line=40,
               category=Category.MANUTENIBILIDADE),
            mk(rule_id="bandit:B608", debt_id="DT-01", line=219),
        ]
        direto = [f.uid for f in deduplicate(list(entrada))]
        invertido = [f.uid for f in deduplicate(list(reversed(entrada)))]
        self.assertEqual(direto, invertido)

    def test_rodar_duas_vezes_da_o_mesmo_resultado(self):
        entrada = [mk(rule_id=f"r{i}", line=i, debt_id=f"DT-{i:02d}") for i in range(1, 12)]
        self.assertEqual(
            [f.uid for f in deduplicate(list(entrada))],
            [f.uid for f in deduplicate(list(entrada))],
        )


if __name__ == "__main__":
    unittest.main()

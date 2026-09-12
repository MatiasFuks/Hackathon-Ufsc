"""
Testes do adaptador PHP.

Rodam SEM phpstan/phpmetrics/phploc instalados: as funções `normalize_*` são
puras e recebem o JSON já pronto, e os detectores `builtin` só precisam ler
arquivo. O teste de integração no fim é pulado quando o repo-alvo não está no
lugar esperado.
"""
import json
import os
import shutil
import tempfile
import unittest

from detectors.php import (
    CC_BANDS, _IndiceDeOrigem, _sql_interpolado, analyze, cobertura_questionario,
    normalize_phpmetrics, normalize_phpstan, scan_segredos, scan_sql_injection,
    scan_xss_blade, verificar_hash_de_senha,
)
from models import Confidence, Severity, deduplicate

REPO_ALVO = os.path.join(os.path.dirname(__file__), "..", "..", "..", "bad-codebase")

# Fixture com os quatro tipos de literal do PHP no MESMO arquivo. A diferença
# entre eles é o núcleo do detector de SQLi: só aspas duplas e heredoc
# interpolam.
FIXTURE_SQL = """<?php
class ReportController
{
    public function comDadoDoRequest(Request $r)
    {
        $month = $r->get('month', date('Y-m'));
        return DB::select("SELECT * FROM h WHERE m = '$month'"); // MARK-TAINTED
    }

    public function aspasSimplesNaoInterpolam($month)
    {
        return DB::select('SELECT * FROM h WHERE m = $month'); // MARK-SAFE-LITERAL
    }

    public function comBinding($month)
    {
        return DB::select('SELECT * FROM h WHERE m = ?', [$month]); // MARK-SAFE-BIND
    }

    public function comParametro($customerId, $month)
    {
        return DB::select("SELECT * FROM h WHERE c = {$customerId}"); // MARK-INTERNAL
    }

    public function queryBuilder($thing, $id)
    {
        $map = ['customer' => 'customers', 'hour' => 'billable_hours'];
        return DB::table($map[$thing])->where('id', $id)->delete(); // MARK-SAFE-BUILDER
    }

    public function heredocInterpola($month)
    {
        return DB::select(<<<SQL
            SELECT * FROM h WHERE m = '$month'
        SQL); // MARK-HEREDOC
    }

    public function nowdocNaoInterpola($month)
    {
        return DB::select(<<<'SQL'
            SELECT * FROM h WHERE m = '$month'
        SQL); // MARK-NOWDOC
    }
}
"""


def _repo_temporario(arquivos: dict[str, str]) -> str:
    """Cria um repo descartável. Quem chama é responsável por remover."""
    raiz = tempfile.mkdtemp()
    for rel, conteudo in arquivos.items():
        destino = os.path.join(raiz, rel)
        os.makedirs(os.path.dirname(destino), exist_ok=True)
        with open(destino, "w", encoding="utf-8") as fh:
            fh.write(conteudo)
    return raiz


class LiteraisDePhp(unittest.TestCase):
    """A distinção aspas simples / duplas / heredoc / nowdoc é o anti-FP central."""

    def setUp(self):
        self.sites = _sql_interpolado(FIXTURE_SQL)
        self.linhas = {linha for linha, _, _ in self.sites}

    def _linha_da_marca(self, marca: str) -> int:
        for i, linha in enumerate(FIXTURE_SQL.splitlines(), start=1):
            if marca in linha:
                return i
        raise AssertionError(f"marca {marca} não encontrada na fixture")

    def test_aspas_duplas_com_variavel_e_detectado(self):
        self.assertIn(self._linha_da_marca("MARK-TAINTED"), self.linhas)

    def test_aspas_simples_nao_interpolam_logo_nao_sao_injecao(self):
        """`'... = $month'` em PHP é o texto literal `$month`, não o valor."""
        self.assertNotIn(self._linha_da_marca("MARK-SAFE-LITERAL"), self.linhas)

    def test_binding_com_interrogacao_nao_e_detectado(self):
        self.assertNotIn(self._linha_da_marca("MARK-SAFE-BIND"), self.linhas)

    def test_query_builder_nao_e_sql_cru(self):
        """`DB::table($map[$thing])` não monta SQL — é o espelho do FP-03."""
        self.assertNotIn(self._linha_da_marca("MARK-SAFE-BUILDER"), self.linhas)

    def test_heredoc_interpola_e_e_detectado(self):
        """
        A linha reportada é a de ABERTURA (`<<<SQL`), não a do fechamento —
        é onde está o statement que precisa ser corrigido.
        """
        abertura = self._linha_da_marca("MARK-HEREDOC") - 2
        self.assertIn(abertura, self.linhas)

    def test_nowdoc_nao_interpola(self):
        self.assertNotIn(self._linha_da_marca("MARK-NOWDOC"), self.linhas)

    def test_saida_ordenada_por_linha(self):
        """Determinismo: a ordem não pode depender da ordem de CHAMADAS_SQL."""
        self.assertEqual(self.sites, sorted(self.sites))


class ClassificacaoDeOrigem(unittest.TestCase):
    def setUp(self):
        self.index = _IndiceDeOrigem(FIXTURE_SQL)

    def test_valor_do_request_e_tainted(self):
        self.assertEqual(self.index.classificar("$month"), "tainted")

    def test_parametro_de_metodo_fica_em_interno(self):
        self.assertEqual(self.index.classificar("{$customerId}"), "internal")

    def test_superglobal_e_tainted_sem_intermediario(self):
        self.assertEqual(self.index.classificar("$_GET['x']"), "tainted")

    def test_acesso_direto_ao_request_e_tainted(self):
        self.assertEqual(self.index.classificar("{$r->get('month')}"), "tainted")

    def test_basta_uma_expressao_atacavel(self):
        origem, _ = self.index.classificar_conjunto(["{$this->id}", "$month"])
        self.assertEqual(origem, "tainted")

    def test_limitacao_conhecida_ignora_escopo(self):
        """
        Igual ao detector Python: a varredura não respeita escopo. Um `$month`
        vindo do request num método contamina o `$month` parâmetro de outro.
        Documentado como limitação, não como bug — erra para MAIS informação.
        """
        self.assertEqual(self.index.classificar("$month"), "tainted")


class ConfiancaDoSqli(unittest.TestCase):
    def test_request_vira_confianca_alta_e_parametro_vira_media(self):
        repo = _repo_temporario({"app/R.php": FIXTURE_SQL})
        try:
            por_linha = {f.line: f for f in scan_sql_injection(repo)}
            confiancas = {f.confidence for f in por_linha.values()}
            self.assertIn(Confidence.ALTA, confiancas)
            self.assertTrue(all(f.debt_id == "DT-01" for f in por_linha.values()))
            self.assertTrue(all(f.questionnaire_item == "Q1" for f in por_linha.values()))
        finally:
            shutil.rmtree(repo)

    def test_apenas_alcancavel_pelo_request_marca_publicly_reachable(self):
        repo = _repo_temporario({"app/R.php": FIXTURE_SQL})
        try:
            achados = scan_sql_injection(repo)
            alcancaveis = [f for f in achados if f.publicly_reachable]
            self.assertTrue(alcancaveis)
            self.assertTrue(all(f.confidence is Confidence.ALTA for f in alcancaveis))
        finally:
            shutil.rmtree(repo)


class DeteccaoDeSegredos(unittest.TestCase):
    FIXTURE = """<?php
class Config
{
    protected $table       = 'billing_categories';
    private $smsApiKey     = 'SMSGLOBAL_KEY_abc123def456';
    private $erpApiUrl     = 'https://erp.hourtrack.com.br/api/v1';
    private $slackWebhook  = 'https://hooks.slack.com/services/T0/B0/XXXXXXXX';
    public $apiToken       = 'your-token-here';
}
return ['password' => env('DB_PASSWORD', ''), 'key' => env('APP_KEY')];
"""

    def setUp(self):
        self.repo = _repo_temporario({"app/C.php": self.FIXTURE})
        self.achados = {f.metrics["variavel"]: f for f in scan_segredos(self.repo)}

    def tearDown(self):
        shutil.rmtree(self.repo)

    def test_credencial_literal_e_detectada(self):
        self.assertIn("smsApiKey", self.achados)

    def test_webhook_do_slack_conta_como_credencial(self):
        """Quem tem a URL posta na conta — é credencial, não endereço."""
        self.assertIn("slackWebhook", self.achados)

    def test_nome_de_tabela_nao_e_segredo(self):
        """`protected $table = 'customers'` é o FP clássico de regra por valor."""
        self.assertNotIn("table", self.achados)

    def test_url_de_api_nao_e_segredo(self):
        self.assertNotIn("erpApiUrl", self.achados)

    def test_placeholder_e_ignorado(self):
        self.assertNotIn("apiToken", self.achados)

    def test_valor_vindo_de_env_nunca_e_achado(self):
        """`env('DB_PASSWORD')` é o jeito CERTO; marcar isso seria FP puro."""
        self.assertNotIn("password", self.achados)
        self.assertNotIn("key", self.achados)


class XssNoBlade(unittest.TestCase):
    def test_um_achado_por_template_e_nao_por_ocorrencia(self):
        """
        Priorizar > contar. As ocorrências de um template são UMA correção;
        7 achados separados inflariam a contagem sem informar nada a mais.
        """
        repo = _repo_temporario({
            "resources/views/x.blade.php":
                "<td>{!! $a->name !!}</td><td>{{ $b->ok }}</td><td>{!! $c->x !!}</td>",
        })
        try:
            achados = scan_xss_blade(repo)
            self.assertEqual(len(achados), 1)
            self.assertEqual(achados[0].metrics["ocorrencias"], 2)
            self.assertEqual(achados[0].questionnaire_item, "Q2")
        finally:
            shutil.rmtree(repo)

    def test_escape_padrao_do_blade_nao_gera_achado(self):
        repo = _repo_temporario({"resources/views/y.blade.php": "<td>{{ $a->name }}</td>"})
        try:
            self.assertEqual(scan_xss_blade(repo), [])
        finally:
            shutil.rmtree(repo)


class HashDeSenha(unittest.TestCase):
    def test_bcrypt_sem_md5_e_conforme(self):
        """Divergência real com o repo Python: aqui Q3/Q7 passam."""
        repo = _repo_temporario({"app/U.php": "<?php $p = bcrypt($r->password);"})
        try:
            achados, veredito = verificar_hash_de_senha(repo)
            self.assertEqual(achados, [])
            self.assertIn("conformes", veredito)
        finally:
            shutil.rmtree(repo)

    def test_md5_em_senha_derruba_q3_e_q7(self):
        repo = _repo_temporario({"app/U.php": "<?php $hash = md5($password);"})
        try:
            achados, _ = verificar_hash_de_senha(repo)
            self.assertEqual(len(achados), 1)
            self.assertEqual(achados[0].questionnaire_item, "Q3,Q7")
            self.assertEqual(achados[0].severity, Severity.CRITICA)
        finally:
            shutil.rmtree(repo)

    def test_md5_fora_de_contexto_de_senha_nao_e_achado(self):
        """md5 para chave de cache/ETag não é débito de credencial."""
        repo = _repo_temporario({"app/C.php": "<?php $cacheKey = md5($url);"})
        try:
            achados, _ = verificar_hash_de_senha(repo)
            self.assertEqual(achados, [])
        finally:
            shutil.rmtree(repo)


class FiltroDeRuidoDoPhpstan(unittest.TestCase):
    """FP-04: sem as deps do Laravel, o phpstan vira gerador de ruído."""

    def _payload(self, *mensagens):
        return {"files": {"/repo/app/X.php": {
            "messages": [{"message": m, "line": 10} for m in mensagens]}}}

    def test_classe_desconhecida_do_framework_e_descartada(self):
        payload = self._payload(
            "Class App\\X extends unknown class Illuminate\\Console\\Command.",
            "Call to method handle() on an unknown class Illuminate\\Http\\Request.",
        )
        achados, ruido, _ = normalize_phpstan(payload, "/repo")
        self.assertEqual(achados, [])
        self.assertEqual(ruido, 2)

    def test_erro_real_de_corretude_vira_achado(self):
        achados, ruido, fora = normalize_phpstan(
            self._payload("Undefined variable: $total"), "/repo")
        self.assertEqual(len(achados), 1)
        self.assertEqual((ruido, fora), (0, 0))
        self.assertEqual(achados[0].source, "phpstan")

    def test_mensagem_fora_do_mandato_e_descartada(self):
        achados, _, fora = normalize_phpstan(
            self._payload("Method X::y() has parameter $z with no value type specified in iterable type array."),
            "/repo")
        self.assertEqual(achados, [])
        self.assertEqual(fora, 1)

    def test_confianca_media_porque_o_phpstan_ve_o_codigo_pela_metade(self):
        achados, _, _ = normalize_phpstan(self._payload("Undefined variable: $x"), "/repo")
        self.assertEqual(achados[0].confidence, Confidence.MEDIA)


class ComplexidadeDoPhpmetrics(unittest.TestCase):
    def test_aceita_o_formato_de_dicionario(self):
        achados = normalize_phpmetrics({"App\\Helpers\\DateHelper": {"ccn": 36}}, "/repo")
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0].severity, Severity.ALTA)
        self.assertEqual(achados[0].metrics["cc"], 36)

    def test_aceita_o_formato_de_lista(self):
        achados = normalize_phpmetrics([{"name": "App\\X", "ccn": 20}], "/repo")
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0].severity, Severity.MEDIA)

    def test_classe_simples_fica_abaixo_do_piso(self):
        self.assertEqual(normalize_phpmetrics({"App\\Simples": {"ccn": 4}}, "/repo"), [])

    def test_fqcn_vira_caminho_psr4(self):
        achados = normalize_phpmetrics({"App\\Helpers\\DateHelper": {"ccn": 36}}, "/repo")
        self.assertEqual(achados[0].file, "app/Helpers/DateHelper.php")

    def test_bandas_em_ordem_decrescente(self):
        """Se a ordem quebrar, `next()` devolve a banda errada silenciosamente."""
        limiares = [lo for lo, _, _, _ in CC_BANDS]
        self.assertEqual(limiares, sorted(limiares, reverse=True))

    def test_limiares_iguais_aos_do_detector_python(self):
        """
        O scoring é cego à linguagem. Se as bandas divergirem, o mesmo débito
        recebe prioridade diferente só por causa do repo de origem.
        """
        from detectors.python import CC_BANDS as CC_PY
        self.assertEqual([lo for lo, _, _, _ in CC_BANDS],
                         [lo for lo, _, _, _ in CC_PY])

    def test_payload_invalido_nao_quebra(self):
        self.assertEqual(normalize_phpmetrics("lixo", "/repo"), [])
        self.assertEqual(normalize_phpmetrics({"X": {"ccn": "n/a"}}, "/repo"), [])


class MetricasDoPhploc(unittest.TestCase):
    """
    Regressão: o JSON real do phploc não usa as chaves do FERRAMENTAS.md.

    Com a leitura só pelas chaves documentadas, a ferramenta era reportada
    como "ok" entregando `? LOC, ? LLOC` — pior que falhar, porque parecia
    ter funcionado.
    """

    def test_le_o_schema_real_do_container(self):
        from detectors.php import _metricas_phploc
        texto = _metricas_phploc({"loc": 2802, "lloc": 900, "classes": 12,
                                  "classCcnAvg": 9.2, "classCcnMax": 36})
        self.assertIn("2802 LOC", texto)
        self.assertIn("36", texto)
        self.assertNotIn("?", texto)

    def test_le_o_schema_documentado_no_ferramentas_md(self):
        from detectors.php import _metricas_phploc
        texto = _metricas_phploc({
            "linesOfCode": 1840, "logicalLinesOfCode": 620,
            "cyclomaticComplexity": {"average": 4.5, "maximum": 18},
        })
        self.assertIn("1840 LOC", texto)
        self.assertIn("4.5", texto)

    def test_schema_desconhecido_nao_quebra(self):
        from detectors.php import _metricas_phploc
        self.assertIn("?", _metricas_phploc({}))


class InvocacaoDasFerramentas(unittest.TestCase):
    def test_phpmetrics_nao_usa_quiet(self):
        """
        Regressão medida no container: `--quiet` faz o phpmetrics sair com
        código 0 sem escrever o JSON. Falha silenciosa que custava as 6
        classes complexas do repo.
        """
        from detectors.php import cmd_phpmetrics
        self.assertNotIn("--quiet", cmd_phpmetrics("/tmp/x.json", "/repo/app"))

    def test_phpmetrics_escreve_json_no_destino_pedido(self):
        from detectors.php import cmd_phpmetrics
        self.assertIn("--report-json=/tmp/x.json", cmd_phpmetrics("/tmp/x.json", "/repo/app"))


class DegradacaoSemFerramenta(unittest.TestCase):
    def test_analyze_sem_nenhuma_ferramenta_ainda_produz_achados(self):
        """
        Requisito do README: o pipeline precisa funcionar sem as ferramentas.
        No PHP isso importa mais que no Python — os detectores builtin são a
        única fonte de segurança.
        """
        repo = _repo_temporario({
            "app/R.php": FIXTURE_SQL,
            "routes/web.php": '<?php Route::get("/", [X::class, "i"]);',
        })
        try:
            achados, runs = analyze(repo, use_semgrep=False)
            self.assertTrue(achados, "builtin deve achar mesmo sem ferramenta externa")
            self.assertTrue(any(r.name == "builtin:php" and r.ok for r in runs))
            # Fora do container as ferramentas não existem; dentro dele existem.
            # O teste vale nos dois casos: o que importa é que a ausência seja
            # REGISTRADA em vez de derrubar o pipeline.
            for nome in ("phpstan", "phpmetrics"):
                run = next(r for r in runs if r.name == nome)
                if shutil.which(nome) is None:
                    self.assertFalse(run.available)
                    self.assertIn("não instalada", run.error)
        finally:
            shutil.rmtree(repo)

    def test_repo_vazio_nao_levanta_excecao(self):
        repo = _repo_temporario({"README.md": "vazio"})
        try:
            achados, runs = analyze(repo, use_semgrep=False)
            self.assertEqual(achados, [])
            self.assertTrue(runs)
        finally:
            shutil.rmtree(repo)


class CoberturaDoQuestionario(unittest.TestCase):
    def test_sem_builtin_nao_declara_cobertura(self):
        """Não verificou, não afirma. É o erro do comercial da HourTrack."""
        self.assertEqual(cobertura_questionario(set()), set())
        self.assertEqual(cobertura_questionario({"phpstan", "phpmetrics"}), set())

    def test_q6_nunca_e_declarado_coberto(self):
        """`.env.example` é template, não configuração de produção."""
        self.assertNotIn("Q6", cobertura_questionario({"builtin:php"}))

    def test_builtin_cobre_os_itens_de_owasp(self):
        cobertos = cobertura_questionario({"builtin:php"})
        for item in ("Q1", "Q2", "Q3", "Q4", "Q7", "1.1"):
            self.assertIn(item, cobertos)


@unittest.skipUnless(os.path.isdir(REPO_ALVO), "repo PHP alvo não encontrado")
class IntegracaoNoRepoAlvo(unittest.TestCase):
    """Oráculo de regressão contra o código-alvo real."""

    @classmethod
    def setUpClass(cls):
        cls.achados, cls.runs = analyze(REPO_ALVO, use_semgrep=False)
        cls.por_local = {f"{f.file}:{f.line}": f for f in cls.achados}

    def _dt(self, debt_id):
        return [f for f in self.achados if f.debt_id == debt_id]

    def test_seis_locais_de_sql_injection(self):
        self.assertEqual(len(self._dt("DT-01")), 6)

    def test_sqli_alcancavel_pelo_request_tem_confianca_alta(self):
        alvo = self.por_local["app/Http/Controllers/ReportController.php:146"]
        self.assertEqual(alvo.confidence, Confidence.ALTA)
        self.assertTrue(alvo.publicly_reachable)

    def test_sqli_de_parametro_interno_fica_em_media(self):
        alvo = self.por_local["app/Services/BillingService.php:32"]
        self.assertEqual(alvo.confidence, Confidence.MEDIA)

    def test_queries_parametrizadas_nao_sao_reportadas(self):
        """
        O espelho do FP-03: `DB::select('... WHERE id = ?', [$x])` é seguro.
        Um scan que marca todo SQL geraria 13 falsos positivos aqui.
        """
        seguros = [
            "app/Http/Controllers/EverythingController.php:37",
            "app/Services/NotificationService.php:28",
            "app/Services/BillingService.php:24",
            "app/Console/Commands/SyncData.php:82",
            "app/Models/Customer.php:38",
            "app/Models/BillingCategory.php:51",
        ]
        for local in seguros:
            self.assertNotIn(local, self.por_local, f"falso positivo em {local}")

    def test_oito_credenciais_hardcoded(self):
        """4 em NotificationService, 3 em SyncData (ERP, CRM, Slack), 1 em ReportController."""
        self.assertEqual(len(self._dt("DT-04")), 8)

    def test_config_com_env_nao_gera_falso_positivo(self):
        """`config/` tem 8+ chaves credenciais vindas de env() — nenhuma é débito."""
        self.assertFalse([f for f in self.achados if f.file.startswith("config/")])

    def test_xss_no_template_monolitico(self):
        xss = self._dt("DT-02")
        self.assertEqual(len(xss), 1)
        self.assertEqual(xss[0].metrics["ocorrencias"], 7)

    def test_rotas_publicas_derrubam_o_item_de_autenticacao(self):
        rotas = self._dt("DT-06")
        self.assertEqual(len(rotas), 1)
        self.assertEqual(rotas[0].questionnaire_item, "1.1")

    def test_md5_nao_existe_no_repo_php(self):
        """
        Divergência verificada com o ground truth do Python: DT-03 NÃO se
        aplica aqui. Reportá-lo seria falso positivo importado do outro repo.
        """
        self.assertEqual(self._dt("DT-03"), [])

    def test_debug_do_template_nao_derruba_item_do_questionario(self):
        debug = self._dt("DT-05")
        self.assertEqual(len(debug), 1)
        self.assertIsNone(debug[0].questionnaire_item)
        self.assertEqual(debug[0].confidence, Confidence.MEDIA)

    def test_log_sensivel_no_middleware(self):
        log = self._dt("DT-08")
        self.assertEqual(len(log), 1)
        self.assertIn("LogEverything", log[0].file)

    def test_nao_reporta_sqlite_nem_env_commitado(self):
        """FP-01 e FP-02 valem para o repo PHP também."""
        suspeitos = [f for f in self.achados
                     if f.file.endswith(".sqlite") or f.file == ".env"]
        self.assertEqual(suspeitos, [])

    def test_deduplicacao_nao_perde_debito(self):
        antes = {f.debt_id for f in self.achados}
        depois = {f.debt_id for f in deduplicate(list(self.achados))}
        self.assertEqual(antes, depois)

    def test_determinismo_entre_execucoes(self):
        outra, _ = analyze(REPO_ALVO, use_semgrep=False)
        self.assertEqual([f.uid for f in self.achados], [f.uid for f in outra])
        self.assertEqual([f.to_dict() for f in self.achados],
                         [f.to_dict() for f in outra])


if __name__ == "__main__":
    unittest.main()

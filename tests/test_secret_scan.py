"""Tests for secret scanning (rule engine + module). No live httpx calls."""

import json

from reconecoboost.analysis.secrets import redact, scan_entropy, scan_text, shannon_entropy
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.modules.web.secret_scan import SecretScan
from reconecoboost.persistence import Database, Store


# --- rule engine ----------------------------------------------------------
def test_scan_detects_and_redacts():
    aws_key = "AKIA" + "A" * 16          # AKIA + 16 chars
    goog_key = "AIza" + "A" * 35         # AIza + 35 chars
    text = f'var k="{aws_key}"; const g="{goog_key}";'
    found = {m.rule for m in scan_text(text)}
    assert "AWS Access Key ID" in found
    assert "Google API Key" in found
    # the raw secret never survives — only a masked sample
    aws = next(m for m in scan_text(text) if m.rule == "AWS Access Key ID")
    assert aws_key not in aws.redacted
    assert aws.redacted.startswith("AKIA")


def test_scan_leaked_credential_keyword_list():
    # provider keywords from the h4x0r-dz list, as `keyword = "value"`
    text = 'cloudflare_api_key = "abcd1234efgh5678ijkl"; datadog_app_key: "ZZZ99887766554433aa"'
    rules = {m.rule for m in scan_text(text)}
    assert "Leaked Credential Assignment" in rules
    found_values_safe = all("abcd1234efgh5678ijkl" not in m.redacted for m in scan_text(text))
    assert found_values_safe  # value redacted
    # placeholders still dropped even with the broad list
    assert scan_text('cloudflare_api_key = "your_api_key_here"') == []


def test_scan_drops_obvious_placeholders():
    assert scan_text('api_key = "your_api_key_here_xxxx"') == []
    assert scan_text('token: "EXAMPLE_SAMPLE_TOKEN_VALUE"') == []


def test_new_provider_rules():
    cases = {
        "OpenAI API Key": "sk-" + "A" * 24 + "T3BlbkFJ" + "B" * 24,
        "GitLab PAT": "glpat-" + "a" * 20,
        "npm Access Token": "npm_" + "a" * 36,
        "Stripe API Key": "sk_live_" + "a" * 30,
        "Postman API Token": "PMAK-" + "a" * 24 + "-" + "b" * 34,
        "Google Service Account Key": '{"type": "service_account", "project_id": "x"}',
    }
    for rule_name, sample in cases.items():
        assert rule_name in {m.rule for m in scan_text(sample)}, rule_name


def test_entropy_detection_is_opt_in():
    # a random-looking quoted secret that matches NO regex rule
    blob = 'const k = "Zx9Qa72KdLpW3vY8Tb1Rc5Ne0Mf6Hg4Uj"; '
    assert scan_text(blob) == []                       # off by default
    hits = scan_text(blob, entropy=True)
    assert any(m.rule == "High-Entropy String" for m in hits)


def test_entropy_skips_hashes_and_lowentropy():
    assert scan_entropy('"' + "a" * 40 + '"') == []     # low entropy
    assert scan_entropy('"' + "abcdef0123456789" * 4 + '"') == []  # 64-char sha256-like, skipped


def test_shannon_entropy_orders_random_above_words():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("Zx9Qa72KdLpW3vY8")


def test_redact_short_and_long():
    assert "secret" not in redact("supersecretlongvalue1234")
    assert redact("abc") == "a****"


# --- module (reads bodies cached by js_fetch) -----------------------------
def _write_bodies(tmp_path, mapping):
    rdir = tmp_path / "responses"
    rdir.mkdir(parents=True, exist_ok=True)
    index = []
    for i, (url, body) in enumerate(mapping.items()):
        fname = f"body-{i:04d}.txt"
        (rdir / fname).write_text(body, encoding="utf-8")
        index.append({"url": url, "file": fname})
    (rdir / "index.json").write_text(json.dumps(index), encoding="utf-8")


def _ctx(store, tmp_path):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), repository=store, results_dir=tmp_path,
    )


def test_secret_scan_stores_findings_and_results(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    gh_token = "ghp_" + "A" * 36
    _write_bodies(tmp_path, {"https://a.example.com/app.js": f'const t="{gh_token}";'})
    ctx = _ctx(store, tmp_path)
    store.start_run(ctx)

    result = SecretScan().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    secrets = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "secret"]
    assert len(secrets) == 1
    assert "GitHub Token" in secrets[0]["title"]
    assert gh_token not in json.dumps(dict(secrets[0]))   # redacted
    assert (tmp_path / "secrets.json").exists()
    assert "GitHub Token" in (tmp_path / "secrets.txt").read_text()
    store.close()


def test_secret_scan_no_bodies_is_noop(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = _ctx(store, tmp_path)        # no responses/index.json
    store.start_run(ctx)
    result = SecretScan().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert result.meta == {"bodies": 0}
    store.close()

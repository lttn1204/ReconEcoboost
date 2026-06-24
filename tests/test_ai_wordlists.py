"""Tests for the generative AI wordlist modules (ai_subwords/ai_dirwords/ai_params).

Uses StubProvider (canned parsed payload) — no network / no real API call.
"""

from reconecoboost.ai.base import AIProvider, AIResponse
from reconecoboost.ai.stub import StubProvider
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.modules.web.ai_wordlists import AiDirwords, AiParams, AiSubwords
from reconecoboost.persistence import Database, Store


class RaisingProvider(AIProvider):
    def generate(self, prompt, *, schema=None, system=None, max_tokens=None, effort=None):
        raise RuntimeError("model exploded")


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def _ctx(store, tmp_path, ai, pipeline=None):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline=pipeline or {}), repository=store, results_dir=tmp_path, ai=ai,
    )


def _seed_subs(store, ctx, names):
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", n, attributes={"resolved": True}, tool="subfinder") for n in names
    ]))


# --- ai_subwords -----------------------------------------------------------
def test_ai_subwords_writes_sanitized_seam(tmp_path):
    store = _store()
    provider = StubProvider(parsed={"words": [
        "lpb-staging",          # valid
        "API.EXAMPLE.COM",      # full FQDN -> label "api"
        "bad_underscore",       # invalid label char -> dropped
        "x..y",                 # -> "x"
        "lpb-qa", "lpb-staging" # dup dropped
    ]})
    ctx = _ctx(store, tmp_path, provider)
    _seed_subs(store, ctx, ["api.example.com", "lpb-dev.example.com"])

    result = AiSubwords().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    words = [w for w in (tmp_path / "ai_subwords.txt").read_text().splitlines() if not w.startswith("#")]
    assert "lpb-staging" in words and "lpb-qa" in words and "api" in words and "x" in words
    assert "bad_underscore" not in words
    assert words.count("lpb-staging") == 1   # deduped
    # provenance finding recorded
    notes = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "recon_note"]
    assert any("ai_subwords" in f["title"] for f in notes)
    store.close()


def test_ai_subwords_inert_without_ai(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, None)            # --no-ai => ctx.ai is None
    _seed_subs(store, ctx, ["api.example.com"])

    result = AiSubwords().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.meta.get("inert") is True
    assert not (tmp_path / "ai_subwords.txt").exists()   # seam untouched -> brute runs as before
    store.close()


def test_ai_subwords_skips_without_context(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, StubProvider(parsed={"words": ["x"]}))
    store.start_run(ctx)                          # no subdomains seeded
    result = AiSubwords().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert "skipped" in result.meta            # reason surfaced (no context)
    assert result.error                        # shown in the run summary
    store.close()


def test_ai_subwords_ai_error_is_inert(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, RaisingProvider())
    _seed_subs(store, ctx, ["api.example.com"])

    result = AiSubwords().run(ctx)               # provider raises -> must not crash

    assert result.status == ModuleStatus.SUCCESS
    assert "model exploded" in (result.error or "")
    store.close()


def test_ai_subwords_respects_max_words(tmp_path):
    store = _store()
    provider = StubProvider(parsed={"words": [f"lab{i}" for i in range(50)]})
    ctx = _ctx(store, tmp_path, provider, {"ai_subwords": {"max_words": 5}})
    _seed_subs(store, ctx, ["api.example.com"])

    AiSubwords().run(ctx)

    words = [w for w in (tmp_path / "ai_subwords.txt").read_text().splitlines() if not w.startswith("#")]
    assert len(words) == 5
    store.close()


# --- ai_dirwords / ai_params sanitizers ------------------------------------
def test_ai_dirwords_sanitize_and_write(tmp_path):
    store = _store()
    provider = StubProvider(parsed={"words": ["actuator/env", "/admin/", "has space", "..", "v2"]})
    ctx = _ctx(store, tmp_path, provider)
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api/v1", tool="katana"),
    ]))

    AiDirwords().run(ctx)

    words = [w for w in (tmp_path / "ai_dirwords.txt").read_text().splitlines() if not w.startswith("#")]
    assert "actuator/env" in words and "admin" in words and "v2" in words
    assert "has space" not in words and ".." not in words
    store.close()


def test_ai_params_sanitize_and_write(tmp_path):
    store = _store()
    provider = StubProvider(parsed={"words": ["customerId", "cif_number", "bad param", "x"*60, "otpCode"]})
    ctx = _ctx(store, tmp_path, provider)
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api?accountId=1", tool="gau"),
    ]))

    AiParams().run(ctx)

    words = [w for w in (tmp_path / "ai_params.txt").read_text().splitlines() if not w.startswith("#")]
    assert "customerId" in words and "cif_number" in words and "otpCode" in words
    assert "bad param" not in words and ("x" * 60) not in words
    store.close()

"""Tests that the configured wordlist is auto-passed to ffuf."""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.dir_bruteforce import DirBruteforce, _DEFAULT_WORDLIST
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0, stdout="{}", duration_s=0.0
        )


def _ctx(executor, store, wordlists_config):
    return Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(wordlists=wordlists_config),
        executor=executor,
        tools=FakeTools(),
        repository=store,
    )


def _store_with_host():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    return store, db


def _seed_host(store, ctx):
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )


def test_configured_wordlist_is_passed():
    store, _ = _store_with_host()
    ex = FakeExecutor()
    cfg = {"wordlists": {"directories": {"path": "wordlists/ffuf/directories.txt"}}}
    ctx = _ctx(ex, store, cfg)
    _seed_host(store, ctx)

    DirBruteforce().run(ctx)

    argv = ex.calls[-1]
    assert "-w" in argv
    assert argv[argv.index("-w") + 1] == "wordlists/ffuf/directories.txt"
    assert "--json" in argv  # feroxbuster JSON output to stdout
    store.close()


def test_falls_back_to_default_wordlist():
    store, _ = _store_with_host()
    ex = FakeExecutor()
    ctx = _ctx(ex, store, {})  # no wordlists configured
    _seed_host(store, ctx)

    DirBruteforce().run(ctx)

    argv = ex.calls[-1]
    assert argv[argv.index("-w") + 1] == _DEFAULT_WORDLIST
    store.close()


def test_shipped_starter_wordlists_exist_and_nonempty():
    from pathlib import Path

    for name in ("directories.txt", "common.txt"):
        path = Path("wordlists/ffuf") / name
        assert path.exists(), f"missing starter wordlist: {path}"
        # at least one real (non-comment, non-blank) entry
        entries = [
            line for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert entries, f"{path} has no usable entries"

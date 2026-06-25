"""Tests for the Phase-0 AI seam: extra wordlists read from results/<run_id>/.

The seam lets a future AI stage steer brute/fuzz modules by writing
``ai_subwords.txt`` / ``ai_dirwords.txt``; with no file the behaviour is
unchanged (inert).
"""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import (
    ExecutionResult,
    ExecutionStatus,
    Normalizer,
    ParsedRecord,
    ToolHandle,
)
from reconecoboost.modules.web.dir_bruteforce import DirBruteforce
from reconecoboost.modules.web.dns_resolve import DnsResolve
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.0"


class FakeExecutor:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS,
                               exit_code=0, stdout=self.stdout, duration_s=0.1)


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


# --- dns_resolve brute consumes ai_subwords.txt --------------------------
def test_dns_brute_folds_ai_subwords(tmp_path):
    (tmp_path / "ai_subwords.txt").write_text("# ai\nadminpanel\n", encoding="utf-8")
    wl = tmp_path / "subs.txt"
    wl.write_text("dev\n", encoding="utf-8")
    store = _store()
    ex = FakeExecutor("")
    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline={"dns_resolve": {"brute": {"enabled": True, "wordlist": str(wl)}}}),
        executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize(
        [ParsedRecord("subdomain", "www.example.com", tool="subfinder")]))

    DnsResolve().run(ctx)

    # brute candidates are streamed to a file (dnsx -l), not stdin
    fed = set((tmp_path / "dns_candidates.txt").read_text().split())
    assert "dev.example.com" in fed             # base wordlist
    assert "adminpanel.example.com" in fed      # AI seam word folded in
    store.close()


# --- dir_bruteforce merges ai_dirwords.txt into the wordlist --------------
def test_dir_bruteforce_merges_ai_dirwords(tmp_path):
    base = tmp_path / "dirs.txt"
    base.write_text("admin\nlogin\n", encoding="utf-8")
    (tmp_path / "ai_dirwords.txt").write_text("# ai\ngraphql\nadmin\n", encoding="utf-8")
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(wordlists={"wordlists": {"directories": {"path": str(base)}}}),
        results_dir=tmp_path,
    )
    path = DirBruteforce()._wordlist(ctx)
    words = (tmp_path / "dir_wordlist_merged.txt").read_text().split()

    assert path.endswith("dir_wordlist_merged.txt")
    assert words == ["admin", "login", "graphql"]   # base ∪ AI, deduped, order kept


def test_dir_bruteforce_no_ai_words_uses_base(tmp_path):
    base = tmp_path / "dirs.txt"
    base.write_text("admin\n", encoding="utf-8")
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(wordlists={"wordlists": {"directories": {"path": str(base)}}}),
        results_dir=tmp_path,
    )
    assert DirBruteforce()._wordlist(ctx) == str(base)   # unchanged when no AI file

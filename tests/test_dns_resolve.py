"""Tests for dnsx DNS resolution/enrichment + alive_detection internal skip."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.alive_detection import AliveDetection
from reconecoboost.modules.web.dns_resolve import DnsResolve
from reconecoboost.modules.web.parsers import DnsxParser
from reconecoboost.persistence import Database, Store


# --- parser ---------------------------------------------------------------
def test_dnsx_parser_flags_internal_and_ip():
    raw = "\n".join([
        json.dumps({"host": "api.example.com", "a": ["1.2.3.4"]}),
        json.dumps({"host": "lpb-dev.example.com", "a": ["10.20.1.5"]}),  # RFC1918
        json.dumps({"host": "nodata.example.com", "status_code": "NOERROR"}),  # no A -> skip
    ])
    recs = {r.key: r for r in DnsxParser().parse(raw)}
    assert recs["api.example.com"].attributes == {"resolved": True, "ip": ["1.2.3.4"]}
    assert recs["lpb-dev.example.com"].attributes["internal"] is True
    assert "nodata.example.com" not in recs  # NODATA is not a resolving host


def test_dnsx_parser_mixed_public_and_private_is_not_internal():
    # a host on a public IP that ALSO leaks internal IPs (e.g. GSLB) is reachable,
    # so it must NOT be flagged internal — but the leak is recorded as intel.
    raw = json.dumps({"host": "www.example.com", "a": ["1.2.3.4", "10.0.0.5"]})
    rec = DnsxParser().parse(raw)[0]
    assert "internal" not in rec.attributes          # reachable -> still probed
    assert rec.attributes["internal_ips"] == ["10.0.0.5"]


def test_dnsx_resolver_args_default_and_override():
    from reconecoboost.modules.web.dns_resolve import dnsx_resolver_args

    class _Ctx:
        def __init__(self, pipeline):
            self.config = Config(pipeline=pipeline)

    # explicit override wins
    assert dnsx_resolver_args(_Ctx({"dns_resolve": {"resolvers": ["1.1.1.1", "8.8.8.8"]}})) \
        == ["-r", "1.1.1.1,8.8.8.8"]
    # empty list => dnsx defaults (no -r)
    assert dnsx_resolver_args(_Ctx({"dns_resolve": {"resolvers": []}})) == []
    # unset => system resolvers (a -r flag, or empty if resolv.conf is unreadable)
    auto = dnsx_resolver_args(_Ctx({}))
    assert auto == [] or (auto[0] == "-r" and auto[1])


# --- module helpers -------------------------------------------------------
class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.0"


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                               stdout=self.stdout, duration_s=0.1)


def _store_with_subs(subs):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    return store


def test_dns_resolve_enriches_subdomain_assets():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    stdout = "\n".join([
        json.dumps({"host": "api.example.com", "a": ["1.2.3.4"]}),
        json.dumps({"host": "lpb-dev.example.com", "a": ["10.0.0.5"]}),
    ])
    ex = FakeExecutor(stdout)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "api.example.com", tool="subfinder"),
        ParsedRecord("subdomain", "lpb-dev.example.com", tool="subfinder"),
    ]))

    result = DnsResolve().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    by_key = {a["canonical_key"]: json.loads(a["attributes_json"] or "{}")
              for a in store.list_assets(ctx.run_id, "subdomain")}
    assert by_key["api.example.com"]["ip"] == ["1.2.3.4"]
    assert by_key["lpb-dev.example.com"]["internal"] is True
    store.close()


def test_dns_brute_generates_candidates_and_saves_results(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    # tiny brute wordlist
    wl = tmp_path / "subs.txt"
    wl.write_text("# comment\ndev\napi\nvpn\n", encoding="utf-8")
    # dnsx "resolves" only dev.example.com
    stdout = json.dumps({"host": "dev.example.com", "a": ["1.2.3.4"]})
    ex = FakeExecutor(stdout)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline={"dns_resolve": {"brute": {"enabled": True, "wordlist": str(wl)}}}),
        executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "www.example.com", tool="subfinder"),
    ]))

    result = DnsResolve().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    # brute candidates are streamed to a file and dnsx reads it with -l (not stdin),
    # so the full wordlist runs without living in memory.
    argv = ex.calls[0][0]
    assert "-l" in argv
    fed = set((tmp_path / "dns_candidates.txt").read_text().split())
    # words are brute-forced against the APEX (example.com), plus the known sub is resolved
    assert {"dev.example.com", "api.example.com", "vpn.example.com", "www.example.com"} <= fed
    # only the resolving one became an asset
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert "dev.example.com" in subs
    # results summary written for review
    summary = (tmp_path / "dns_resolve.txt").read_text()
    assert "dev.example.com" in summary and "1.2.3.4" in summary
    store.close()


def test_dns_brute_skipped_without_wildcard_scope(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    wl = tmp_path / "subs.txt"
    wl.write_text("dev\napi\n", encoding="utf-8")
    ex = FakeExecutor("")
    ctx = Context(  # exact-host scope, NO wildcard -> brute must not generate
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["example.com"]),
        config=Config(pipeline={"dns_resolve": {"brute": {"enabled": True, "wordlist": str(wl)}}}),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "example.com", tool="seed"),  # apex, in-scope
    ]))

    DnsResolve().run(ctx)

    fed = set(ex.calls[0][1].split())
    assert "dev.example.com" not in fed and "api.example.com" not in fed  # no brute
    assert "example.com" in fed                                           # but resolve still runs
    store.close()


def test_alive_detection_skips_internal_by_default():
    # Default prefer=public: internal-only hosts excluded, public hosts included.
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "api.example.com", attributes={"resolved": True, "ip": ["1.2.3.4"]}, tool="dnsx"),
        ParsedRecord("subdomain", "lpb-dev.example.com", attributes={"internal": True}, tool="dnsx"),
    ]))

    inputs = AliveDetection()._gather_inputs(ctx)

    assert "api.example.com" in inputs
    assert "lpb-dev.example.com" not in inputs   # internal-only, prefer=public -> skip
    store.close()


# --- network preference (public / internal / both) ------------------------
def test_network_preference_helpers():
    from reconecoboost.modules.web.dns_resolve import family_ips, host_reachable

    mixed = {"ip": ["1.2.3.4", "10.0.0.5"]}
    internal_only = {"internal": True}
    public_only = {"ip": ["1.2.3.4"]}

    # host_reachable: prefer drives inclusion, no skip_internal param
    assert host_reachable(public_only, "public") is True
    assert host_reachable(internal_only, "public") is False   # unreachable from outside
    assert host_reachable(internal_only, "internal") is True
    assert host_reachable(internal_only, "both") is True

    # family_ips picks the right subset for mixed hosts
    assert family_ips(mixed["ip"], "public") == ["1.2.3.4"]
    assert family_ips(mixed["ip"], "internal") == ["10.0.0.5"]
    assert sorted(family_ips(mixed["ip"], "both")) == ["1.2.3.4", "10.0.0.5"]


def _alive_inputs_for_prefer(prefer):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(pipeline={"dns_resolve": {"prefer": prefer}}), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "internal-only.example.com", attributes={"internal": True}, tool="dnsx"),
        ParsedRecord("subdomain", "public.example.com", attributes={"resolved": True, "ip": ["1.2.3.4"]}, tool="dnsx"),
    ]))
    inputs = AliveDetection()._gather_inputs(ctx)
    store.close()
    return inputs


def test_alive_detection_probes_internal_when_prefer_internal_or_both():
    for prefer in ("internal", "both"):
        inputs = _alive_inputs_for_prefer(prefer)
        assert "internal-only.example.com" in inputs   # internal host now probed/bruted
        assert "public.example.com" in inputs


def test_alive_detection_skips_internal_when_prefer_public():
    inputs = _alive_inputs_for_prefer("public")
    assert "internal-only.example.com" not in inputs
    assert "public.example.com" in inputs


def test_vhost_ip_family_follows_preference():
    from reconecoboost.modules.web.vhost_discovery import VhostDiscovery

    def targets_for(prefer):
        db = Database(":memory:")
        db.connect()
        db.initialize()
        store = Store(db)
        ctx = Context(
            domain=Domain.WEB,
            scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
            config=Config(pipeline={"dns_resolve": {"prefer": prefer}}), repository=store,
        )
        store.start_run(ctx)
        store.persist_normalization(ctx.run_id, Normalizer().normalize([
            ParsedRecord("subdomain", "www.example.com",
                         attributes={"resolved": True, "ip": ["1.2.3.4", "10.0.0.5"]}, tool="dnsx"),
        ]))
        combos = VhostDiscovery()._gather_inputs(ctx)
        store.close()
        return {c.split("|", 2)[1] for c in combos}   # the target host/IP of each combo

    assert "1.2.3.4" in targets_for("public") and "10.0.0.5" not in targets_for("public")
    assert "10.0.0.5" in targets_for("internal") and "1.2.3.4" not in targets_for("internal")
    both = targets_for("both")
    assert {"1.2.3.4", "10.0.0.5"} <= both

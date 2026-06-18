"""Raw tool output is captured to the results dir and linked in the DB."""

import sys

import reconecoboost.modules.web  # noqa: F401  (registers the subfinder parser)
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import CommandExecutor, ToolHandle
from reconecoboost.modules.base import ToolInvocation, ToolModule
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class _CapturingModule(ToolModule):
    """A real tool module backed by a python one-liner (so the real executor runs)."""

    name = "asset_discovery"  # reuses the registered subfinder parser
    domain = Domain.WEB
    tool = "subfinder"
    parser = "subfinder"
    input_type = None
    output_ext = "txt"

    def command(self, tool, item, ctx) -> ToolInvocation:
        return ToolInvocation([sys.executable, "-c", "print('a.example.com')"])


def test_raw_output_written_and_linked(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)

    results_dir = tmp_path / "results"
    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        executor=CommandExecutor(),
        tools=FakeTools(),
        repository=store,
        results_dir=results_dir,
    )
    store.start_run(ctx)

    _CapturingModule().run(ctx)

    # 1. raw file exists on disk under results/
    raw_file = results_dir / "asset_discovery-00.txt"
    assert raw_file.exists()
    assert "a.example.com" in raw_file.read_text()

    # 2. tool_run row records the capture path
    tool_runs = store.list_tool_runs(ctx.run_id)
    assert tool_runs[0]["capture_path"] == str(raw_file)

    # 3. provenance links the asset back to the raw file
    row = store.db.conn.execute("SELECT raw_ref FROM provenance").fetchone()
    assert row["raw_ref"] == str(raw_file)

    store.close()


def test_no_results_dir_means_no_capture(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)

    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        executor=CommandExecutor(),
        tools=FakeTools(),
        repository=store,
        results_dir=None,  # capture disabled
    )
    store.start_run(ctx)

    _CapturingModule().run(ctx)

    assert store.list_tool_runs(ctx.run_id)[0]["capture_path"] is None
    store.close()

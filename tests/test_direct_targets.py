"""Direct-target mode: explicit targets are probed without discovery."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, ToolHandle
from reconecoboost.modules.web.alive_detection import AliveDetection
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    """Captures stdin and returns an httpx-style JSONL line per fed host."""

    def __init__(self):
        self.input_text = None

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.input_text = input_text
        lines = []
        for host in (input_text or "").splitlines():
            host = host.strip()
            if host:
                lines.append(json.dumps(
                    {"url": f"https://{host}", "input": host, "status_code": 200}
                ))
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout="\n".join(lines), duration_s=0.0,
        )


def test_targets_probed_without_discovery():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor()

    # No subdomains in the store (asset_discovery did not run), two explicit targets.
    scope = Scope(
        targets=["a.com.vn", "elearning.a.com.vn"],
        in_scope=["a.com.vn", "elearning.a.com.vn"],
    )
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)

    AliveDetection().run(ctx)

    # both targets were fed to httpx via stdin
    fed = set((ex.input_text or "").split())
    assert fed == {"a.com.vn", "elearning.a.com.vn"}

    # both became host assets
    hosts = {h["canonical_key"] for h in store.list_assets(ctx.run_id, "host")}
    assert hosts == {"https://a.com.vn", "https://elearning.a.com.vn"}
    store.close()


def test_out_of_scope_target_excluded_from_probe():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor()

    # targets are always in scope, but out_of_scope still vetoes one of them
    scope = Scope(targets=["a.com.vn", "evil.com"], out_of_scope=["evil.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)

    AliveDetection().run(ctx)

    fed = set((ex.input_text or "").split())
    assert fed == {"a.com.vn"}  # evil.com excluded by out_of_scope
    store.close()

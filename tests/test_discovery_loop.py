"""Tests for the cross-module discovery loop (pipeline.discovery.loop)."""

from reconecoboost.core.models import Domain, ModuleResult, ModuleStatus, Stage
from reconecoboost.core.module import BaseModule
from reconecoboost.orchestration.pipeline import Pipeline


class _Rec(BaseModule):
    """Records how many times it ran, on a shared log list."""
    def __init__(self, name, runs, *, run_once=False, produces=()):
        self.name = name
        self.stage = Stage.DISCOVERY
        self.domain = Domain.WEB
        self.requires = ()
        self.produces = produces
        self.run_once = run_once
        self._runs = runs

    def run(self, ctx):
        self._runs.append(self.name)
        return ModuleResult(self.name, ModuleStatus.SUCCESS)


class _FakeRepo:
    """Returns a growing subdomain count for 2 rounds, then stable (converged)."""
    def __init__(self, counts):
        self._counts = counts
        self._i = 0

    def list_assets(self, run_id, asset_type):
        # called once per round (after cycle) for "subdomain"
        val = self._counts[min(self._i, len(self._counts) - 1)]
        self._i += 1
        return [object()] * val


class _Ctx:
    def __init__(self, pipeline_cfg, repo):
        self.run_id = "r"
        self.config = type("C", (), {"pipeline": pipeline_cfg})()
        self.repository = repo
        self.results = []

    def add_result(self, r):
        self.results.append(r)


def _pipeline(modules):
    p = Pipeline.__new__(Pipeline)
    p.order = modules
    return p


def test_loop_disabled_runs_each_module_once():
    runs = []
    mods = [_Rec("disco", runs), _Rec("final", runs, run_once=True)]
    ctx = _Ctx({"discovery": {"loop": {"enabled": False}}}, _FakeRepo([0]))
    _pipeline(mods).run(ctx)
    assert runs == ["disco", "final"]   # single pass, DAG order


def test_loop_reruns_cycle_and_finalizes_once():
    runs = []
    cycle = _Rec("disco", runs)
    final = _Rec("final", runs, run_once=True)
    # round1 -> 1 sub, round2 -> 2 subs, round3 -> 2 (converged) ... but rounds cap=3
    ctx = _Ctx({"discovery": {"loop": {"enabled": True, "rounds": 3}}}, _FakeRepo([1, 2, 2]))
    _pipeline([cycle, final]).run(ctx)
    # cycle ran 3 times (r1:1<r2? grew; r2 grew; r3: converged -> finalize), final once
    assert runs.count("disco") == 3
    assert runs.count("final") == 1
    assert runs[-1] == "final"   # finalize last


def test_loop_stops_early_on_convergence():
    runs = []
    cycle = _Rec("disco", runs)
    final = _Rec("final", runs, run_once=True)
    # round1 -> 5, round2 -> 5 (no new) => converge at round 2, finalize, stop
    ctx = _Ctx({"discovery": {"loop": {"enabled": True, "rounds": 9}}}, _FakeRepo([5, 5]))
    _pipeline([cycle, final]).run(ctx)
    assert runs.count("disco") == 2     # stopped at round 2, not 9
    assert runs.count("final") == 1

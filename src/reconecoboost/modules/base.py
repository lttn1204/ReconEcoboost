"""ToolModule — shared base for tool-wrapping recon modules.

Captures the flow every external-tool stage repeats (architecture doc 05/08):

    resolve tool -> build argv -> execute (CommandExecutor) -> record tool_run
      -> parse (Parser) -> scope-filter -> normalize (Normalizer) -> persist (Store)

A concrete module only declares its tool/parser/inputs and builds the argv. It
never touches subprocess, SQL, or raw stdout directly.

Scope enforcement (the Context side of the confirmed Context+Executor chokepoint)
is applied here: out-of-scope inputs are not scanned, and out-of-scope produced
records are dropped before persistence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..core.errors import ToolNotFoundError
from ..core.models import ModuleResult, ModuleStatus
from ..core.module import BaseModule
from ..engine import PARSERS, Normalizer
from ..engine.executor import redact_argv


# --------------------------------------------------------------------------- #
# Small URL helpers shared by modules and parsers                              #
# --------------------------------------------------------------------------- #


def host_of(value: str | None) -> str | None:
    """Extract the hostname from a URL or a bare host[:port]/path string."""
    if not value:
        return None
    if "://" in value:
        return urlparse(value).hostname
    return value.split("/")[0].split(":")[0] or None


def origin_of(value: str | None) -> str | None:
    """Return ``scheme://netloc`` for a URL, or ``None`` if it has no scheme."""
    if not value or "://" not in value:
        return None
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


@dataclass
class ToolInvocation:
    """One concrete command to run: an argv plus optional stdin text."""

    argv: list[str]
    input_text: str | None = None


class ToolModule(BaseModule):
    """Base class for modules that wrap a single external tool."""

    #: Canonical asset_type to read as inputs; ``None`` means use scope targets.
    input_type: str | None = None
    #: If True, feed all inputs to one invocation (via stdin); else one per input.
    batch: bool = False
    #: Per-module timeout override (seconds); ``None`` uses the executor default.
    timeout_s: float | None = None
    #: File extension for captured raw output (e.g. "jsonl", "json", "txt").
    output_ext: str = "txt"
    #: If True, re-feed discovered subdomains as seeds (recursive discovery),
    #: bounded by the configured depth.
    recursive: bool = False

    # -- to override by concrete modules -----------------------------------

    def command(self, tool, item: str, ctx) -> ToolInvocation:
        """Build the invocation for a single input (per-item mode)."""
        raise NotImplementedError

    def batch_command(self, tool, items: list[str], ctx) -> ToolInvocation:
        """Build the single invocation for all inputs (batch mode)."""
        raise NotImplementedError

    def commands(self, tool, item: str, ctx) -> list[ToolInvocation]:
        """Invocations for one input. Default: a single ``command()``.

        Override to run several invocations per input — e.g. dir_bruteforce runs
        one ffuf pass per configured HTTP method.
        """
        return [self.command(tool, item, ctx)]

    # -- the shared flow ----------------------------------------------------

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)

        if ctx.executor is None or ctx.tools is None:
            raise NotImplementedError("engine services not available on context")

        try:
            tool = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.SKIPPED
            result.error = str(exc)
            return result

        version = ctx.tools.version(self.tool)
        parser = PARSERS.get(self.parser)

        # Seed targets (input_type is None) are explicit operator input — always
        # run discovery on them. Everything derived from the store is scope-gated,
        # so probing/crawling/fuzzing/fingerprinting only touch in-scope hosts.
        if self.input_type is None:
            frontier = list(self._gather_inputs(ctx))
        else:
            frontier = [i for i in self._gather_inputs(ctx) if self._scope_ok(ctx, i)]

        rate_args = self._rate_args(ctx)
        records = []

        # Inject any extra records (e.g. seed targets), scope-filtered like the rest.
        for record in self.extra_records(ctx):
            if self._record_in_scope(ctx, record):
                records.append(record)

        if not frontier and not records:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"items": 0}
            return result

        # Recursive discovery: re-feed newly-found subdomains as seeds, up to
        # `depth` levels, stopping early when a level finds nothing new.
        depth = self._recursion_depth(ctx) if self.recursive else 1
        seen: set[str] = set()
        capture_index = 0
        levels = 0

        while frontier and levels < depth:
            current = [t for t in frontier if t not in seen]
            if not current:
                break
            seen.update(current)
            levels += 1

            if self.batch:
                pairs = [(None, self.batch_command(tool, current, ctx))]
            else:
                pairs = [
                    (item, inv)
                    for item in current
                    for inv in self.commands(tool, item, ctx)
                ]

            timeout = self._timeout(ctx)
            executed = self._execute(ctx, pairs, rate_args, timeout)

            # Persist on THIS (main) thread only — the SQLite connection is
            # single-thread. Iterate in input order so capture files stay deterministic.
            level_records = []
            for idx, item, argv, exec_result in sorted(executed, key=lambda r: r[0]):
                capture_path = self._write_capture(ctx, capture_index, exec_result)
                capture_index += 1
                self._record_tool_run(ctx, version, argv, exec_result, capture_path)
                if not exec_result.ok:
                    continue
                parsed = self.refine_records(ctx, item, parser.parse(exec_result.stdout))
                for record in parsed:
                    if self._record_in_scope(ctx, record):
                        if capture_path:
                            record.raw_ref = capture_path
                        level_records.append(record)

            records.extend(level_records)

            # Next level: newly-discovered, in-scope subdomains not already scanned.
            if self.recursive:
                frontier = [
                    r.key for r in level_records
                    if r.asset_type == "subdomain"
                    and r.key not in seen
                    and self._scope_ok(ctx, r.key)
                ]
            else:
                frontier = []

        records = self.finalize_records(ctx, records)
        norm = Normalizer().normalize(records)
        if ctx.repository is not None:
            counts = ctx.repository.persist_normalization(ctx.run_id, norm)
            result.produced = counts["assets"]
            result.meta = {"levels": levels, "relations": counts["relations"]}
        else:
            result.produced = len(norm.entities)
            result.meta = {"levels": levels}

        self.after_persist(ctx, norm.entities)

        result.status = ModuleStatus.SUCCESS
        return result

    def _execute(self, ctx, pairs, rate_args, timeout) -> list:
        """Run the invocations, parallelizing ACROSS hosts.

        Different hosts are different servers, so they run concurrently (each keeps
        its own tool rate limit); a single host's invocations stay serial so we never
        exceed that host's rate. Worker threads ONLY call the subprocess executor —
        no DB, no file writes, no parsing — because SQLite is single-thread and those
        happen on the caller's thread afterwards. Returns ``[(idx, item, argv, result)]``.
        """
        # Group by host, preserving each pair's original index for deterministic output.
        groups: dict[str, list] = {}
        for idx, (item, inv) in enumerate(pairs):
            key = host_of(item) or f"__batch_{idx}"   # batch/no-host → its own group
            groups.setdefault(key, []).append((idx, item, inv))

        def run_group(group: list) -> list:
            out = []
            for idx, item, inv in group:
                argv = inv.argv + rate_args
                exec_result = ctx.executor.run(
                    argv, timeout_s=timeout, input_text=inv.input_text
                )
                out.append((idx, item, argv, exec_result))
            return out

        workers = min(self._concurrency(ctx), len(groups))
        if workers <= 1:
            executed: list = []
            for group in groups.values():
                executed.extend(run_group(group))
            return executed

        executed = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_group, g) for g in groups.values()]
            for future in as_completed(futures):
                executed.extend(future.result())
        return executed

    def _concurrency(self, ctx) -> int:
        """How many hosts to scan in parallel: ``pipeline.<module>.concurrency`` if set,
        else the global ``pipeline.max_concurrent_targets`` (default 5). 1 = serial."""
        pipeline = ctx.config.pipeline or {}
        spec = (pipeline.get(self.name, {}) or {})
        val = spec.get("concurrency", pipeline.get("max_concurrent_targets", 5))
        try:
            return max(1, int(val))
        except (TypeError, ValueError):
            return 5

    def extra_records(self, ctx) -> list:
        """Records to contribute beyond tool output (e.g. seed targets).

        Default none. Overridden by discovery to inject the explicit target(s)
        so they flow through the pipeline even if a tool doesn't surface them.
        Still subject to scope filtering.
        """
        return []

    def after_persist(self, ctx, entities) -> None:
        """Hook called after results are persisted.

        Default no-op. Modules override to log result detail or write derived
        findings (e.g. dir_bruteforce logs status/size and flags catch-alls).
        """
        return None

    # -- helpers ------------------------------------------------------------

    def _capture_path(self, ctx, index: int):
        """Path to write this invocation's output, or None if not capturing."""
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return None
        return results_dir / f"{self.name}-{index:02d}.{self.output_ext}"

    def _write_capture(self, ctx, index: int, exec_result) -> str | None:
        """Write this invocation's output to the results dir; return its path.

        Content comes from :meth:`format_capture` (verbatim by default), so a
        module can save a cleaner, human-readable file instead of raw stdout.
        """
        if getattr(ctx, "results_dir", None) is None or not exec_result.ok:
            return None
        content = self.format_capture(exec_result.stdout)
        if not content:
            return None
        path = self._capture_path(ctx, index)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def finalize_records(self, ctx, records: list) -> list:
        """Transform the full record list before normalization (default: unchanged).

        Runs once after all invocations. Used e.g. by dir_bruteforce to fold
        per-method results for the same URL into one record.
        """
        return records

    def refine_records(self, ctx, item, records: list) -> list:
        """Per-invocation hook to adjust parsed records before scope-filtering.

        ``item`` is the input that produced this invocation (None for batch).
        Default: unchanged. Used e.g. by vhost discovery to turn a bare ``FUZZ``
        keyword into the full hostname ``FUZZ.<domain>``.
        """
        return records

    def format_capture(self, raw_stdout: str) -> str:
        """Format raw tool output for the saved results file. Default: verbatim.

        Override to save a tidier, readable file (e.g. dir_bruteforce renders one
        endpoint per line). The parser still receives the raw stdout.
        """
        return raw_stdout

    def _recursion_depth(self, ctx) -> int:
        """Recursive discovery depth from config (pipeline.discovery.recursive_depth)."""
        discovery = (ctx.config.pipeline.get("discovery", {}) or {})
        try:
            depth = int(discovery.get("recursive_depth", 1))
        except (TypeError, ValueError):
            depth = 1
        return max(1, depth)

    def _timeout(self, ctx) -> float | None:
        """Per-invocation timeout: ``pipeline.<module>.timeout_s`` if set, else the
        class default (``self.timeout_s``, usually None → executor default).

        Lets slow stages (e.g. dns_resolve over a multi-million-word brute) raise
        their own ceiling without hitting the short global executor default.
        """
        spec = (ctx.config.pipeline.get(self.name, {}) or {})
        val = spec.get("timeout_s")
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                return self.timeout_s
        return self.timeout_s

    def _rate_args(self, ctx) -> list[str]:
        """Return the tool's native requests-per-second flag, from config.

        Resolution: per-tool ``rate_limit`` if set, else ``defaults.rate_limit``.
        A value of ``None`` or ``<= 0`` (and a tool without a ``rate_flag``)
        means unlimited — no flag is injected.
        """
        tools_cfg = ctx.config.tools or {}
        spec = (tools_cfg.get("tools", {}) or {}).get(self.tool, {}) or {}
        flag = spec.get("rate_flag")
        if not flag:
            return []
        rate = spec.get("rate_limit")
        if rate is None:
            rate = (tools_cfg.get("defaults", {}) or {}).get("rate_limit")
        if not rate or rate <= 0:
            return []
        return [flag, str(int(rate))]

    def _extra_wordlist(self, ctx, name: str) -> list[str]:
        """Read an optional extra wordlist from ``results/<run_id>/<name>.txt``.

        This is the **AI seam**: deterministic brute/fuzz stages call this and
        transparently consume words an AI stage may write later (e.g.
        ``ai_subwords.txt`` / ``ai_dirwords.txt``). No file -> empty list, so the
        seam is inert until an AI module populates it. Comment lines (``#``) and
        blanks are skipped; entries are stripped.
        """
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return []
        path = Path(results_dir) / f"{name}.txt"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]

    def _gather_inputs(self, ctx) -> list[str]:
        if self.input_type is None:
            return list(ctx.scope.targets)
        if ctx.repository is None:
            return []
        return [
            asset["canonical_key"]
            for asset in ctx.repository.list_assets(ctx.run_id, self.input_type)
        ]

    @staticmethod
    def _scope_ok(ctx, item: str) -> bool:
        host = host_of(item)
        return True if host is None else ctx.scope.is_allowed(host)

    def _record_in_scope(self, ctx, record) -> bool:
        host = self._record_host(record)
        return True if host is None else ctx.scope.is_allowed(host)

    @staticmethod
    def _record_host(record) -> str | None:
        if record.asset_type in ("subdomain", "host"):
            return host_of(record.key)
        if record.asset_type in ("url", "endpoint"):
            return host_of(record.key)
        return None  # technology / artifact: scope already enforced on its host

    def _record_tool_run(self, ctx, version, argv, exec_result, capture_path=None) -> None:
        if ctx.repository is None:
            return
        ctx.repository.record_tool_run(
            ctx.run_id,
            tool=self.tool,
            module=self.name,
            version=version,
            argv_redacted=redact_argv(argv),
            exit_code=exec_result.exit_code,
            status=exec_result.status.value,
            duration_s=exec_result.duration_s,
            capture_path=capture_path,
        )

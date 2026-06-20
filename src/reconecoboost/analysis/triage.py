"""Deterministic triage — rank discovered assets by signal, no LLM.

Synthesizes three field-proven open-source approaches, improved:

* **uro** (s0md3v) — declutters URL lists by collapsing same-path/different-value
  URLs and dropping static files. We adopt the heuristics but **non-destructively**:
  nothing is removed from the store; noise is only *demoted/grouped* for display.
* **reNgine** (yogeshojha) — flags "interesting" assets by configurable keywords
  and dedups by status+length. We keep this, but never drop 401/403 (they're
  signal, not noise) and add HTTP-method awareness it lacks.
* **gf-patterns** (1ndianl33t/tomnomnom) — per-vuln-class parameter name sets.
  We use them to *tag* a URL with the likely bug class (sqli/lfi/ssrf/…), giving
  the human and the agent a free, evidence-backed lead.

The output is a ranked list with a score + human reasons + vuln-class tags, plus
collapsed noise clusters. Pure functions only (easy to test, zero side effects).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, urlsplit

# --- gf-patterns-derived parameter name sets (vuln-class tagging) ------------
PARAM_CLASSES: dict[str, set[str]] = {
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name", "sort",
             "where", "search", "params", "process", "row", "view", "table", "from", "sel",
             "results", "fetch", "order", "keyword", "column", "field", "delete", "string",
             "number", "filter"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template",
            "php_path", "doc", "page", "cat", "dir", "action", "board", "date", "detail",
            "download", "prefix", "include", "inc", "locate", "show", "site", "type",
            "content", "layout", "mod", "conf"},
    "ssrf": {"url", "uri", "dest", "destination", "redirect", "redirect_uri", "redirect_url",
             "return", "return_url", "next", "data", "reference", "site", "html", "val",
             "domain", "callback", "feed", "host", "port", "to", "out", "navigation", "open",
             "continue", "window", "image_url", "img_url", "file_url", "load_url", "load_file",
             "forward", "go", "goto"},
    "redirect": {"redirect", "redirect_to", "redirect_uri", "redirect_url", "url", "uri",
                 "next", "next_page", "dest", "destination", "go", "goto", "return", "returnto",
                 "return_to", "return_url", "rurl", "redir", "out", "target", "to",
                 "login_url", "continue", "forward"},
    "xss": {"q", "s", "search", "query", "keyword", "id", "page", "view", "name", "message",
            "comment", "redirect", "url", "return", "callback", "ref", "u", "next", "data",
            "feedback", "email", "subject", "title", "body", "content", "input", "value"},
    "idor": {"id", "user", "user_id", "uid", "account", "number", "order", "no", "doc", "key",
             "email", "group", "profile", "edit", "report", "file", "row"},
    "ssti": {"template", "preview", "id", "view", "activity", "name", "content", "redirect",
             "page", "message"},
}

# --- uro-style "useless"/static extensions (declutter) ----------------------
STATIC_EXTS: set[str] = {
    "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tif", "tiff",
    "woff", "woff2", "ttf", "eot", "otf", "mp4", "mp3", "avi", "mov", "webm", "map", "wasm",
}

# --- reNgine-style interesting path keywords (high-value endpoints) ----------
PATH_KEYWORDS: set[str] = {
    "admin", "administrator", "login", "signin", "auth", "sso", "oauth", "token", "api",
    "graphql", "swagger", "openapi", "actuator", "dashboard", "console", "manage", "portal",
    "upload", "import", "export", "download", "backup", "dump", "config", "setting", "setup",
    "install", "debug", "trace", "test", "dev", "staging", "uat", "internal", "private",
    "secret", "credential", "jenkins", "gitlab", "phpmyadmin", "wp-admin", "wp-login",
    ".git", ".env", ".svn", "webhook", "payment", "invoice", "account", "profile",
}

# Tags that guarantee an asset is included in the curated AI context, even if it
# falls past the top-N cut — these are the high-value manual-testing leads.
GUARANTEED_TAGS: set[str] = {
    "method-anomaly", "dangerous-method", "sqli", "lfi", "ssrf", "redirect", "xss", "idor", "ssti",
}

DANGEROUS_METHODS: set[str] = {"PUT", "DELETE", "PATCH", "TRACE", "DEBUG", "CONNECT", "OPTIONS"}
_NOT_ACCEPTED = {400, 404, 405, 501}  # status markers for "method not accepted"

DEFAULT_WEIGHTS: dict[str, int] = {
    "nuclei_critical": 100, "nuclei_high": 80, "nuclei_medium": 50, "nuclei_low": 25,
    "nuclei_info": 5,
    "method_anomaly": 60, "non_get_accepted": 45, "dangerous_method": 50,
    "param_vuln_class": 35, "has_param": 20,
    "path_keyword": 40, "auth_status": 15, "tech": 20,
    "catch_all": -50, "static": -30, "duplicate": -20,
}
DEFAULT_CLUSTER_THRESHOLD = 5


# --- data ------------------------------------------------------------------
@dataclass
class ScoredTarget:
    key: str
    kind: str               # "host" | "url"
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    status: int | None = None


@dataclass
class TriageResult:
    targets: list[dict]     # full ranked list (highest first) — nothing dropped
    collapsed: list[dict]   # catch-all clusters {netloc,status,length,count,sample}
    stats: dict


# --- url helpers -----------------------------------------------------------
def _path(key: str) -> str:
    return urlsplit(key).path or "/"


def _ext(key: str) -> str:
    last = _path(key).rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def is_static(key: str) -> bool:
    return _ext(key) in STATIC_EXTS


def param_keys(key: str) -> set[str]:
    return set(parse_qs(urlsplit(key).query).keys())


def param_vuln_classes(keys: set[str]) -> list[str]:
    low = {k.lower() for k in keys}
    return sorted(c for c, names in PARAM_CLASSES.items() if low & names)


def path_keyword_hits(key: str) -> list[str]:
    p = _path(key).lower()
    return sorted(k for k in PATH_KEYWORDS if k in p)


def path_template(key: str) -> str:
    """uro-style key: same path + same param *names* (values ignored)."""
    s = urlsplit(key)
    return f"{s.scheme}://{s.netloc}{s.path}?{'&'.join(sorted(param_keys(key)))}"


def _methods_of(attrs: dict) -> dict:
    """Normalize per-method data to {VERB: {status, length}}.

    dir_bruteforce stores a `methods` dict; url_probe/httpx store a flat
    `status_code` — treat the latter as a GET probe.
    """
    methods = attrs.get("methods")
    if isinstance(methods, dict) and methods:
        return methods
    sc = attrs.get("status_code")
    if sc is not None:
        return {"GET": {"status": sc, "length": attrs.get("content_length")}}
    return {}


def _primary_status(methods: dict) -> int | None:
    if "GET" in methods:
        return (methods["GET"] or {}).get("status")
    for info in methods.values():
        st = (info or {}).get("status")
        if st is not None:
            return st
    return None


def _primary_length(methods: dict):
    for verb in ("GET", *methods):
        info = methods.get(verb) or {}
        if info.get("length") is not None:
            return info["length"]
    return None


def _method_signals(methods: dict) -> tuple[bool, bool, list[str]]:
    """Return (non_get_accepted, anomaly, dangerous_methods)."""
    get_status = (methods.get("GET") or {}).get("status")
    non_get_ok = anomaly = False
    dangerous: list[str] = []
    for verb, info in methods.items():
        if verb == "GET":
            continue
        st = (info or {}).get("status")
        if st is not None and 200 <= st < 300:
            non_get_ok = True
            if get_status is None or get_status >= 400:
                anomaly = True
        if verb in DANGEROUS_METHODS and st is not None and st not in _NOT_ACCEPTED:
            dangerous.append(verb)
    return non_get_ok, anomaly, sorted(set(dangerous))


def _index_findings(findings: list[dict]) -> dict[str, list[str]]:
    """Map asset key (host or matched URL) -> [severities] from nuclei findings."""
    fmap: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        for k in {k for k in (f.get("host"), f.get("matched_at")) if k}:  # dedupe same key
            fmap[k].append(sev)
    return fmap


def _apply_findings(t: ScoredTarget, fmap: dict[str, list[str]], w: dict) -> bool:
    sevs = fmap.get(t.key)
    if not sevs:
        return False
    for s in sevs:
        t.score += w.get(f"nuclei_{s}", w["nuclei_info"])
        t.tags.append(f"nuclei:{s}")
    t.reasons.append(f"nuclei finding(s): {', '.join(sevs)}")
    return True


# --- main ------------------------------------------------------------------
def score_targets(
    hosts: list[dict],
    urls: list[dict],
    findings: list[dict],
    *,
    weights: dict | None = None,
    cluster_threshold: int = DEFAULT_CLUSTER_THRESHOLD,
    top_n: int = 0,
) -> TriageResult:
    """Score hosts + urls. Inputs are dicts: {"key","attributes"}.

    findings: [{"severity","host","matched_at"}] (nuclei vulnerabilities).
    Returns the FULL ranked list (nothing removed); noise is demoted + grouped.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    fmap = _index_findings(findings)
    scored: list[ScoredTarget] = []

    # hosts: every live subdomain root, boosted by nuclei findings + tech
    for h in hosts:
        attrs = h.get("attributes") or {}
        t = ScoredTarget(key=h["key"], kind="host", status=attrs.get("status_code"))
        _apply_findings(t, fmap, w)
        tech = attrs.get("tech")
        if tech:
            t.score += w["tech"]
            t.reasons.append("tech: " + (", ".join(map(str, tech)) if isinstance(tech, list) else str(tech)))
        scored.append(t)

    # pre-compute catch-all clusters: many urls sharing (netloc, status, length)
    def cluster_key(u: dict):
        m = _methods_of(u.get("attributes") or {})
        return (urlsplit(u["key"]).netloc, _primary_status(m), _primary_length(m))

    counts = Counter(cluster_key(u) for u in urls)
    seen_templates: set[str] = set()
    collapsed: dict[tuple, int] = defaultdict(int)
    collapsed_sample: dict[tuple, str] = {}

    for u in urls:
        key = u["key"]
        attrs = u.get("attributes") or {}
        methods = _methods_of(attrs)
        t = ScoredTarget(key=key, kind="url", status=_primary_status(methods))

        has_finding = _apply_findings(t, fmap, w)

        non_get_ok, anomaly, dangerous = _method_signals(methods)
        if anomaly:
            t.score += w["method_anomaly"]
            t.reasons.append("method anomaly (non-GET 2xx where GET is blocked)")
            t.tags.append("method-anomaly")
        elif non_get_ok:
            t.score += w["non_get_accepted"]
            t.reasons.append("accepts non-GET method")
        if dangerous:
            t.score += w["dangerous_method"]
            t.reasons.append("dangerous method enabled: " + ", ".join(dangerous))
            t.tags.append("dangerous-method")

        pkeys = param_keys(key)
        classes = param_vuln_classes(pkeys)
        if classes:
            t.score += w["param_vuln_class"]
            t.tags.extend(classes)
            t.reasons.append("param vuln-class: " + ", ".join(classes))
        elif pkeys:
            t.score += w["has_param"]
            t.reasons.append("has parameter(s): " + ", ".join(sorted(pkeys)))

        kw = path_keyword_hits(key)
        if kw:
            t.score += w["path_keyword"]
            t.reasons.append("interesting path: " + ", ".join(kw))

        if t.status in (401, 403):
            t.score += w["auth_status"]
            t.reasons.append(f"auth-protected ({t.status})")

        # Noise demotion (display only) — NEVER applied to an asset carrying real
        # signal (a finding, a non-GET method, a vuln-class param, or a keyword).
        protected = has_finding or non_get_ok or bool(classes) or bool(kw) or bool(dangerous)
        if not protected:
            ck = cluster_key(u)
            if counts[ck] >= cluster_threshold:
                t.score += w["catch_all"]
                t.reasons.append(f"catch-all cluster (×{counts[ck]})")
                collapsed[ck] += 1
                collapsed_sample.setdefault(ck, key)
            if is_static(key):
                t.score += w["static"]
                t.reasons.append("static asset")
            tmpl = path_template(key)
            if tmpl in seen_templates:
                t.score += w["duplicate"]
                t.reasons.append("duplicate path template")
            seen_templates.add(tmpl)

        scored.append(t)

    scored.sort(key=lambda x: (-x.score, x.key))
    targets = [asdict(t) for t in scored]
    collapsed_list = [
        {"netloc": ck[0], "status": ck[1], "length": ck[2], "count": c,
         "sample": collapsed_sample[ck]}
        for ck, c in sorted(collapsed.items(), key=lambda kv: -kv[1])
    ]
    high = sum(1 for t in scored if t.score > 0)
    stats = {
        "hosts": len(hosts), "urls": len(urls), "scored": len(scored),
        "high_signal": high, "collapsed_clusters": len(collapsed_list),
        "top_n": top_n or len(scored),
    }
    return TriageResult(targets=targets, collapsed=collapsed_list, stats=stats)


def render_text(result: TriageResult, top_n: int = 25) -> str:
    """Human-readable ranked list for results/<run_id>/triage.txt."""
    lines = ["ReconEcoboost — deterministic triage (ranked targets)", ""]
    ranked = [t for t in result.targets if t["score"] > 0] or result.targets
    for i, t in enumerate(ranked[:top_n], 1):
        tags = f"  [{', '.join(t['tags'])}]" if t["tags"] else ""
        lines.append(f"{i:>3}. score={t['score']:<4} {t['key']}{tags}")
        if t["reasons"]:
            lines.append(f"       - {'; '.join(t['reasons'])}")
    if result.collapsed:
        lines.append("")
        lines.append("Collapsed noise clusters (catch-all — kept in DB, hidden here):")
        for c in result.collapsed:
            lines.append(
                f"  - {c['netloc']}  status={c['status']} len={c['length']}  ×{c['count']}"
                f"  (e.g. {c['sample']})"
            )
    lines.append("")
    lines.append(f"stats: {result.stats}")
    return "\n".join(lines) + "\n"

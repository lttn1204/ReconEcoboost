"""Deterministic secret detection — regex rules over fetched text (no LLM).

Rule lineage follows the common scanners (gitleaks / leaklens). This module is
PURE: it takes text and returns redacted matches. Matches are **redacted** before
they ever reach the store or a report — we keep the rule name, a masked sample,
and the line number, never the raw secret.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRule:
    name: str
    severity: str            # info | low | medium | high | critical
    pattern: re.Pattern
    group: int = 0           # capture group holding the secret (0 = whole match)


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern)


# Broad provider/credential keyword list from h4x0r-dz/Leaked-Credentials — matched
# as `keyword ... = "value"`. Supplements the precise rules below with much wider
# provider coverage. Keywords are escaped (literal), value must be 8–64 chars.
_LEAKED_CRED_KEYWORDS = (
    "access_key", "access_token", "admin_pass", "admin_user", "algolia_admin_key",
    "algolia_api_key", "alias_pass", "alicloud_access_key", "amazon_secret_access_key",
    "amazonaws", "ansible_vault_password", "aos_key", "api_key", "api_key_secret",
    "api_key_sid", "api_secret", "apidocs", "apikey", "apiSecret", "app_debug", "app_id",
    "app_key", "app_log_level", "app_secret", "appkey", "appkeysecret", "application_key",
    "appsecret", "appspot", "auth_token", "authorizationToken", "authsecret", "aws_access",
    "aws_access_key_id", "aws_bucket", "aws_key", "aws_secret", "aws_secret_key", "aws_token",
    "AWSSecretKey", "b2_app_key", "bintray_apikey", "bintray_gpg_password", "bintray_key",
    "bintraykey", "bluemix_api_key", "bluemix_pass", "browserstack_access_key",
    "bucket_password", "bucketeer_aws_access_key_id", "bucketeer_aws_secret_access_key",
    "built_branch_deploy_key", "bx_password", "cache_s3_secret_key", "cattle_access_key",
    "cattle_secret_key", "certificate_password", "ci_deploy_password", "client_secret",
    "client_zpk_secret_key", "clojars_password", "cloud_api_key", "cloud_watch_aws_access_key",
    "cloudant_password", "cloudflare_api_key", "cloudflare_auth_key", "cloudinary_api_secret",
    "codecov_token", "conn.login", "connectionstring", "consumer_key", "consumer_secret",
    "credentials", "cypress_record_key", "database_password", "datadog_api_key",
    "datadog_app_key", "db_password", "db_username", "dbpasswd", "dbpassword", "dbuser",
    "deploy_password", "digitalocean_ssh_key_body", "digitalocean_ssh_key_ids",
    "docker_hub_password", "docker_key", "docker_pass", "docker_passwd", "docker_password",
    "dockerhub_password", "dockerhubpassword", "droplet_travis_password", "dynamoaccesskeyid",
    "dynamosecretaccesskey", "elasticsearch_password", "encryption_key", "encryption_password",
    "env.heroku_api_key", "env.sonatype_password", "eureka.awssecretkey", "heroku_api_key",
    "sonatype_password", "secret_key", "secret_token", "private_key", "passwd", "password",
)
_LEAKED_ALT = "|".join(re.escape(k) for k in _LEAKED_CRED_KEYWORDS)


# High-signal, low-false-positive rules. Extend freely — order doesn't matter.
SECRET_RULES: list[SecretRule] = [
    SecretRule("AWS Access Key ID", "high", _c(r"\bAKIA[0-9A-Z]{16}\b")),
    SecretRule("AWS Secret Access Key", "critical",
               _c(r"""(?i)aws.{0,20}?(?:secret|sk).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]"""), group=1),
    SecretRule("Google API Key", "high", _c(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    SecretRule("Google OAuth Access Token", "high", _c(r"\bya29\.[0-9A-Za-z\-_]{20,}")),
    SecretRule("GitHub Token", "high", _c(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    SecretRule("GitHub Fine-grained PAT", "high", _c(r"\bgithub_pat_[0-9A-Za-z_]{82}\b")),
    SecretRule("Slack Token", "high", _c(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    SecretRule("Slack Webhook", "medium",
               _c(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+")),
    SecretRule("Stripe Secret Key", "critical", _c(r"\bsk_live_[0-9a-zA-Z]{24}\b")),
    SecretRule("SendGrid API Key", "high", _c(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    SecretRule("Twilio API Key", "high", _c(r"\bSK[0-9a-fA-F]{32}\b")),
    SecretRule("Mailgun API Key", "high", _c(r"\bkey-[0-9a-zA-Z]{32}\b")),
    SecretRule("JSON Web Token", "low",
               _c(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    SecretRule("Private Key", "critical",
               _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    SecretRule("Generic Secret Assignment", "medium",
               _c(r"""(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|auth)['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_/+=.]{16,64})['"]"""),
               group=1),
    SecretRule("Firebase Database URL", "info", _c(r"https://[a-z0-9-]+\.firebaseio\.com")),
    SecretRule("Cloud Storage Bucket", "info",
               _c(r"(?:s3://[a-z0-9.\-]{3,}|[a-z0-9.\-]{3,}\.s3\.amazonaws\.com|storage\.googleapis\.com/[a-z0-9._\-]+)")),
    # --- precise provider rules adapted from gitleaks (low false-positive) ----
    SecretRule("OpenAI API Key", "critical", _c(r"\bsk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b")),
    SecretRule("Anthropic API Key", "critical", _c(r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,}\b")),
    SecretRule("GitLab PAT", "high", _c(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    SecretRule("npm Access Token", "high", _c(r"\bnpm_[A-Za-z0-9]{36}\b")),
    SecretRule("Stripe API Key", "critical", _c(r"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b")),
    SecretRule("Square Access Token", "high", _c(r"\b(?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60}\b")),
    SecretRule("Shopify Token", "high", _c(r"\bshp(?:at|pa|ca|ss)_[a-fA-F0-9]{32}\b")),
    SecretRule("PyPI Upload Token", "high", _c(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    SecretRule("Postman API Token", "high", _c(r"\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\b")),
    SecretRule("Telegram Bot Token", "high", _c(r"\b\d{5,16}:A[A-Za-z0-9_\-]{34}\b")),
    SecretRule("Discord Bot Token", "medium",
               _c(r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b")),
    SecretRule("Discord Webhook", "medium",
               _c(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,21}/[A-Za-z0-9_\-]+")),
    SecretRule("Google OAuth Client Secret", "high", _c(r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b")),
    SecretRule("Google Service Account Key", "critical", _c(r'"type"\s*:\s*"service_account"')),
    SecretRule("Mailchimp API Key", "high", _c(r"\b[a-f0-9]{32}-us[0-9]{1,2}\b")),
    SecretRule("Twilio Account SID", "medium", _c(r"\bAC[a-z0-9]{32}\b")),
    # Broad keyword-assignment rule (h4x0r-dz/Leaked-Credentials). Appended last so
    # it supplements — never replaces — the precise provider rules above.
    SecretRule(
        "Leaked Credential Assignment", "medium",
        _c(rf"(?i)(?:{_LEAKED_ALT})[a-z0-9_ .\-,]{{0,25}}(?:=|>|:=|\|\|:|<=|=>|:).{{0,5}}['\"]([0-9a-zA-Z\-_=]{{8,64}})['\"]"),
        group=1,
    ),
]

# Obvious non-secrets — drop to cut false positives.
_DENY = re.compile(r"(?i)(example|sample|test|dummy|placeholder|your[_-]|changeme|insert[_-]|here['\"]?$|xxxx+|0000000000|redacted|process\.env|import\.meta)")


@dataclass
class SecretMatch:
    rule: str
    severity: str
    redacted: str
    line: int


def redact(secret: str) -> str:
    """Mask a secret for safe storage: keep a few edge chars + length only."""
    s = secret.strip()
    if len(s) <= 8:
        return (s[0] + "****") if s else "****"
    return f"{s[:4]}…{s[-2:]} ({len(s)} chars)"


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) — high for random secrets, low for words."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# Quoted high-entropy candidates (detect-secrets / trufflehog style). Quoting cuts
# the minified-variable noise that plagues raw entropy scanning of JS.
_QUOTED = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,80})['"]""")
_HEX = re.compile(r"[a-fA-F0-9]+")


def scan_entropy(
    text: str,
    exclude: frozenset[str] = frozenset(),
    *,
    base64_threshold: float = 4.5,
    hex_threshold: float = 3.0,
    min_length: int = 20,
    max_findings: int = 50,
) -> list[SecretMatch]:
    """Flag random-looking quoted strings no regex matched (unknown secrets).

    Thresholds follow trufflehog (base64 ~4.5, hex ~2.7-3.0). Common hex hashes
    (md5/sha1/sha256 lengths) are skipped — they're rarely secrets.
    """
    out: list[SecretMatch] = []
    seen: set[str] = set()
    for m in _QUOTED.finditer(text):
        val = m.group(1)
        if len(val) < min_length or val in exclude or val in seen or _DENY.search(val):
            continue
        is_hex = _HEX.fullmatch(val) is not None
        if is_hex and len(val) in (32, 40, 64):       # md5 / sha1 / sha256 — noise
            continue
        threshold = hex_threshold if is_hex else base64_threshold
        if shannon_entropy(val) < threshold:
            continue
        seen.add(val)
        line = text.count("\n", 0, m.start()) + 1
        out.append(SecretMatch("High-Entropy String", "low", redact(val), line))
        if len(out) >= max_findings:
            break
    return out


def scan_text(
    text: str,
    *,
    max_findings: int = 100,
    entropy: bool = False,
    base64_threshold: float = 4.5,
    hex_threshold: float = 3.0,
    entropy_min_length: int = 20,
) -> list[SecretMatch]:
    """Return redacted secret matches in ``text`` (deduped per rule+value).

    With ``entropy=True``, also flags high-entropy quoted strings that no regex
    matched (catches unknown/custom secrets).
    """
    out: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(text):
            raw = m.group(rule.group) if rule.group else m.group(0)
            if not raw or _DENY.search(raw):
                continue
            dedupe = (rule.name, raw)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            line = text.count("\n", 0, m.start()) + 1
            out.append(SecretMatch(rule.name, rule.severity, redact(raw), line))
            if len(out) >= max_findings:
                return out
    if entropy:
        already = frozenset(raw for _, raw in seen)
        out.extend(scan_entropy(
            text, already,
            base64_threshold=base64_threshold, hex_threshold=hex_threshold,
            min_length=entropy_min_length, max_findings=max(0, max_findings - len(out)),
        ))
    return out

#!/usr/bin/env python3
"""
jsrecon - extract endpoints, paths and likely leaked secrets from
JavaScript files you have already saved locally.

Pure Python standard library. It reads FILES ON DISK (or stdin). It does
NOT fetch anything over the network and does NOT connect to any host.
Point it at your own app's bundles, or at scripts you are authorised to
review, to find forgotten API routes and accidentally committed secrets.

Examples:
    jsrecon app.min.js
    jsrecon dist/*.js --kind endpoints --format json
    curl -s https://your-site.example/main.js | jsrecon -   # you fetch, it parses
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict

__version__ = "1.0.0"

# --- endpoint / path patterns ------------------------------------------------
URL_RE = re.compile(r"""https?://[^\s"'`<>()]+""")
# quoted absolute paths like "/api/v2/users" or '/internal/debug'
PATH_RE = re.compile(r"""["'`](/(?:[A-Za-z0-9_\-./~]+))["'`]""")
# fetch("...") / axios.get('...') / url: "..."
CALL_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch)|url|endpoint|baseURL)\s*[:(]\s*["'`]([^"'`]+)["'`]""", re.I)

# --- secret patterns (name, regex, note) -------------------------------------
# Patterns are intentionally specific to keep false positives low. Any hit is a
# *candidate* to verify and rotate, never a confirmed live credential.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "Slack token"),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    ("stripe_secret", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b"), "Stripe live secret key"),
    ("stripe_test", re.compile(r"\b(sk|rk)_test_[0-9A-Za-z]{20,}\b"), "Stripe test key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "JSON Web Token"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key block"),
    ("google_oauth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "Google OAuth client id"),
    ("generic_assignment", re.compile(r"""(?i)\b(?:api[_-]?key|secret|passwd|password|token|auth)\b["'`]?\s*[:=]\s*["'`]([0-9A-Za-z_\-./+=]{12,})["'`]"""), "generic key/secret assignment"),
]

COMMON_PATH_NOISE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|css|woff2?|ttf|ico|map)$", re.I)


@dataclass(frozen=True)
class Finding:
    kind: str          # "endpoint" | "secret"
    value: str
    source: str
    line: int
    note: str = ""


def _redact(s: str) -> str:
    """Show enough to recognise a secret without printing it in full."""
    s = s.strip()
    if len(s) <= 10:
        return s[:2] + "***"
    return s[:4] + "***" + s[-4:]


def scan_endpoints(text: str, source: str) -> list[Finding]:
    out: dict[str, Finding] = {}
    for i, line in enumerate(text.splitlines(), 1):
        for m in URL_RE.finditer(line):
            v = m.group(0).rstrip(".,);")
            out.setdefault(v, Finding("endpoint", v, source, i))
        for rx in (PATH_RE, CALL_RE):
            for m in rx.finditer(line):
                v = m.group(1)
                if v.startswith("/") and not COMMON_PATH_NOISE.search(v) and len(v) > 1:
                    out.setdefault(v, Finding("endpoint", v, source, i))
                elif v.startswith("http"):
                    out.setdefault(v, Finding("endpoint", v, source, i))
    return list(out.values())


def scan_secrets(text: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for i, line in enumerate(text.splitlines(), 1):
        for name, rx, note in SECRET_PATTERNS:
            for m in rx.finditer(line):
                raw = m.group(0)
                key = (name, raw)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding("secret", _redact(raw), source, i, f"{name}: {note}"))
    return out


def scan_text(text: str, source: str, kind: str) -> list[Finding]:
    findings = []
    if kind in ("endpoints", "all"):
        findings += scan_endpoints(text, source)
    if kind in ("secrets", "all"):
        findings += scan_secrets(text, source)
    return findings


# --------------------------------------------------------------------------- output

def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    eps = [f for f in findings if f.kind == "endpoint"]
    secs = [f for f in findings if f.kind == "secret"]
    lines = []
    if secs:
        lines.append(f"POSSIBLE SECRETS ({len(secs)}) - verify and rotate if real:")
        for f in secs:
            lines.append(f"  {f.source}:{f.line}  {f.note}  ->  {f.value}")
        lines.append("")
    if eps:
        lines.append(f"ENDPOINTS / PATHS ({len(eps)}):")
        for f in sorted(eps, key=lambda x: x.value):
            lines.append(f"  {f.value}    ({f.source}:{f.line})")
    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


def iter_sources(paths: list[str]):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                yield p, fh.read()
        except OSError as e:
            print(f"skip {p}: {e}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jsrecon", description="Extract endpoints and likely secrets from locally saved JavaScript files. Offline; parses files only.")
    p.add_argument("paths", nargs="+", help="JavaScript files to scan, or - for stdin.")
    p.add_argument("--kind", choices=("all", "endpoints", "secrets"), default="all")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--fail-on-secret", action="store_true", help="Exit code 2 if any possible secret is found (for CI/pre-commit).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings: list[Finding] = []
    for source, text in iter_sources(args.paths):
        findings += scan_text(text, source, args.kind)
    if args.format == "json":
        print(render_json(findings))
    else:
        print(render_text(findings))
    if args.fail_on_secret and any(f.kind == "secret" for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

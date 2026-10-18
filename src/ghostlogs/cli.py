"""GhostLogs command line: `pack` and `doctor`.

Exit codes: 0 = pack written within budget (or doctor clean),
1 = pack written but over budget, 2 = could not run (missing
input, bad pattern file, bad config). A pack is never written on a
2. Nothing here touches the network or modifies the source log.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze
from .pack import build_pack
from .patterns import (compile_cli_patterns, default_patterns,
                       load_pattern_file)
from .tokens import METHOD, SOURCE

CONFIG_KEYS = {"budget", "window_before", "window_after",
               "patterns_file", "no_redact"}


def _load_config(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"config {path}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"config {path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config {path}: top level must be an object")
    unknown = sorted(set(data) - CONFIG_KEYS)
    if unknown:
        raise ValueError(
            f"config {path}: unknown keys {unknown}; "
            f"allowed keys are {sorted(CONFIG_KEYS)}")
    return data


def _resolve_settings(args) -> dict:
    config = _load_config(args.config) if getattr(args, "config", None) else {}

    def pick(cli_value, key, default):
        if cli_value is not None:
            return cli_value
        if key in config:
            return config[key]
        return default

    settings = {
        "budget": pick(args.budget, "budget", 8000),
        "window_before": pick(args.window_before, "window_before", 3),
        "window_after": pick(args.window_after, "window_after", 5),
        "no_redact": bool(pick(True if args.no_redact else None,
                               "no_redact", False)),
    }
    patterns_file = getattr(args, "patterns", None) or config.get("patterns_file")
    patterns = default_patterns()
    if patterns_file:
        patterns = patterns + load_pattern_file(patterns_file)
    patterns = patterns + compile_cli_patterns(
        getattr(args, "pattern", None))
    settings["patterns"] = patterns
    return settings


def _cmd_pack(args) -> int:
    source = Path(args.logfile)
    if not source.is_file():
        print(f"ghostlogs: no such log file: {source}", file=sys.stderr)
        return 2
    try:
        settings = _resolve_settings(args)
    except ValueError as exc:
        print(f"ghostlogs: {exc}", file=sys.stderr)
        return 2
    if settings["budget"] <= 0 or settings["window_before"] < 0 \
            or settings["window_after"] < 0:
        print("ghostlogs: budget must be positive and window sizes "
              "must be zero or more", file=sys.stderr)
        return 2
    analysis = analyze(source, settings["patterns"],
                       window_before=settings["window_before"],
                       window_after=settings["window_after"])
    result = build_pack(analysis, args.output, settings["budget"],
                        settings["patterns"],
                        redact=not settings["no_redact"])
    m = result.manifest
    c = m["counts"]
    print(f"Packed {source} -> {result.out_dir}")
    print(f"  lines {c['total_lines']} = kept {c['kept']} + collapsed "
          f"{c['collapsed']} + dropped {c['dropped']} "
          f"(reconciles: {c['reconciles']})")
    print(f"  windows: {m['windows']['emitted']} emitted of "
          f"{m['windows']['matched']} matched; duplicate groups: "
          f"{m['duplicates']['emitted_groups']} emitted of "
          f"{m['duplicates']['groups']}")
    print(f"  pack estimate {m['pack_estimated_tokens']} tokens "
          f"against budget {m['budget_tokens']} "
          f"(estimator: {METHOD})")
    print(f"  budget tier: {m['budget_tier']} - "
          f"{m['budget_tier_meaning']}")
    if m["redaction"]["enabled"]:
        print(f"  redactions: {m['redaction']['total']} "
              f"{m['redaction']['counts']}")
    else:
        print("  WARNING: redaction disabled for this run "
              "(--no-redact); recorded in the manifest.")
    if result.over_budget:
        print("  OVER BUDGET: mandatory content alone exceeded the "
              "budget; pack written and marked over_budget.")
        return 1
    return 0


def _cmd_doctor(args) -> int:
    try:
        settings = _resolve_settings(args)
    except ValueError as exc:
        print(f"ghostlogs: {exc}", file=sys.stderr)
        return 2
    print(f"ghostlogs {__version__}")
    print(f"estimator: {METHOD} (source: {SOURCE})")
    print(f"patterns loaded: {len(settings['patterns'])}")
    for p in settings["patterns"]:
        print(f"  {p.id} (severity {p.severity}, kind {p.kind}): "
              f"{p.regex.pattern}")
    print("source handling: local files only, read line by line, "
          "never modified")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghostlogs",
        description="Slice a large local log file into a "
                    "token-budgeted incident pack (INCIDENT.md + "
                    "manifest.json). Source logs are never modified.")
    parser.add_argument("--version", action="version",
                        version=f"ghostlogs {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pack = sub.add_parser("pack", help="build an incident pack from a log file")
    p_pack.add_argument("logfile", help="path to the local log file")
    p_pack.add_argument("-o", "--output", required=True,
                        help="pack output directory")
    p_pack.add_argument("--budget", type=int, default=None,
                        help="token budget for the pack (default 8000)")
    p_pack.add_argument("--window-before", type=int, default=None,
                        help="context lines before a match (default 3)")
    p_pack.add_argument("--window-after", type=int, default=None,
                        help="context lines after a match (default 5)")
    p_pack.add_argument("--patterns", default=None,
                        help="file of extra patterns, one per line: "
                             "id = regex, or a bare regex")
    p_pack.add_argument("--pattern", action="append", default=None,
                        help="one extra regex; repeatable")
    p_pack.add_argument("--config", default=None,
                        help="JSON config file (keys: budget, "
                             "window_before, window_after, "
                             "patterns_file, no_redact)")
    p_pack.add_argument("--no-redact", action="store_true",
                        help="disable secret-shape redaction "
                             "(recorded in the manifest)")
    p_pack.set_defaults(func=_cmd_pack)

    p_doc = sub.add_parser("doctor", help="report estimator, patterns, version")
    p_doc.add_argument("--patterns", default=None,
                       help="also load and validate this pattern file")
    p_doc.add_argument("--pattern", action="append", default=None,
                       help="one extra regex; repeatable")
    p_doc.add_argument("--config", default=None,
                       help="also load and validate this config file")
    p_doc.set_defaults(func=_cmd_doctor, budget=None, window_before=None,
                    window_after=None, no_redact=False)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

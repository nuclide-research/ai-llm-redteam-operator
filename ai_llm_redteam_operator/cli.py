"""
CLI for ai-llm-redteam-operator.

Two subcommands:

    plan   write a scenario packet (the policy) for a focus value
    run    execute that packet against one authorized target (the agent)

`plan` is the default, so the historical bare form still works:

    ai-llm-redteam-operator category open_gateways
    ai-llm-redteam-operator plan platform LiteLLM --format json
    ai-llm-redteam-operator --list-values category

The agent fires real HTTP. It refuses to send without an authorization
reference and a target, and it is dry-run by default:

    ai-llm-redteam-operator run platform LiteLLM \
        --target https://10.0.0.5:4000 --authorize ENG-2026-014        # dry-run
    ai-llm-redteam-operator run platform LiteLLM \
        --target https://10.0.0.5:4000 --authorize ENG-2026-014 --live  # sends
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .operator import AegisLLM_Operator
from .models import ExposureCategory, AttackPath
from .agent import (
    AuthorizationError,
    RunConfig,
    ScopeError,
    build_agent,
    render_run_report_markdown,
)


DEFAULT_DB      = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/nuclide.db")
DEFAULT_COORDS  = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/coords.json")
DEFAULT_DETAILS = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/details.json")

_FOCUS_CHOICES = ["category", "platform", "attack_path"]

_KNOWN_VALUES = {
    "category":    ExposureCategory.ALL,
    "attack_path": AttackPath.ALL,
    "platform":    list(ExposureCategory.PLATFORM_MAP.keys()),
}


def _add_data_paths(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db",      default=DEFAULT_DB,      metavar="PATH", help="Path to nuclide.db")
    p.add_argument("--coords",  default=DEFAULT_COORDS,  metavar="PATH", help="Path to coords.json")
    p.add_argument("--details", default=DEFAULT_DETAILS, metavar="PATH", help="Path to details.json")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-llm-redteam-operator",
        description="Plan and run AI/LLM red-team scenarios for a given focus.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command")

    # --- plan ----------------------------------------------------------------
    plan = sub.add_parser("plan", help="Generate a scenario packet (no network).")
    plan.add_argument("focus_type", nargs="?", choices=_FOCUS_CHOICES, help="Focus dimension")
    plan.add_argument("focus_value", nargs="?", help="Value within the focus dimension")
    _add_data_paths(plan)
    plan.add_argument("--format", default="md", choices=["md", "json"],
                      help="Output format: 'md' (default) or 'json'")
    plan.add_argument("--min-severity", dest="min_severity",
                      choices=["info", "low", "medium", "high", "critical"],
                      help="Filter to hosts at or above this severity")
    plan.add_argument("--sectors", help="Comma-separated sector filter")
    plan.add_argument("--limit", type=int, default=500, help="Max hosts from DB (default 500)")
    plan.add_argument("--list-values", dest="list_values", metavar="FOCUS_TYPE",
                      choices=_FOCUS_CHOICES, help="List known values for a focus type and exit")
    plan.add_argument("--out", metavar="FILE", help="Write output to FILE instead of stdout")

    # --- run -----------------------------------------------------------------
    run = sub.add_parser("run", help="Execute a packet against one authorized target.")
    run.add_argument("focus_type", choices=_FOCUS_CHOICES, help="Focus dimension")
    run.add_argument("focus_value", help="Value within the focus dimension")
    _add_data_paths(run)
    run.add_argument("--target", required=True, metavar="URL",
                     help="Base target URL, e.g. https://10.0.0.5:4000")
    run.add_argument("--authorize", dest="authorize", required=True, metavar="REF",
                     help="Engagement / scope reference. Required. No send without it.")
    g = run.add_mutually_exclusive_group()
    g.add_argument("--dry-run", dest="dry_run", action="store_true", default=True,
                   help="Plan requests, send nothing (default)")
    g.add_argument("--live", dest="dry_run", action="store_false",
                   help="Actually send the planned requests")
    run.add_argument("--max-aggressiveness", dest="max_agg", default="medium",
                     choices=["low_noise", "medium", "high"],
                     help="Highest READ-probe noise level to send (default medium)")
    run.add_argument("--allow-writes", dest="allow_writes", action="store_true",
                     help="Permit POST/PUT/PATCH/DELETE probes (off by default, "
                          "independent of --max-aggressiveness)")
    run.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout seconds")
    run.add_argument("--delay", type=float, default=0.5, help="Pause before each live request")
    run.add_argument("--max-requests", dest="max_requests", type=int, default=60,
                     help="Global request budget for the run")
    run.add_argument("--max-body-bytes", dest="max_body_bytes", type=int, default=4096,
                     help="Response body sample cap")
    run.add_argument("--verify-tls", dest="verify_tls", action="store_true",
                     help="Verify target TLS certs (off by default; self-signed is common)")
    run.add_argument("--llm-endpoint", dest="llm_endpoint", metavar="URL",
                     help="Optional OpenAI-compatible chat endpoint for the strategist")
    run.add_argument("--llm-model", dest="llm_model", default="gpt-4o-mini",
                     help="Model name for the strategist")
    run.add_argument("--llm-api-key-env", dest="llm_api_key_env", metavar="VAR",
                     help="Env var holding the strategist API key")
    run.add_argument("--format", default="md", choices=["md", "json"],
                     help="Report format: 'md' (default) or 'json'")
    run.add_argument("--out", metavar="FILE", help="Write report to FILE instead of stdout")

    return p


def _normalize_argv(argv):
    """Keep the historical bare form working: if the first token is a focus
    type (not a subcommand), assume `plan`."""
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in _FOCUS_CHOICES:
        return ["plan"] + list(argv)
    # `--list-values ...` with no subcommand also routes to plan.
    if argv and argv[0] == "--list-values":
        return ["plan"] + list(argv)
    return list(argv)


def _cmd_plan(args, op: AegisLLM_Operator) -> int:
    if getattr(args, "list_values", None):
        values = _KNOWN_VALUES.get(args.list_values, [])
        print("Known %s values:" % args.list_values)
        for v in values:
            print("  %s" % v)
        return 0

    if not args.focus_type or not args.focus_value:
        print("plan needs a focus_type and focus_value (or use --list-values).",
              file=sys.stderr)
        return 1

    options = {"limit": args.limit}
    if args.min_severity:
        options["min_severity"] = args.min_severity
    if args.sectors:
        options["sectors"] = [s.strip() for s in args.sectors.split(",")]

    try:
        packet = op.generate_scenario_packet(
            focus_type=args.focus_type, focus_value=args.focus_value, options=options)
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1

    output = json.dumps(packet, indent=2) if args.format == "json" \
        else op.render_markdown(packet)
    _emit(output, args.out)
    return 0


def _cmd_run(args, op: AegisLLM_Operator) -> int:
    try:
        packet = op.generate_scenario_packet(
            focus_type=args.focus_type, focus_value=args.focus_value,
            options={"limit": 500})
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1

    api_key = None
    if args.llm_api_key_env:
        api_key = os.environ.get(args.llm_api_key_env)
        if not api_key:
            print("Error: env var %s is empty" % args.llm_api_key_env, file=sys.stderr)
            return 1

    config = RunConfig(
        target=args.target,
        authorization=args.authorize,
        dry_run=args.dry_run,
        max_aggressiveness=args.max_agg,
        allow_writes=args.allow_writes,
        request_timeout=args.timeout,
        delay_seconds=args.delay,
        max_body_bytes=args.max_body_bytes,
        max_requests=args.max_requests,
        verify_tls=args.verify_tls,
        llm_endpoint=args.llm_endpoint,
        llm_api_key=api_key,
        llm_model=args.llm_model,
    )

    try:
        agent = build_agent(config)
        report = agent.run(packet)
    except (AuthorizationError, ScopeError) as exc:
        print("Refused: %s" % exc, file=sys.stderr)
        return 2

    output = json.dumps(report.to_dict(), indent=2) if args.format == "json" \
        else render_run_report_markdown(report)
    _emit(output, args.out)
    # Exit non-zero-free: a clean run is 0 regardless of findings.
    return 0


def _emit(output: str, out_path) -> None:
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(output)
        print("Written to %s" % out_path)
    else:
        print(output)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(argv))

    if not args.command:
        parser.print_help()
        return 1

    op = AegisLLM_Operator(args.db, args.coords, args.details)
    if args.command == "plan":
        return _cmd_plan(args, op)
    if args.command == "run":
        return _cmd_run(args, op)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

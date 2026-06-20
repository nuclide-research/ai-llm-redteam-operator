"""
CLI for AegisLLM_Operator.

Usage:
    python -m ai_llm_redteam_operator.cli category open_gateways
    python -m ai_llm_redteam_operator.cli platform LiteLLM --format json
    python -m ai_llm_redteam_operator.cli attack_path flowise_to_weaviate_pii_dump --format md
    python -m ai_llm_redteam_operator.cli category open_gateways --min-severity high --sectors commercial,healthcare
    python -m ai_llm_redteam_operator.cli --list-values category
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .operator import AegisLLM_Operator
from .models import ExposureCategory, AttackPath


DEFAULT_DB      = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/nuclide.db")
DEFAULT_COORDS  = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/coords.json")
DEFAULT_DETAILS = os.path.expanduser("~/AI-LLM-Infrastructure-OSINT/data/details.json")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai_llm_redteam_operator",
        description="Generate an AI/LLM red-team scenario packet for a given focus.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "focus_type",
        nargs="?",
        choices=["category", "platform", "attack_path"],
        help="Focus dimension",
    )
    p.add_argument(
        "focus_value",
        nargs="?",
        help="Value within the chosen focus dimension",
    )
    p.add_argument(
        "--db",      default=DEFAULT_DB,      metavar="PATH", help="Path to nuclide.db")
    p.add_argument(
        "--coords",  default=DEFAULT_COORDS,  metavar="PATH", help="Path to coords.json")
    p.add_argument(
        "--details", default=DEFAULT_DETAILS, metavar="PATH", help="Path to details.json")
    p.add_argument(
        "--format",  default="md", choices=["md", "json"],
        help="Output format: 'md' (Markdown, default) or 'json'")
    p.add_argument(
        "--min-severity", dest="min_severity",
        choices=["info", "low", "medium", "high", "critical"],
        help="Filter to hosts at or above this severity")
    p.add_argument(
        "--sectors", help="Comma-separated sector filter (e.g. commercial,healthcare)")
    p.add_argument(
        "--limit", type=int, default=500, help="Max hosts to pull from DB (default 500)")
    p.add_argument(
        "--list-values", dest="list_values", metavar="FOCUS_TYPE",
        choices=["category", "platform", "attack_path"],
        help="List known values for a focus type and exit")
    p.add_argument(
        "--out", metavar="FILE", help="Write output to FILE instead of stdout")
    return p


_KNOWN_VALUES = {
    "category":    ExposureCategory.ALL,
    "attack_path": AttackPath.ALL,
    "platform":    list(ExposureCategory.PLATFORM_MAP.keys()),
}


def main(argv=None):
    parser = build_parser()
    args   = parser.parse_args(argv)

    op = AegisLLM_Operator(args.db, args.coords, args.details)

    if args.list_values:
        values = _KNOWN_VALUES.get(args.list_values, [])
        print(f"Known {args.list_values} values:")
        for v in values:
            print(f"  {v}")
        return 0

    if not args.focus_type or not args.focus_value:
        parser.print_help()
        return 1

    options: dict = {"limit": args.limit}
    if args.min_severity:
        options["min_severity"] = args.min_severity
    if args.sectors:
        options["sectors"] = [s.strip() for s in args.sectors.split(",")]

    try:
        packet = op.generate_scenario_packet(
            focus_type=args.focus_type,
            focus_value=args.focus_value,
            options=options,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        output = json.dumps(packet, indent=2)
    else:
        output = op.render_markdown(packet)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output)
        print(f"Written to {args.out}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())

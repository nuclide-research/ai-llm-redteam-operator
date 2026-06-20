"""
AegisLLM Operator - Markdown renderer

Takes a ScenarioPacket dict (from dataclasses.asdict) and produces
a structured Markdown report for red/blue team consumption.
"""

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _badge(label: str) -> str:
    return f"[{label.upper()}]"


def _severity_badge(s: str) -> str:
    return _badge(s)


def _noise_badge(n: str) -> str:
    return _badge(n.replace("_", " "))


def _bullet_list(items: List[str], indent: int = 0) -> str:
    prefix = "  " * indent
    return "\n".join(f"{prefix}- {item}" for item in items)


def _numbered_list(items: List[str], indent: int = 0) -> str:
    prefix = "  " * indent
    return "\n".join(f"{prefix}{i + 1}. {item}" for i, item in enumerate(items))


def _kv_table(rows: List[tuple]) -> str:
    lines = ["| Metric | Value |", "|--------|-------|"]
    for k, v in rows:
        lines.append(f"| {k} | {v} |")
    return "\n".join(lines)


def _section(n: int, title: str) -> str:
    return f"\n## {n}. {title}\n"


def _subsection(title: str) -> str:
    return f"\n### {title}\n"


def _subsubsection(title: str) -> str:
    return f"\n#### {title}\n"


def _hr() -> str:
    return "\n---\n"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_target_profile(tp: Dict) -> str:
    lines = [_section(1, "Target Profile")]

    lines.append(f"**Focus:** `{tp['focus_type']}` / `{tp['focus_value']}`")
    lines.append(f"\n**Platforms:** {', '.join(tp['typical_platforms'])}\n")

    hs = tp["host_summary"]
    total = hs.get("total_hosts", 0)
    lines.append(_subsection("Host Summary"))

    # Auth posture breakdown
    ap = hs.get("auth_posture_counts", {})
    ap_open = ap.get("open", 0)
    ap_weak = ap.get("weak", 0)
    ap_auth = ap.get("auth", 0)
    pct = lambda n: f"{(n/total*100):.1f}%" if total > 0 else "n/a"

    rows = [
        ("Total hosts (stubbed)", str(total)),
        ("Open auth", f"{ap_open} ({pct(ap_open)})"),
        ("Weak auth", f"{ap_weak} ({pct(ap_weak)})"),
        ("Authenticated", f"{ap_auth} ({pct(ap_auth)})"),
    ]
    lines.append(_kv_table(rows))
    lines.append("")

    sv = hs.get("severity_counts", {})
    sv_str = " | ".join(f"{k}: **{v}**" for k, v in sv.items() if v > 0)
    lines.append(f"**Severity distribution:** {sv_str}\n")

    sc = hs.get("sector_counts", {})
    sc_str = " | ".join(f"{k}: {v}" for k, v in sc.items() if v > 0)
    lines.append(f"**Sectors:** {sc_str}\n")

    lines.append(_subsection("Notable Patterns"))
    lines.append(_bullet_list(tp["notable_patterns"]))
    lines.append("")

    lines.append(_subsection("Representative Notes"))
    lines.append(f"_{tp['representative_notes']}_\n")

    return "\n".join(lines)


def _render_recon_mapping(rm: Dict) -> str:
    lines = [_section(2, "Recon & Surface Mapping")]

    lines.append(_subsection("Surface Elements"))
    lines.append("| Type | Pattern | Notes |")
    lines.append("|------|---------|-------|")
    for se in rm["surface_elements"]:
        typ = f"`{se['type']}`"
        pat = f"`{se['pattern']}`"
        lines.append(f"| {typ} | {pat} | {se['notes']} |")
    lines.append("")

    lines.append(_subsection("HTTP Probe Patterns"))
    for pp in rm["http_probe_patterns"]:
        noise = _noise_badge(pp["aggressiveness"])
        lines.append(_subsubsection(f"{pp['id']}: {pp['description']} {noise}"))
        lines.append(f"**Methods:** `{'`, `'.join(pp['methods'])}`  ")
        lines.append(f"**Paths:** `{'`, `'.join(pp['paths'])}`  ")
        if pp.get("headers"):
            hdr_str = ", ".join(f"`{k}: {v}`" for k, v in pp["headers"].items())
            lines.append(f"**Headers:** {hdr_str}  ")
        if pp.get("body_shape"):
            lines.append(f"**Body shape:** {pp['body_shape']}  ")
        lines.append(f"\n**Goals:**\n{_bullet_list(pp['goals'])}\n")
        lines.append(f"**Notes:** {pp['notes']}\n")

    lines.append(_subsection("Recon Phases"))
    for phase in rm["recon_phases"]:
        probes = " -> ".join(f"`{p}`" for p in phase["probe_ids"])
        lines.append(f"**{phase['id']}: {phase['name']}**  ")
        lines.append(f"Probes: {probes}  ")
        lines.append(f"{phase['description']}\n")

    return "\n".join(lines)


def _render_threat_model(tm: Dict) -> str:
    lines = [_section(3, "Threat Model & Attack Hypotheses")]

    lines.append(_subsection("Assets"))
    lines.append("| Asset | Criticality | Description |")
    lines.append("|-------|-------------|-------------|")
    for asset in tm["assets"]:
        crit = f"**{asset['criticality'].upper()}**"
        lines.append(f"| `{asset['name']}` | {crit} | {asset['description']} |")
    lines.append("")

    lines.append(_subsection("Threat Hypotheses"))
    for h in tm["hypotheses"]:
        impact = _severity_badge(h["impact_if_confirmed"])
        conf = _badge(f"confidence: {h['confidence']}")
        lines.append(_subsubsection(f"{h['id']} {impact} {conf}"))
        lines.append(f"{h['description']}\n")
        cats = ", ".join(f"`{c}`" for c in h["related_categories"])
        paths = ", ".join(f"`{p}`" for p in h["related_attack_paths"])
        if cats:
            lines.append(f"**Categories:** {cats}  ")
        if paths:
            lines.append(f"**Attack paths:** {paths}  ")
        lines.append(f"\n**Notes:** _{h['notes']}_\n")

    return "\n".join(lines)


def _render_test_cases(tcs: List[Dict]) -> str:
    lines = [_section(4, "Test Cases")]

    for tc in tcs:
        sev = _severity_badge(tc["severity_if_confirmed"])
        noise = _noise_badge(tc["noise_level"])
        lines.append(_subsection(f"{tc['id']}: {tc['objective']} {sev} {noise}"))

        if tc.get("preconditions"):
            lines.append("**Preconditions:**")
            lines.append(_bullet_list(tc["preconditions"]))
            lines.append("")

        lines.append("**Steps:**")
        lines.append(_numbered_list(tc["steps_summary"]))
        lines.append("")

        lines.append("**Expected weak signals:**")
        lines.append(_bullet_list(tc["expected_weak_signals"]))
        lines.append("")

        df = ", ".join(f"`{d}`" for d in tc["detection_focus"])
        assets = ", ".join(f"`{a}`" for a in tc["related_assets"])
        lines.append(f"**Detection focus:** {df}  ")
        lines.append(f"**Assets at risk:** {assets}  ")
        lines.append(f"\n**Notes:** _{tc['notes']}_\n")

    return "\n".join(lines)


def _render_attack_chains(chains: List[Dict]) -> str:
    lines = [_section(5, "Attack Chains")]

    for ac in chains:
        noise = _noise_badge(ac["overall_noise_profile"])
        lines.append(_subsection(f"{ac['id']}: {ac['name']} {noise}"))

        step_str = " -> ".join(f"`{s}`" for s in ac["steps"])
        lines.append(f"**Chain:** {step_str}\n")
        lines.append(f"{ac['summary']}\n")

        if ac["related_attack_paths"]:
            paths = ", ".join(f"`{p}`" for p in ac["related_attack_paths"])
            lines.append(f"**Maps to:** {paths}\n")

        lines.append("**Defender learning goals:**")
        lines.append(_bullet_list(ac["defender_learning_goals"]))
        lines.append("")

    return "\n".join(lines)


def _render_detection_telemetry(dt: Dict) -> str:
    lines = [_section(6, "Detection & Telemetry")]

    lines.append(_subsection("Logging Recommendations"))
    for rec in dt["logging_recommendations"]:
        lines.append(_subsubsection(f"Event: `{rec['event']}`"))
        fields_str = ", ".join(f"`{f}`" for f in rec["fields"])
        lines.append(f"**Fields:** {fields_str}  ")
        lines.append(f"\n{rec['notes']}\n")

    lines.append(_subsection("Detection Ideas"))
    lines.append("| Pattern | Severity | Notes |")
    lines.append("|---------|----------|-------|")
    for idea in dt["detection_ideas"]:
        sev = idea["severity"].upper()
        # Escape pipes in pattern and notes for table safety
        pat = idea["pattern"].replace("|", "/")
        note = idea["notes"].replace("|", "/")
        lines.append(f"| {pat} | **{sev}** | {note} |")
    lines.append("")

    lines.append(_subsection("Stealth Considerations"))
    lines.append(
        "_How a careful attacker minimizes signal, and what defenders can still key on:_\n"
    )
    lines.append(_bullet_list(dt["stealth_considerations"]))
    lines.append("")

    return "\n".join(lines)


def _render_hardening(h: Dict) -> str:
    lines = [_section(7, "Hardening & Counterplay")]

    lines.append(_subsection("Quick Wins"))
    lines.append(_bullet_list(h["quick_wins"]))
    lines.append("")

    lines.append(_subsection("Architectural Changes"))
    lines.append(_bullet_list(h["architectural_changes"]))
    lines.append("")

    lines.append(_subsection("Detection Engineering Actions"))
    lines.append(_bullet_list(h["detection_engineering_actions"]))
    lines.append("")

    lines.append(_subsection("Template Guidance"))
    lines.append(_bullet_list(h["template_guidance"]))
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def render_markdown(packet: Dict[str, Any]) -> str:
    """
    Render a ScenarioPacket dict as a Markdown report.

    Args:
        packet: dict from dataclasses.asdict(ScenarioPacket(...))
                or AegisLLM_Operator.generate_scenario_packet(...)

    Returns:
        str: Complete Markdown report.
    """
    tp = packet["target_profile"]
    focus = tp["focus_value"].replace("_", " ")

    lines: List[str] = []

    lines.append(f"# {focus} - AegisLLM Red-Team Scenario\n")
    lines.append(
        f"> **Focus:** `{tp['focus_type']}` / `{tp['focus_value']}`  \n"
        f"> **Generated by:** AegisLLM Operator  \n"
        f"> **Use:** Authorized internal/client assessments only.\n"
    )
    lines.append(_hr())

    lines.append(_render_target_profile(tp))
    lines.append(_hr())

    lines.append(_render_recon_mapping(packet["recon_mapping"]))
    lines.append(_hr())

    lines.append(_render_threat_model(packet["threat_model"]))
    lines.append(_hr())

    lines.append(_render_test_cases(packet["test_cases"]))
    lines.append(_hr())

    lines.append(_render_attack_chains(packet["attack_chains"]))
    lines.append(_hr())

    lines.append(_render_detection_telemetry(packet["detection_telemetry"]))
    lines.append(_hr())

    lines.append(_render_hardening(packet["hardening"]))

    return "\n".join(lines)

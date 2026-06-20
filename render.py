"""
Markdown rendering for ScenarioPacket dicts.

render_markdown(packet) is the only public entry point.
All helpers are private; add new section renderers and call them from
render_markdown() to extend.
"""

from __future__ import annotations
from typing import Any, Dict, List


def render_markdown(packet: Dict[str, Any]) -> str:
    """
    Render a scenario packet dict (from ScenarioPacket.to_dict()) as Markdown.

    Sections:
      # Scenario Packet: <focus>
      ## Target Profile
      ## Recon & Surface Mapping
      ## Threat Model & Attack Hypotheses
      ## Test Cases
      ## Attack Chains
      ## Detection & Telemetry
      ## Hardening & Counterplay
    """
    sections = [
        _render_header(packet),
        _render_target_profile(packet.get("target_profile", {})),
        _render_recon_mapping(packet.get("recon_mapping", {})),
        _render_threat_model(packet.get("threat_model", {})),
        _render_test_cases(packet.get("test_cases", [])),
        _render_attack_chains(packet.get("attack_chains", [])),
        _render_detection_telemetry(packet.get("detection_telemetry", {})),
        _render_hardening(packet.get("hardening", {})),
    ]
    return "\n\n".join(s for s in sections if s)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_header(packet: Dict) -> str:
    tp = packet.get("target_profile", {})
    focus_type  = tp.get("focus_type", "unknown")
    focus_value = tp.get("focus_value", "unknown")
    label = focus_value.replace("_", " ").title()
    return f"# Scenario Packet: {label}\n\n**Focus type:** `{focus_type}`  **Value:** `{focus_value}`"


def _render_target_profile(tp: Dict) -> str:
    if not tp:
        return ""
    hs    = tp.get("host_summary", {})
    lines = ["## Target Profile", ""]
    lines.append(f"> {tp.get('representative_notes', '')}")
    lines.append("")

    lines.append(f"**Total hosts in scope:** {hs.get('total_hosts', 0)}")
    lines.append("")

    lines += _kv_table("Severity distribution", hs.get("severity_counts", {}))
    lines += _kv_table("Sector distribution",   hs.get("sector_counts",   {}))
    lines += _kv_table("Auth posture (details.json subset)", hs.get("auth_posture_counts", {}))

    platforms = tp.get("typical_platforms", [])
    if platforms:
        lines.append("**Typical platforms:** " + ", ".join(f"`{p}`" for p in platforms))

    return "\n".join(lines)


def _render_recon_mapping(rm: Dict) -> str:
    if not rm:
        return ""
    lines = ["## Recon & Surface Mapping", ""]

    surface = rm.get("surface_elements", [])
    if surface:
        lines.append("### Surface Elements")
        lines.append("")
        lines.append("| Type | Pattern | Notes |")
        lines.append("|------|---------|-------|")
        for e in surface:
            t = e.get("type", "")
            p = _code(e.get("pattern", ""))
            n = e.get("notes", "")
            lines.append(f"| `{t}` | {p} | {n} |")
        lines.append("")

    probes = rm.get("http_probe_patterns", [])
    if probes:
        lines.append("### HTTP Probe Patterns")
        lines.append("")
        for pr in probes:
            lines.append(f"**{pr.get('description', '')}**")
            methods = ", ".join(f"`{m}`" for m in pr.get("methods", []))
            paths   = ", ".join(f"`{p}`" for p in pr.get("paths",   []))
            hdrs    = pr.get("headers", {})
            lines.append(f"- Methods: {methods}")
            lines.append(f"- Paths: {paths}")
            if hdrs:
                hdr_str = ", ".join(f"`{k}: {v}`" for k, v in hdrs.items())
                lines.append(f"- Headers: {hdr_str}")
            notes = pr.get("notes", "")
            if notes:
                lines.append(f"- Notes: {notes}")
            lines.append("")

    strategy = rm.get("mapping_strategy", [])
    if strategy:
        lines.append("### Mapping Strategy")
        lines.append("")
        for step in strategy:
            lines.append(f"- {step}")

    return "\n".join(lines)


def _render_threat_model(tm: Dict) -> str:
    if not tm:
        return ""
    lines = ["## Threat Model & Attack Hypotheses", ""]

    assets = tm.get("assets", [])
    if assets:
        lines.append("### Assets at Risk")
        lines.append("")
        for a in assets:
            lines.append(f"- **`{a.get('name', '')}`** -- {a.get('description', '')}")
        lines.append("")

    hyps = tm.get("hypotheses", [])
    if hyps:
        lines.append("### Hypotheses")
        lines.append("")
        for h in hyps:
            sev   = h.get("impact_if_confirmed", "unknown")
            badge = _severity_badge(sev)
            lines.append(f"**{h.get('id', '')}** {badge} {h.get('description', '')}")
            cats  = h.get("related_categories", [])
            paths = h.get("related_attack_paths", [])
            if cats:
                lines.append(f"  - Categories: {', '.join(f'`{c}`' for c in cats)}")
            if paths:
                lines.append(f"  - Attack paths: {', '.join(f'`{p}`' for p in paths)}")
            lines.append("")

    return "\n".join(lines)


def _render_test_cases(tcs: List[Dict]) -> str:
    if not tcs:
        return ""
    lines = ["## Test Cases", ""]
    for tc in tcs:
        sev   = tc.get("severity_if_confirmed", "unknown")
        badge = _severity_badge(sev)
        lines.append(f"### {tc.get('id', '')} {badge} -- {tc.get('objective', '')}")
        lines.append("")

        pre = tc.get("preconditions", [])
        if pre:
            lines.append("**Preconditions:**")
            for p in pre:
                lines.append(f"- {p}")
            lines.append("")

        steps = tc.get("steps_summary", [])
        if steps:
            lines.append("**Steps:**")
            for i, s in enumerate(steps, 1):
                lines.append(f"{i}. {s}")
            lines.append("")

        signals = tc.get("expected_weak_signals", [])
        if signals:
            lines.append("**Weak signals indicating a finding:**")
            for s in signals:
                lines.append(f"- {s}")
            lines.append("")

        notes = tc.get("notes", "")
        if notes:
            lines.append(f"> **Note:** {notes}")
            lines.append("")

    return "\n".join(lines)


def _render_attack_chains(acs: List[Dict]) -> str:
    if not acs:
        return ""
    lines = ["## Attack Chains", ""]
    for ac in acs:
        lines.append(f"### {ac.get('id', '')} -- {ac.get('name', '')}")
        lines.append("")
        steps = ac.get("steps", [])
        if steps:
            lines.append("**Sequence:** " + " -> ".join(f"`{s}`" for s in steps))
            lines.append("")
        summary = ac.get("summary", "")
        if summary:
            lines.append(summary)
            lines.append("")
    return "\n".join(lines)


def _render_detection_telemetry(dt: Dict) -> str:
    if not dt:
        return ""
    lines = ["## Detection & Telemetry", ""]

    recs = dt.get("logging_recommendations", [])
    if recs:
        lines.append("### Logging Recommendations")
        lines.append("")
        lines.append("| Event | Fields | Notes |")
        lines.append("|-------|--------|-------|")
        for r in recs:
            event  = f"`{r.get('event', '')}`"
            fields = ", ".join(f"`{f}`" for f in r.get("fields", []))
            notes  = r.get("notes", "")
            lines.append(f"| {event} | {fields} | {notes} |")
        lines.append("")

    ideas = dt.get("detection_ideas", [])
    if ideas:
        lines.append("### Detection Patterns")
        lines.append("")
        for d in ideas:
            sev   = d.get("severity", "unknown")
            badge = _severity_badge(sev)
            lines.append(f"- {badge} **{d.get('pattern', '')}** -- {d.get('notes', '')}")

    return "\n".join(lines)


def _render_hardening(h: Dict) -> str:
    if not h:
        return ""
    lines = ["## Hardening & Counterplay", ""]

    qw = h.get("quick_wins", [])
    if qw:
        lines.append("### Quick Wins (< 1 hour)")
        lines.append("")
        for w in qw:
            lines.append(f"- {w}")
        lines.append("")

    ac = h.get("architectural_changes", [])
    if ac:
        lines.append("### Architectural Changes")
        lines.append("")
        for c in ac:
            lines.append(f"- {c}")
        lines.append("")

    tg = h.get("template_guidance", [])
    if tg:
        lines.append("### Secure Deployment Template Guidance")
        lines.append("")
        for g in tg:
            lines.append(f"- {g}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_badge(sev: str) -> str:
    badges = {
        "critical": "[CRITICAL]",
        "high":     "[HIGH]",
        "medium":   "[MEDIUM]",
        "low":      "[LOW]",
        "info":     "[INFO]",
    }
    return badges.get(sev.lower(), f"[{sev.upper()}]")


def _code(s: str) -> str:
    return f"`{s}`" if s else ""


def _kv_table(title: str, d: Dict) -> List[str]:
    if not d:
        return []
    lines = [f"**{title}:**", ""]
    lines.append("| Value | Count |")
    lines.append("|-------|-------|")
    for k, v in sorted(d.items(), key=lambda x: -x[1]):
        lines.append(f"| {k} | {v} |")
    lines.append("")
    return lines

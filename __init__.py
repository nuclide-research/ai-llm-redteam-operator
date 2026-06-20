"""
ai_llm_redteam_operator
=======================
Operator-grade AI/LLM infrastructure red-team scenario packet generator.

Quick start:
    from ai_llm_redteam_operator import AI_LLM_RedTeam_Operator

    op = AI_LLM_RedTeam_Operator(
        db_path="nuclide.db",
        coords_path="coords.json",
        details_path="details.json",
    )
    packet = op.generate_scenario_packet("category", "open_gateways")
    print(op.render_markdown(packet))

CLI:
    python -m ai_llm_redteam_operator.cli --help
"""

from .operator import AI_LLM_RedTeam_Operator
from .models import (
    ExposureCategory,
    AttackPath,
    ScenarioPacket,
    TargetProfile,
    ReconMapping,
    ThreatModel,
    TestCase,
    AttackChain,
    DetectionTelemetry,
    Hardening,
)
from .render import render_markdown

__all__ = [
    "AI_LLM_RedTeam_Operator",
    "ExposureCategory",
    "AttackPath",
    "ScenarioPacket",
    "TargetProfile",
    "ReconMapping",
    "ThreatModel",
    "TestCase",
    "AttackChain",
    "DetectionTelemetry",
    "Hardening",
    "render_markdown",
]

"""
AegisLLM Operator - AI/LLM Red-Team & Detection Design Engine

Models a senior AI/LLM-focused red-teamer + detection engineer.
For authorized internal/client assessments only.

Usage:
    from aegisllm_operator import AegisLLM_Operator

    op = AegisLLM_Operator(
        db_path="nuclide.db",
        coords_path="coords.json",
        details_path="details.json",
    )

    packet = op.generate_scenario_packet("category", "open_gateways")
    print(op.render_markdown(packet))
"""

from .operator import AegisLLM_Operator
from .agent import (
    AuthorizationError,
    ChainOutcome,
    Finding,
    LLMStrategist,
    Observation,
    ProbeRunner,
    RedTeamAgent,
    RunConfig,
    RunReport,
    ScopeError,
    SignalEvaluator,
    build_agent,
    render_run_report_markdown,
)
from .models import (
    AttackChain,
    AttackPath,
    Asset,
    DetectionIdea,
    DetectionTelemetry,
    ExposureCategory,
    FocusType,
    Hardening,
    HTTPProbePattern,
    LoggingRecommendation,
    ReconMapping,
    ReconPhase,
    ScenarioPacket,
    SurfaceElement,
    TargetProfile,
    TestCase,
    ThreatHypothesis,
    ThreatModel,
)
from .render import render_markdown

__version__ = "0.2.0"
__all__ = [
    "AegisLLM_Operator",
    "render_markdown",
    # agent
    "AuthorizationError",
    "ChainOutcome",
    "Finding",
    "LLMStrategist",
    "Observation",
    "ProbeRunner",
    "RedTeamAgent",
    "RunConfig",
    "RunReport",
    "ScopeError",
    "SignalEvaluator",
    "build_agent",
    "render_run_report_markdown",
    # models
    "AttackChain",
    "AttackPath",
    "Asset",
    "DetectionIdea",
    "DetectionTelemetry",
    "ExposureCategory",
    "FocusType",
    "Hardening",
    "HTTPProbePattern",
    "LoggingRecommendation",
    "ReconMapping",
    "ReconPhase",
    "ScenarioPacket",
    "SurfaceElement",
    "TargetProfile",
    "TestCase",
    "ThreatHypothesis",
    "ThreatModel",
]

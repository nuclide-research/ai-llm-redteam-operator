"""
Data models for AI_LLM_RedTeam_Operator scenario packets.

All models are plain dataclasses; use asdict() or .to_dict() for JSON export.
Literal type hints document allowed values but are not enforced at runtime --
add Pydantic if you want validation.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Domain enums (strings, not Enum classes, so they serialize cleanly)
# ---------------------------------------------------------------------------

class ExposureCategory:
    EXPOSED_MODEL_RUNTIMES = "exposed_model_runtimes"
    OPEN_GATEWAYS          = "open_gateways"
    NOTEBOOKS              = "notebooks"
    CHAT_UIS               = "chat_uis"
    LEAKY_DATA_STORES      = "leaky_data_stores"
    KEY_ABUSE              = "key_abuse"
    OBSERVABILITY          = "observability"
    AGENT_SURFACES         = "agent_surfaces"

    ALL: List[str] = [
        EXPOSED_MODEL_RUNTIMES, OPEN_GATEWAYS, NOTEBOOKS, CHAT_UIS,
        LEAKY_DATA_STORES, KEY_ABUSE, OBSERVABILITY, AGENT_SURFACES,
    ]


class AttackPath:
    OPEN_GATEWAY_LLMJACKING         = "open_gateway_llmjacking"
    OLLAMA_11434_HOST_TAKEOVER      = "ollama_11434_host_takeover"
    FLOWISE_TO_WEAVIATE_PII_DUMP    = "flowise_to_weaviate_pii_dump"
    OPEN_WEBUI_OPEN_SIGNUP_RAG_SEAT = "open_webui_open_signup_rag_seat"
    OPEN_JUPYTER_GPU_RCE            = "open_jupyter_gpu_rce"

    ALL: List[str] = [
        OPEN_GATEWAY_LLMJACKING, OLLAMA_11434_HOST_TAKEOVER,
        FLOWISE_TO_WEAVIATE_PII_DUMP, OPEN_WEBUI_OPEN_SIGNUP_RAG_SEAT,
        OPEN_JUPYTER_GPU_RCE,
    ]


# ---------------------------------------------------------------------------
# Mixin
# ---------------------------------------------------------------------------

class _Serializable:
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]

    def to_json(self, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# ReconMapping models
# ---------------------------------------------------------------------------

@dataclass
class SurfaceElement(_Serializable):
    # type: "http_path" | "port" | "header_pattern" | "banner_pattern"
    type: str
    pattern: str
    notes: str


@dataclass
class HTTPProbePattern(_Serializable):
    description: str
    methods: List[str]
    paths: List[str]
    headers: Dict[str, str]
    notes: str


@dataclass
class ReconMapping(_Serializable):
    surface_elements: List[SurfaceElement]
    http_probe_patterns: List[HTTPProbePattern]
    mapping_strategy: List[str]


# ---------------------------------------------------------------------------
# ThreatModel models
# ---------------------------------------------------------------------------

@dataclass
class Asset(_Serializable):
    name: str
    description: str


@dataclass
class ThreatHypothesis(_Serializable):
    id: str
    description: str
    related_categories: List[str]
    related_attack_paths: List[str]
    # "low" | "medium" | "high" | "critical"
    impact_if_confirmed: str


@dataclass
class ThreatModel(_Serializable):
    assets: List[Asset]
    hypotheses: List[ThreatHypothesis]


# ---------------------------------------------------------------------------
# TestCase
# ---------------------------------------------------------------------------

@dataclass
class TestCase(_Serializable):
    id: str
    objective: str
    preconditions: List[str]
    steps_summary: List[str]
    expected_weak_signals: List[str]
    # "low" | "medium" | "high" | "critical"
    severity_if_confirmed: str
    notes: str


# ---------------------------------------------------------------------------
# AttackChain
# ---------------------------------------------------------------------------

@dataclass
class AttackChain(_Serializable):
    id: str
    name: str
    steps: List[str]  # TestCase IDs in sequence
    summary: str


# ---------------------------------------------------------------------------
# Detection / Telemetry
# ---------------------------------------------------------------------------

@dataclass
class LoggingRecommendation(_Serializable):
    event: str
    fields: List[str]
    notes: str


@dataclass
class DetectionIdea(_Serializable):
    pattern: str
    # "low" | "medium" | "high" | "critical"
    severity: str
    notes: str


@dataclass
class DetectionTelemetry(_Serializable):
    logging_recommendations: List[LoggingRecommendation]
    detection_ideas: List[DetectionIdea]


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------

@dataclass
class Hardening(_Serializable):
    quick_wins: List[str]
    architectural_changes: List[str]
    template_guidance: List[str]


# ---------------------------------------------------------------------------
# TargetProfile
# ---------------------------------------------------------------------------

@dataclass
class HostSummary(_Serializable):
    total_hosts: int
    severity_counts: Dict[str, int]
    sector_counts: Dict[str, int]
    auth_posture_counts: Dict[str, int]


@dataclass
class TargetProfile(_Serializable):
    # "category" | "platform" | "attack_path"
    focus_type: str
    focus_value: str
    host_summary: HostSummary
    typical_platforms: List[str]
    representative_notes: str


# ---------------------------------------------------------------------------
# Top-level ScenarioPacket
# ---------------------------------------------------------------------------

@dataclass
class ScenarioPacket(_Serializable):
    target_profile: TargetProfile
    recon_mapping: ReconMapping
    threat_model: ThreatModel
    test_cases: List[TestCase]
    attack_chains: List[AttackChain]
    detection_telemetry: DetectionTelemetry
    hardening: Hardening

    # ------------------------------------------------------------------
    # Convenience: rebuild from a dict (e.g., loaded from stored JSON)
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScenarioPacket":
        hs = d["target_profile"]["host_summary"]
        tp = TargetProfile(
            focus_type=d["target_profile"]["focus_type"],
            focus_value=d["target_profile"]["focus_value"],
            host_summary=HostSummary(**hs),
            typical_platforms=d["target_profile"]["typical_platforms"],
            representative_notes=d["target_profile"]["representative_notes"],
        )
        rm = ReconMapping(
            surface_elements=[SurfaceElement(**e) for e in d["recon_mapping"]["surface_elements"]],
            http_probe_patterns=[HTTPProbePattern(**p) for p in d["recon_mapping"]["http_probe_patterns"]],
            mapping_strategy=d["recon_mapping"]["mapping_strategy"],
        )
        tm = ThreatModel(
            assets=[Asset(**a) for a in d["threat_model"]["assets"]],
            hypotheses=[ThreatHypothesis(**h) for h in d["threat_model"]["hypotheses"]],
        )
        tcs = [TestCase(**tc) for tc in d["test_cases"]]
        acs = [AttackChain(**ac) for ac in d["attack_chains"]]
        dt = DetectionTelemetry(
            logging_recommendations=[LoggingRecommendation(**l) for l in d["detection_telemetry"]["logging_recommendations"]],
            detection_ideas=[DetectionIdea(**di) for di in d["detection_telemetry"]["detection_ideas"]],
        )
        h = Hardening(**d["hardening"])
        return cls(tp, rm, tm, tcs, acs, dt, h)

"""
AegisLLM Operator - Data Models

All models are stdlib dataclasses. Serialize the full packet with:
    import dataclasses
    dataclasses.asdict(packet)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional


# ---------------------------------------------------------------------------
# Type aliases (runtime: plain strings; type checkers see the Literal bounds)
# ---------------------------------------------------------------------------

FocusType = Literal["category", "platform", "attack_path"]
SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
Criticality = Literal["low", "medium", "high", "mission_critical"]
Confidence = Literal["low", "medium", "high"]
Aggressiveness = Literal["low_noise", "medium", "high"]
NoiseProfile = Literal["low_noise", "medium", "high"]
SurfaceElementType = Literal["http_path", "port", "header_pattern", "banner_pattern"]


# ---------------------------------------------------------------------------
# Domain registries
# ---------------------------------------------------------------------------

class ExposureCategory:
    EXPOSED_MODEL_RUNTIMES = "exposed_model_runtimes"
    OPEN_GATEWAYS         = "open_gateways"
    NOTEBOOKS             = "notebooks"
    CHAT_UIS              = "chat_uis"
    LEAKY_DATA_STORES     = "leaky_data_stores"
    KEY_ABUSE             = "key_abuse"
    OBSERVABILITY         = "observability"
    AGENT_SURFACES        = "agent_surfaces"

    ALL = [
        EXPOSED_MODEL_RUNTIMES, OPEN_GATEWAYS, NOTEBOOKS, CHAT_UIS,
        LEAKY_DATA_STORES, KEY_ABUSE, OBSERVABILITY, AGENT_SURFACES,
    ]

    # platform string -> category
    PLATFORM_MAP: Dict[str, str] = {
        "Ollama":       EXPOSED_MODEL_RUNTIMES,
        "vLLM":         EXPOSED_MODEL_RUNTIMES,
        "LiteLLM":      OPEN_GATEWAYS,
        "One-API":      OPEN_GATEWAYS,
        "Kong":         OPEN_GATEWAYS,
        "PortKey.ai":   OPEN_GATEWAYS,
        "JupyterHub":   NOTEBOOKS,
        "Open WebUI":   CHAT_UIS,
        "Streamlit":    CHAT_UIS,
        "Elasticsearch": LEAKY_DATA_STORES,
        "Weaviate":     LEAKY_DATA_STORES,
        "Qdrant":       LEAKY_DATA_STORES,
        "Milvus":       LEAKY_DATA_STORES,
        "MLflow":       OBSERVABILITY,
        "Langfuse":     OBSERVABILITY,
        "Flowise":      AGENT_SURFACES,
        "Langflow":     AGENT_SURFACES,
        "OpenHands":    AGENT_SURFACES,
    }

    # category -> canonical platform list
    PLATFORMS: Dict[str, List[str]] = {
        EXPOSED_MODEL_RUNTIMES: ["Ollama", "vLLM"],
        OPEN_GATEWAYS:          ["LiteLLM", "One-API", "Kong", "PortKey.ai"],
        NOTEBOOKS:              ["JupyterHub"],
        CHAT_UIS:               ["Open WebUI", "Streamlit"],
        LEAKY_DATA_STORES:      ["Elasticsearch", "Weaviate", "Qdrant", "Milvus"],
        OBSERVABILITY:          ["MLflow", "Langfuse"],
        AGENT_SURFACES:         ["Flowise", "Langflow", "OpenHands"],
    }


class AttackPath:
    OPEN_GATEWAY_LLMJACKING          = "open_gateway_llmjacking"
    OLLAMA_11434_HOST_TAKEOVER       = "ollama_11434_host_takeover"
    FLOWISE_TO_WEAVIATE_PII_DUMP     = "flowise_to_weaviate_pii_dump"
    OPEN_WEBUI_OPEN_SIGNUP_RAG_SEAT  = "open_webui_open_signup_rag_seat"
    OPEN_JUPYTER_GPU_RCE             = "open_jupyter_gpu_rce"

    ALL = [
        OPEN_GATEWAY_LLMJACKING, OLLAMA_11434_HOST_TAKEOVER,
        FLOWISE_TO_WEAVIATE_PII_DUMP, OPEN_WEBUI_OPEN_SIGNUP_RAG_SEAT,
        OPEN_JUPYTER_GPU_RCE,
    ]

    # attack path -> primary exposure category
    CATEGORY_MAP: Dict[str, str] = {
        OPEN_GATEWAY_LLMJACKING:         ExposureCategory.OPEN_GATEWAYS,
        OLLAMA_11434_HOST_TAKEOVER:      ExposureCategory.EXPOSED_MODEL_RUNTIMES,
        FLOWISE_TO_WEAVIATE_PII_DUMP:    ExposureCategory.AGENT_SURFACES,
        OPEN_WEBUI_OPEN_SIGNUP_RAG_SEAT: ExposureCategory.CHAT_UIS,
        OPEN_JUPYTER_GPU_RCE:            ExposureCategory.NOTEBOOKS,
    }


# ---------------------------------------------------------------------------
# Leaf models
# ---------------------------------------------------------------------------

@dataclass
class SurfaceElement:
    type: SurfaceElementType
    pattern: str
    notes: str


@dataclass
class HTTPProbePattern:
    id: str
    description: str
    methods: List[str]
    paths: List[str]
    headers: Dict[str, str]
    body_shape: Optional[str]
    aggressiveness: Aggressiveness
    goals: List[str]
    notes: str


@dataclass
class ReconPhase:
    id: str
    name: str
    description: str
    probe_ids: List[str]


@dataclass
class Asset:
    name: str
    description: str
    criticality: Criticality


@dataclass
class ThreatHypothesis:
    id: str
    description: str
    related_categories: List[str]
    related_attack_paths: List[str]
    impact_if_confirmed: SeverityLevel
    confidence: Confidence
    notes: str


@dataclass
class TestCase:
    id: str
    objective: str
    preconditions: List[str]
    steps_summary: List[str]
    expected_weak_signals: List[str]
    severity_if_confirmed: SeverityLevel
    noise_level: Aggressiveness
    detection_focus: List[str]
    related_assets: List[str]
    notes: str


@dataclass
class AttackChain:
    id: str
    name: str
    steps: List[str]                    # TestCase IDs in sequence
    summary: str
    overall_noise_profile: NoiseProfile
    defender_learning_goals: List[str]
    related_attack_paths: List[str]


@dataclass
class LoggingRecommendation:
    event: str
    fields: List[str]
    notes: str


@dataclass
class DetectionIdea:
    pattern: str
    severity: SeverityLevel
    notes: str


# ---------------------------------------------------------------------------
# Composite models
# ---------------------------------------------------------------------------

@dataclass
class TargetProfile:
    focus_type: FocusType
    focus_value: str
    host_summary: Dict                  # total_hosts, severity_counts, sector_counts, auth_posture_counts
    typical_platforms: List[str]
    notable_patterns: List[str]
    representative_notes: str


@dataclass
class ReconMapping:
    surface_elements: List[SurfaceElement]
    http_probe_patterns: List[HTTPProbePattern]
    recon_phases: List[ReconPhase]


@dataclass
class ThreatModel:
    assets: List[Asset]
    hypotheses: List[ThreatHypothesis]


@dataclass
class DetectionTelemetry:
    logging_recommendations: List[LoggingRecommendation]
    detection_ideas: List[DetectionIdea]
    stealth_considerations: List[str]


@dataclass
class Hardening:
    quick_wins: List[str]
    architectural_changes: List[str]
    detection_engineering_actions: List[str]
    template_guidance: List[str]


@dataclass
class ScenarioPacket:
    target_profile: TargetProfile
    recon_mapping: ReconMapping
    threat_model: ThreatModel
    test_cases: List[TestCase]
    attack_chains: List[AttackChain]
    detection_telemetry: DetectionTelemetry
    hardening: Hardening

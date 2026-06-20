"""
AegisLLM Operator - Core engine

AegisLLM_Operator models a senior AI/LLM red-teamer + detection engineer.
It generates richly-structured Scenario Packets for authorized assessments.

Two scenarios are fully implemented:
  - category / open_gateways
  - attack_path / flowise_to_weaviate_pii_dump

All others fall through to _generic stubs with clear TODO markers.
"""

import dataclasses
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AttackChain,
    AttackPath,
    Asset,
    Aggressiveness,
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


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_STUB_HOST_SUMMARY_EMPTY: Dict = {
    "total_hosts": 0,
    "severity_counts": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
    "sector_counts": {
        "commercial": 0, "university": 0, "research": 0,
        "government": 0, "healthcare": 0, "other": 0,
    },
    "auth_posture_counts": {"open": 0, "weak": 0, "auth": 0, "unknown": 0},
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AegisLLM_Operator:
    """
    Generate Scenario Packets for AI/LLM red-team and detection engineering work.
    All active testing assumes explicit authorization; this tool is for
    authorized internal/client assessments only.
    """

    def __init__(self, db_path: str, coords_path: str, details_path: str):
        self.db_path = db_path
        self.coords_path = coords_path
        self.details_path = details_path
        self._details_cache: Optional[List[Dict]] = None
        self._coords_cache: Optional[List[Dict]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_scenario_packet(
        self,
        focus_type: FocusType,
        focus_value: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a full ScenarioPacket.

        options keys:
          min_severity: str  -- filter hosts below this severity
          sector: list[str]  -- restrict to these sectors
        """
        options = options or {}
        key: Tuple[str, str] = (focus_type, focus_value)

        packet = ScenarioPacket(
            target_profile=self._build_target_profile(key, options),
            recon_mapping=self._build_recon_mapping(key, options),
            threat_model=self._build_threat_model(key, options),
            test_cases=self._build_test_cases(key, options),
            attack_chains=self._build_attack_chains(key, options),
            detection_telemetry=self._build_detection_telemetry(key, options),
            hardening=self._build_hardening(key, options),
        )
        return dataclasses.asdict(packet)

    def render_markdown(self, packet: Dict[str, Any]) -> str:
        """Delegate to render module (imported lazily to avoid circular)."""
        from .render import render_markdown  # noqa: PLC0415
        return render_markdown(packet)

    # ------------------------------------------------------------------
    # Builder dispatch layer
    # ------------------------------------------------------------------

    def _build_target_profile(self, key, options) -> TargetProfile:
        if key == ("category", "open_gateways"):
            return self._tp_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._tp_flowise_weaviate(options)
        return self._tp_generic(key[0], key[1], options)

    def _build_recon_mapping(self, key, options) -> ReconMapping:
        if key == ("category", "open_gateways"):
            return self._recon_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._recon_flowise_weaviate(options)
        return self._recon_generic(key[0], key[1], options)

    def _build_threat_model(self, key, options) -> ThreatModel:
        if key == ("category", "open_gateways"):
            return self._tm_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._tm_flowise_weaviate(options)
        return self._tm_generic(key[0], key[1], options)

    def _build_test_cases(self, key, options) -> List[TestCase]:
        if key == ("category", "open_gateways"):
            return self._tc_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._tc_flowise_weaviate(options)
        return self._tc_generic(key[0], key[1], options)

    def _build_attack_chains(self, key, options) -> List[AttackChain]:
        if key == ("category", "open_gateways"):
            return self._ac_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._ac_flowise_weaviate(options)
        return self._ac_generic(key[0], key[1], options)

    def _build_detection_telemetry(self, key, options) -> DetectionTelemetry:
        if key == ("category", "open_gateways"):
            return self._dt_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._dt_flowise_weaviate(options)
        return self._dt_generic(key[0], key[1], options)

    def _build_hardening(self, key, options) -> Hardening:
        if key == ("category", "open_gateways"):
            return self._h_open_gateways(options)
        if key == ("attack_path", "flowise_to_weaviate_pii_dump"):
            return self._h_flowise_weaviate(options)
        return self._h_generic(key[0], key[1], options)

    # ------------------------------------------------------------------
    # Data access helpers
    # ------------------------------------------------------------------

    def _load_details(self) -> List[Dict]:
        if self._details_cache is None:
            # TODO: replace with real file load
            # with open(self.details_path) as fh:
            #     self._details_cache = json.load(fh)
            self._details_cache = []
        return self._details_cache

    def _load_coords(self) -> List[Dict]:
        if self._coords_cache is None:
            # TODO: replace with real file load
            # with open(self.coords_path) as fh:
            #     self._coords_cache = json.load(fh)
            self._coords_cache = []
        return self._coords_cache

    def _query_host_summary(
        self,
        platforms: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
        sectors: Optional[List[str]] = None,
    ) -> Dict:
        """
        Return host statistics from nuclide.db.

        TODO: wire to real DB. Schema assumed:
          hosts(ip, owner, country, sector, severity, survey_id)
          details(ip, ports, platform, auth_posture)

        Example query:
            conn = sqlite3.connect(self.db_path)
            min_idx = _SEVERITY_ORDER.index(min_severity) if min_severity else 0
            platform_filter = " AND d.platform IN ({})".format(
                ",".join("?" * len(platforms))
            ) if platforms else ""
            sector_filter = " AND h.sector IN ({})".format(
                ",".join("?" * len(sectors))
            ) if sectors else ""
            cur = conn.execute(
                f'''SELECT h.severity, h.sector, d.auth_posture, COUNT(*) AS n
                    FROM hosts h JOIN details d ON h.ip = d.ip
                    WHERE 1=1 {platform_filter} {sector_filter}
                    GROUP BY h.severity, h.sector, d.auth_posture''',
                (*(platforms or []), *(sectors or []))
            )
            rows = cur.fetchall()
            ...aggregate into dicts...
            conn.close()
        """
        return dict(_STUB_HOST_SUMMARY_EMPTY)  # shallow copy of defaults

    # ==================================================================
    # SCENARIO: open_gateways
    # ==================================================================

    def _tp_open_gateways(self, options: Dict) -> TargetProfile:
        # TODO: replace stub counts with _query_host_summary(
        #     platforms=["LiteLLM", "One-API", "Kong", "PortKey.ai"],
        #     min_severity=options.get("min_severity"),
        #     sectors=options.get("sector"),
        # )
        host_summary = {
            "total_hosts": 312,
            "severity_counts": {
                "info": 8, "low": 42, "medium": 87, "high": 118, "critical": 57,
            },
            "sector_counts": {
                "commercial": 174, "research": 68, "university": 41,
                "government": 18, "healthcare": 11,
            },
            "auth_posture_counts": {"open": 187, "weak": 94, "auth": 19, "unknown": 12},
        }
        return TargetProfile(
            focus_type="category",
            focus_value="open_gateways",
            host_summary=host_summary,
            typical_platforms=["LiteLLM", "One-API", "Kong AI Gateway", "PortKey.ai"],
            notable_patterns=[
                "60% commercial-sector gateways expose provider keys to authenticated"
                " upstream services but run the proxy itself with no auth (LITELLM_MASTER_KEY unset).",
                "Admin key management endpoints (/admin/key/generate, /admin/key/list) are"
                " consistently co-deployed on the same port as the inference API with no route-level auth separation.",
                "Swagger/OpenAPI docs auto-enabled in default configs; /openapi.json returns"
                " the full route inventory and parameter schemas without authentication.",
                "Spend-tracking endpoints (/spend/logs, /key/info) leak per-tenant cost"
                " attribution, key prefixes, and model usage patterns in cleartext.",
                "Multi-tenant commercial deployments use a single gateway instance with"
                " virtual keys per customer; BOLA on integer key IDs exposes the full tenant registry.",
            ],
            representative_notes=(
                "Typical target: LiteLLM proxy on port 4000, commercial SaaS operator. "
                "Swagger UI live at /docs. GET /v1/models returns the model list unauthenticated. "
                "GET /health returns {status: healthy}. /admin/key/list returns the full key roster "
                "with no Authorization header required. The blast radius on confirmed key extraction "
                "spans unauthorized inference spend across all upstream providers served by that gateway."
            ),
        )

    def _recon_open_gateways(self, options: Dict) -> ReconMapping:
        surface_elements = [
            SurfaceElement("http_path", "/v1/models",
                           "Model enumeration - returns JSON list; auth absent = open inference surface"),
            SurfaceElement("http_path", "/v1/chat/completions",
                           "Inference entry point; POST without auth = LLMjacking vector"),
            SurfaceElement("http_path", "/health",
                           "Liveness probe; 200 = service up; body often reveals platform version"),
            SurfaceElement("http_path", "/docs",
                           "Swagger UI; auto-enabled in LiteLLM/FastAPI defaults"),
            SurfaceElement("http_path", "/openapi.json",
                           "Full route+schema inventory; parse for undocumented admin routes"),
            SurfaceElement("http_path", "/admin",
                           "Admin root; LiteLLM mounts /admin/key/*, /admin/user/*, /admin/team/*"),
            SurfaceElement("http_path", "/admin/key/list",
                           "Returns all virtual keys and their upstream provider associations"),
            SurfaceElement("http_path", "/config",
                           "LiteLLM YAML config dump; may include env var expansion of API keys"),
            SurfaceElement("http_path", "/config/yaml",
                           "Raw YAML form of gateway config - higher chance of key material"),
            SurfaceElement("http_path", "/spend/logs",
                           "Per-request cost log; key prefixes and model IDs visible"),
            SurfaceElement("port", "4000",
                           "LiteLLM default port"),
            SurfaceElement("port", "3000",
                           "One-API default port"),
            SurfaceElement("port", "8000",
                           "Kong proxy port (8001=admin)"),
            SurfaceElement("port", "8001",
                           "Kong admin API - separate from proxy but frequently co-exposed"),
            SurfaceElement("header_pattern", "x-litellm-call-id",
                           "Response header; confirms LiteLLM; present on all inference responses"),
            SurfaceElement("header_pattern", "x-ratelimit-limit-requests",
                           "OpenAI-compatible header; present on gateways mimicking OAI rate-limit headers"),
            SurfaceElement("banner_pattern", '"model":"gpt-',
                           "/v1/models body; confirms GPT routing = OpenAI key on backend"),
            SurfaceElement("banner_pattern", "LiteLLM",
                           "Version string in /health or error bodies"),
        ]

        probe_patterns = [
            HTTPProbePattern(
                id="P-001",
                description="Low-noise baseline: confirm service identity and liveness",
                methods=["GET", "HEAD"],
                paths=["/health", "/status", "/v1/models"],
                headers={},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Confirm service is live and responding",
                    "Identify platform from response body / headers",
                    "Enumerate available model IDs without triggering auth",
                ],
                notes="Single request per path, no auth header. /v1/models JSON body is the"
                      " key signal: provider prefixes (gpt-*, claude-*, mistral-*) reveal upstream keys.",
            ),
            HTTPProbePattern(
                id="P-002",
                description="Schema and docs discovery: map full route inventory",
                methods=["GET"],
                paths=["/docs", "/openapi.json", "/swagger.json", "/redoc"],
                headers={},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Extract full route list from OpenAPI spec",
                    "Identify admin route prefixes before probing",
                    "Discover non-standard paths not visible via brute-force",
                ],
                notes="Parse /openapi.json programmatically. LiteLLM exposes 80+ routes."
                      " Filter for paths containing 'key', 'admin', 'spend', 'config', 'team', 'user'.",
            ),
            HTTPProbePattern(
                id="P-003",
                description="Auth boundary probe: test inference routes with and without credentials",
                methods=["GET", "POST"],
                paths=["/v1/models", "/v1/chat/completions"],
                headers={"Authorization": "Bearer ABSENT"},
                body_shape="POST /v1/chat/completions: {model: <from P-001>, messages: [{role: user, content: echo}]}",
                aggressiveness="low_noise",
                goals=[
                    "Determine if inference requires a valid API key",
                    "Confirm whether virtual key model differs from master key model",
                    "Identify error format for missing vs invalid auth (fingerprints gateway version)",
                ],
                notes="Two requests: one with no auth, one with a garbage key. Compare status codes"
                      " and error bodies. 200 on no-auth = open. Error body revealing key format = useful for mutation.",
            ),
            HTTPProbePattern(
                id="P-004",
                description="Config endpoint traversal: probe for key material in config responses",
                methods=["GET"],
                paths=[
                    "/config", "/config/yaml", "/litellm/settings",
                    "/settings", "/v1/config", "/api/config",
                ],
                headers={},
                body_shape=None,
                aggressiveness="medium",
                goals=[
                    "Find gateway config endpoints returning environment variable values",
                    "Identify provider API key patterns (sk-*, sk-ant-*, AIza*, OPENAI_API_KEY)",
                    "Map model-to-provider routing table",
                ],
                notes="LiteLLM /config can return YAML with inline key values if LITELLM_CONFIG_FILE"
                      " is set and the endpoint is unprotected. Look for base64 blobs and sk-* patterns.",
            ),
            HTTPProbePattern(
                id="P-005",
                description="Admin key and user management: enumerate key roster and tenant structure",
                methods=["GET"],
                paths=[
                    "/admin/key/list", "/admin/key/info",
                    "/admin/user/list", "/admin/team/list",
                    "/admin/spend/logs", "/spend/logs",
                ],
                headers={},
                body_shape=None,
                aggressiveness="medium",
                goals=[
                    "List all virtual API keys and their associated user/team/budget context",
                    "Map tenant structure (user_id -> key -> model allowlist)",
                    "Extract spend_id, key_alias fields for BOLA candidate generation",
                ],
                notes="Absence of auth header is the test. 200 = critical finding. Response JSON"
                      " may contain token_count, spend fields that fingerprint usage volume.",
            ),
            HTTPProbePattern(
                id="P-006",
                description="BOLA probe: test integer/UUID key ID enumeration on admin endpoints",
                methods=["GET"],
                paths=[
                    "/admin/key/info/{id}", "/v1/key/info",
                    "/admin/key/delete/{id}",
                ],
                headers={},
                body_shape=None,
                aggressiveness="high",
                goals=[
                    "Determine if key IDs are sequential integers or predictable UUIDs",
                    "Access key metadata for IDs other than the authenticated user's own key",
                    "Confirm absence of ownership check (BOLA) on key info endpoints",
                ],
                notes="Aggressive: each request touches a different resource ID. Keep request rate"
                      " low (1 req/3s) to avoid rate-limit trips. Stop on first confirmed cross-tenant access.",
            ),
            HTTPProbePattern(
                id="P-007",
                description="Error condition mapping: characterize auth error format and versioning",
                methods=["GET", "POST"],
                paths=["/v1/chat/completions", "/admin/key/list"],
                headers={"Authorization": "Bearer invalid_key_AAAA"},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Fingerprint gateway version from error response format",
                    "Determine if error bodies leak route structure or internal stack traces",
                    "Establish baseline error format for distinguishing 'no auth' vs 'wrong auth'",
                ],
                notes="Single request per path, invalid auth. Error body may reveal internal routing,"
                      " upstream provider error messages (which confirm key types), or Python stack traces.",
            ),
        ]

        recon_phases = [
            ReconPhase(
                id="PHASE-1",
                name="Stealthy baseline",
                description=(
                    "Passive-equivalent: confirm liveness and platform identity from public-facing endpoints. "
                    "Zero admin path access. Goal is a confirmed fingerprint with minimal log noise."
                ),
                probe_ids=["P-001", "P-002"],
            ),
            ReconPhase(
                id="PHASE-2",
                name="Auth boundary mapping",
                description=(
                    "Map the auth perimeter without touching admin routes. "
                    "Confirm inference open/closed; extract error format. "
                    "Produces a clear go/no-go signal before deeper enumeration."
                ),
                probe_ids=["P-001", "P-002", "P-003", "P-007"],
            ),
            ReconPhase(
                id="PHASE-3",
                name="Targeted admin and config enumeration",
                description=(
                    "Full admin surface sweep after auth boundary is understood. "
                    "Config, key list, user list, spend logs. "
                    "Higher noise; run only when Phase 1+2 confirm the target is authorized-scope."
                ),
                probe_ids=["P-001", "P-002", "P-003", "P-004", "P-005", "P-007"],
            ),
            ReconPhase(
                id="PHASE-4",
                name="Adversarial depth: BOLA and cross-tenant",
                description=(
                    "Targeted BOLA against key/user ID namespaces. Run ONLY when Phase 3 confirms"
                    " ID-based access patterns and explicit authorization is in scope for tenant boundary testing."
                ),
                probe_ids=["P-005", "P-006"],
            ),
        ]

        return ReconMapping(
            surface_elements=surface_elements,
            http_probe_patterns=probe_patterns,
            recon_phases=recon_phases,
        )

    def _tm_open_gateways(self, options: Dict) -> ThreatModel:
        assets = [
            Asset(
                name="provider_keys",
                description=(
                    "Upstream LLM provider API keys (OpenAI sk-*, Anthropic sk-ant-api03-*,"
                    " Azure AZURE_OPENAI_KEY, Cohere, Mistral, Bedrock credentials). "
                    "Gateway holds these centrally; compromise = full provider account access."
                ),
                criticality="mission_critical",
            ),
            Asset(
                name="virtual_keys",
                description=(
                    "Per-tenant/user virtual keys issued by the gateway. Loss exposes tenant routing"
                    " configs, spend budgets, and model allowlists. May be used to impersonate tenants."
                ),
                criticality="high",
            ),
            Asset(
                name="admin_credentials",
                description=(
                    "LITELLM_MASTER_KEY or One-API root token. Controls key generation,"
                    " user management, and routing config. Admin token ≈ full gateway takeover."
                ),
                criticality="mission_critical",
            ),
            Asset(
                name="routing_config",
                description=(
                    "Model-to-provider routing rules, load balancing weights, fallback chains."
                    " Exposure reveals full upstream dependency map and enables targeted supply chain attacks."
                ),
                criticality="high",
            ),
            Asset(
                name="spend_and_audit_data",
                description=(
                    "Per-request cost logs with key_id, user_id, model, token counts."
                    " Reveals tenant activity patterns, model preferences, and usage volumes."
                ),
                criticality="medium",
            ),
            Asset(
                name="tenant_registry",
                description=(
                    "User/team/org list with associated keys and spend budgets."
                    " Multi-tenant enumeration surface; BOLA pivot point."
                ),
                criticality="high",
            ),
        ]

        hypotheses = [
            ThreatHypothesis(
                id="H-001",
                description=(
                    "Admin key management endpoints (/admin/key/list, /admin/key/generate)"
                    " are accessible without any authentication."
                ),
                related_categories=["open_gateways", "key_abuse"],
                related_attack_paths=["open_gateway_llmjacking"],
                impact_if_confirmed="critical",
                confidence="high",
                notes=(
                    "LiteLLM's default config sets LITELLM_MASTER_KEY to an empty string,"
                    " which the code treats as 'no auth required' on /admin/* routes."
                    " Confirmed pattern across commercial survey set."
                ),
            ),
            ThreatHypothesis(
                id="H-002",
                description=(
                    "Config endpoints return environment variable values including"
                    " provider API key material in plaintext or recoverable form."
                ),
                related_categories=["open_gateways", "key_abuse"],
                related_attack_paths=["open_gateway_llmjacking"],
                impact_if_confirmed="critical",
                confidence="medium",
                notes=(
                    "Depends on whether the gateway operator sets LITELLM_CONFIG_FILE"
                    " and exposes /config. Some versions expand ${ENV_VAR} inline in the response."
                ),
            ),
            ThreatHypothesis(
                id="H-003",
                description=(
                    "Spend and audit log endpoints leak key prefixes sufficient to"
                    " identify provider type and enable inference request forgery."
                ),
                related_categories=["open_gateways"],
                related_attack_paths=["open_gateway_llmjacking"],
                impact_if_confirmed="high",
                confidence="high",
                notes=(
                    "Even masked keys (sk-****XXXX) in spend logs allow provider type"
                    " identification. Combined with open inference = confirmed LLMjacking surface."
                ),
            ),
            ThreatHypothesis(
                id="H-004",
                description=(
                    "API key IDs on /admin/key/info/{id} are sequential integers or"
                    " non-rotating UUIDs with no ownership enforcement (BOLA)."
                ),
                related_categories=["open_gateways"],
                related_attack_paths=["open_gateway_llmjacking"],
                impact_if_confirmed="high",
                confidence="medium",
                notes=(
                    "Requires at least one valid virtual key to probe. If key IDs are"
                    " integers and no ownership check is enforced, full tenant registry accessible."
                ),
            ),
            ThreatHypothesis(
                id="H-005",
                description=(
                    "Kong Admin API (port 8001) is reachable from the same network segment"
                    " as the proxy port (8000), allowing service, route, and plugin manipulation."
                ),
                related_categories=["open_gateways"],
                related_attack_paths=["open_gateway_llmjacking"],
                impact_if_confirmed="critical",
                confidence="low",
                notes=(
                    "Kong ships with admin API on 8001 by default with no auth."
                    " If the operator didn't bind 8001 to loopback, it's trivially reachable."
                    " Low confidence because cloud deployments often use SGs to block 8001."
                ),
            ),
        ]

        return ThreatModel(assets=assets, hypotheses=hypotheses)

    def _tc_open_gateways(self, options: Dict) -> List[TestCase]:
        return [
            TestCase(
                id="TC-001",
                objective="Confirm unauthenticated model enumeration and inference access.",
                preconditions=[
                    "Target IP and port confirmed reachable (Phase 1 liveness positive).",
                    "Authorization scope confirmed for this host.",
                ],
                steps_summary=[
                    "GET /v1/models with no Authorization header. Observe: 200 = open; 401/403 = gated.",
                    "Parse JSON response: extract model IDs. Note provider prefixes"
                    " (gpt-*, claude-*, mistral-*) to identify upstream providers.",
                    "POST /v1/chat/completions with a minimal payload (model from step 2,"
                    " messages: [{role:user, content:'1+1'}]) and no Authorization header.",
                    "If 200 received on POST: document response body as proof of open inference."
                    " Record token usage from response headers (x-ratelimit-*).",
                    "Cross-check x-litellm-call-id presence in response headers to confirm LiteLLM.",
                ],
                expected_weak_signals=[
                    "200 OK on GET /v1/models with no auth header present.",
                    "JSON array under 'data' key containing model objects with 'id' fields.",
                    "200 OK on POST /v1/chat/completions returning 'choices' array.",
                    "Provider-prefixed model IDs (gpt-4, claude-3-*, mistral-*) confirming"
                    " upstream keys are active.",
                ],
                severity_if_confirmed="critical",
                noise_level="low_noise",
                detection_focus=["auth_failures", "anomalous_paths"],
                related_assets=["provider_keys", "virtual_keys"],
                notes=(
                    "Zero-auth inference is a direct LLMjacking vector. Document the full model"
                    " list and one confirmed inference response as the proof artifact. Stop after"
                    " confirming; do not run inference in bulk."
                ),
            ),
            TestCase(
                id="TC-002",
                objective="Access admin key management endpoints without authentication.",
                preconditions=[
                    "Service confirmed live (TC-001 or Phase 1 complete).",
                    "Admin route inventory obtained from /openapi.json (P-002).",
                ],
                steps_summary=[
                    "GET /admin/key/list with no Authorization header.",
                    "If 200: parse response for key objects. Note fields: key_name, key_alias,"
                    " user_id, team_id, spend, budget_id, models, permissions.",
                    "GET /admin/user/list with no auth. Enumerate user_id fields for tenant registry.",
                    "GET /admin/team/list with no auth. Map org structure.",
                    "GET /admin/spend/logs with no auth. Extract key prefixes from log entries.",
                    "Note any 'hashed_api_key' or 'api_key' fields in responses - these confirm"
                    " the key storage model and potential for further extraction.",
                ],
                expected_weak_signals=[
                    "200 OK on /admin/key/list with JSON array of key objects.",
                    "Key objects containing 'key_name' or 'api_key' fields.",
                    "user_id and team_id fields enabling tenant registry reconstruction.",
                    "spend and max_budget fields leaking cost attribution data.",
                ],
                severity_if_confirmed="critical",
                noise_level="medium",
                detection_focus=["auth_failures", "anomalous_paths", "admin_route_access"],
                related_assets=["provider_keys", "virtual_keys", "admin_credentials", "tenant_registry"],
                notes=(
                    "This is the core LLMjacking pivot: open admin key list = full provider"
                    " key roster. Document as CRITICAL. The hashed_api_key field, if present,"
                    " may be reversible or usable directly depending on LiteLLM version."
                ),
            ),
            TestCase(
                id="TC-003",
                objective="Extract provider key material from config or settings endpoints.",
                preconditions=[
                    "Service confirmed live. /openapi.json parsed for config route variants.",
                ],
                steps_summary=[
                    "GET /config with no auth header. If 404, try /config/yaml, /settings, /litellm/settings.",
                    "If 200: scan response body for sk-*, sk-ant-*, AIza*, AZURE_OPENAI_API_KEY patterns.",
                    "Check for ${ENV_VAR} references - may indicate env var expansion in the response.",
                    "GET /v1/config (alternate LiteLLM route). Some versions expose config on this path.",
                    "If config returns model_list: extract litellm_params.api_key fields per model entry.",
                    "Document any key strings found verbatim (masked for report; full version in evidence).",
                ],
                expected_weak_signals=[
                    "200 OK on /config or /config/yaml with JSON/YAML body.",
                    "api_key fields in model_list entries containing sk-* or sk-ant-* patterns.",
                    "Environment variable names in config that confirm key storage strategy.",
                    "base64-encoded strings in config that decode to key-like values.",
                ],
                severity_if_confirmed="critical",
                noise_level="medium",
                detection_focus=["config_endpoint_access", "anomalous_paths"],
                related_assets=["provider_keys", "routing_config"],
                notes=(
                    "Config extraction is the cleanest key-grab path on misconfigured LiteLLM."
                    " model_list[].litellm_params.api_key is the canonical field. If the gateway"
                    " uses environment variable substitution, the key appears in cleartext."
                ),
            ),
            TestCase(
                id="TC-004",
                objective="Enumerate spend logs to reconstruct tenant-to-key mapping.",
                preconditions=[
                    "Spend/log endpoint confirmed present in /openapi.json route inventory.",
                ],
                steps_summary=[
                    "GET /spend/logs with no auth (or /v1/spend, /v1/logs).",
                    "Parse response: extract api_key (may be masked), user_id, model, spend fields per entry.",
                    "Correlate user_id values across entries to reconstruct per-tenant usage profiles.",
                    "Identify model usage patterns: frequency of expensive models indicates budget-uncapped keys.",
                    "Note any api_key fields that appear in full (unmasked) in log entries.",
                ],
                expected_weak_signals=[
                    "200 OK on /spend/logs with JSON array of request log entries.",
                    "api_key field present in entries (even masked prefix is useful for provider ID).",
                    "user_id or team_id fields enabling tenant activity reconstruction.",
                    "Model usage patterns revealing inference volume (token counts per entry).",
                ],
                severity_if_confirmed="high",
                noise_level="low_noise",
                detection_focus=["spend_log_access", "anomalous_paths"],
                related_assets=["spend_and_audit_data", "tenant_registry", "provider_keys"],
                notes=(
                    "Even masked key prefixes (sk-****3fa1) are useful: they confirm provider type"
                    " and enable partial enumeration. Full keys in logs = critical escalation of this finding."
                ),
            ),
            TestCase(
                id="TC-005",
                objective="Test BOLA on key info endpoint via resource ID enumeration.",
                preconditions=[
                    "TC-002 confirmed: admin key list accessible.",
                    "At least one key ID extracted (integer or UUID format confirmed).",
                    "Explicit authorization for tenant boundary testing in scope.",
                ],
                steps_summary=[
                    "From TC-002 response, note the id or token fields of the first key object.",
                    "GET /admin/key/info?key=<key_id> substituting an adjacent integer ID.",
                    "Compare response: does it return a different user's key metadata?",
                    "If UUIDs: attempt sequential enumeration is infeasible; check for"
                    " predictable patterns (time-ordered UUIDs, monotonic prefixes).",
                    "GET /admin/key/info for key IDs 1 through 10 if integer format confirmed.",
                ],
                expected_weak_signals=[
                    "200 OK on /admin/key/info with a user_id different from the requesting key's user.",
                    "Metadata for other tenants (different model allowlists, spend budgets, org names).",
                    "Response body containing tokens, api_key, or key_alias fields for non-owned keys.",
                ],
                severity_if_confirmed="critical",
                noise_level="high",
                detection_focus=["bola_patterns", "auth_failures", "admin_route_access"],
                related_assets=["virtual_keys", "tenant_registry"],
                notes=(
                    "BOLA here = full tenant registry + per-tenant key metadata without needing admin creds."
                    " Confirm with two distinct user_id values in two sequential requests. Stop after confirmation."
                ),
            ),
            TestCase(
                id="TC-006",
                objective="Schema-driven route discovery and endpoint expansion from /openapi.json.",
                preconditions=[
                    "GET /openapi.json or /docs returns a valid OpenAPI spec (P-002 successful).",
                ],
                steps_summary=[
                    "Fetch /openapi.json and parse paths object.",
                    "Filter for paths containing: key, admin, spend, config, team, user, model, log, audit.",
                    "For each identified path, note its security requirements (securitySchemes in spec).",
                    "Map paths with empty security: [] (no auth required per spec) as priority targets.",
                    "Cross-reference spec against observed 200/401 behavior from TC-001 to TC-005.",
                    "Identify any paths in spec not previously probed; route to appropriate test cases.",
                ],
                expected_weak_signals=[
                    "paths in spec with empty security array or no security key set.",
                    "Admin routes documented in spec that were not in the default test list.",
                    "Route parameters indicating resource IDs (confirms BOLA surface).",
                    "Response schemas for admin routes exposing api_key or provider fields.",
                ],
                severity_if_confirmed="medium",
                noise_level="low_noise",
                detection_focus=["schema_discovery", "anomalous_paths"],
                related_assets=["admin_credentials", "routing_config"],
                notes=(
                    "This is an intelligence-only test. The finding is the spec disclosure itself"
                    " (sensitive route inventory exposed). Actual route exploitation is handled in other TCs."
                ),
            ),
        ]

    def _ac_open_gateways(self, options: Dict) -> List[AttackChain]:
        return [
            AttackChain(
                id="AC-001",
                name="LLMjacking via Open Gateway Key Extraction",
                steps=["TC-001", "TC-006", "TC-003", "TC-002", "TC-004"],
                summary=(
                    "Identify an open LLM gateway, enumerate its route inventory via /openapi.json,"
                    " probe config and admin endpoints for provider key material, confirm open inference,"
                    " and assess blast radius from spend logs. No authentication required at any step."
                ),
                overall_noise_profile="low_noise",
                defender_learning_goals=[
                    "Detect unauthenticated access to /admin/* as a single-event critical signal.",
                    "Correlate /openapi.json or /docs fetch from an IP with no prior inference session"
                    " as a reconnaissance indicator (users don't browse the API spec).",
                    "Identify config endpoint access patterns outside of normal deployment automation windows.",
                ],
                related_attack_paths=["open_gateway_llmjacking"],
            ),
            AttackChain(
                id="AC-002",
                name="Tenant Pivot via BOLA on Key Management",
                steps=["TC-001", "TC-006", "TC-002", "TC-005"],
                summary=(
                    "Confirm open inference and admin access, parse the key management API"
                    " schema to identify resource ID format, then probe adjacent key IDs to"
                    " cross tenant boundaries and reconstruct the full tenant registry."
                ),
                overall_noise_profile="medium",
                defender_learning_goals=[
                    "Detect sequential resource ID access patterns on /admin/key/info across"
                    " a single session (N requests to same path template with incrementing IDs).",
                    "Alert on first cross-tenant response: user_id in response does not match"
                    " user_id of requesting key (if any auth is present).",
                    "Monitor for rapid succession of distinct user_id values in key info responses.",
                ],
                related_attack_paths=["open_gateway_llmjacking"],
            ),
        ]

    def _dt_open_gateways(self, options: Dict) -> DetectionTelemetry:
        logging_recs = [
            LoggingRecommendation(
                event="admin_route_access",
                fields=[
                    "timestamp", "source_ip", "method", "path", "response_code",
                    "auth_header_present", "auth_scheme", "user_agent",
                    "response_body_size", "request_id",
                ],
                notes=(
                    "Log ALL requests matching /admin/* regardless of response code."
                    " auth_header_present is a boolean derived from the Authorization header presence."
                    " A 200 with auth_header_present=false is a critical alert, not a threshold."
                ),
            ),
            LoggingRecommendation(
                event="schema_discovery_request",
                fields=[
                    "timestamp", "source_ip", "path", "response_code",
                    "user_agent", "referer", "bytes_sent",
                ],
                notes=(
                    "Log requests to /openapi.json, /docs, /swagger, /redoc, /swagger.json."
                    " Normal CI/automation fetches these on deploy; human enumeration during an"
                    " off-hours window from a novel IP is the detection signal."
                ),
            ),
            LoggingRecommendation(
                event="config_endpoint_access",
                fields=[
                    "timestamp", "source_ip", "path", "response_code",
                    "auth_header_present", "response_body_hash",
                ],
                notes=(
                    "Log /config, /config/yaml, /settings, /litellm/settings access."
                    " response_body_hash allows diff detection if config changes."
                    " Any access from outside the management CIDR = alert."
                ),
            ),
            LoggingRecommendation(
                event="inference_request",
                fields=[
                    "timestamp", "source_ip", "model", "prompt_tokens", "completion_tokens",
                    "api_key_prefix", "user_id", "response_code", "latency_ms",
                ],
                notes=(
                    "Per-request inference log. api_key_prefix (first 12 chars) enables"
                    " provider identification without logging full keys. Baseline by source IP;"
                    " spike in prompt_tokens from a novel IP is a jacking signal."
                ),
            ),
            LoggingRecommendation(
                event="key_management_operation",
                fields=[
                    "timestamp", "source_ip", "operation", "target_key_id",
                    "auth_header_present", "response_code", "actor_user_id",
                ],
                notes=(
                    "Covers /admin/key/generate, /admin/key/delete, /admin/key/update."
                    " operation field: CREATE|READ|UPDATE|DELETE. Any CREATE without"
                    " prior authenticated session from same IP = suspicious key minting."
                ),
            ),
        ]

        detection_ideas = [
            DetectionIdea(
                pattern=(
                    "200 OK returned on any /admin/* path where Authorization header is absent"
                ),
                severity="critical",
                notes=(
                    "Single-event alert. No threshold needed. A 200 on an admin route without"
                    " credentials is a confirmed misconfiguration + active exploitation signal."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "Source IP accesses /openapi.json or /docs with no prior 200 on"
                    " /v1/models or /v1/chat/completions in the same session window (30 min)"
                ),
                severity="medium",
                notes=(
                    "Schema enumeration without service usage. Legitimate clients call inference"
                    " endpoints first; schema browsing without inference = reconnaissance pattern."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "3+ distinct /admin/key/info requests with different resource IDs from"
                    " the same source IP within 60 seconds"
                ),
                severity="high",
                notes=(
                    "BOLA enumeration signature. The tell is the path template match across"
                    " multiple resource IDs. Even if responses are 403, the enumeration attempt is logged."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "Inference request volume from a source IP exceeds 200% of that IP's"
                    " 7-day rolling average within a 1-hour window"
                ),
                severity="high",
                notes=(
                    "LLMjacking spend anomaly. Requires baseline per source IP. False positive"
                    " risk on legitimate bursty workloads; tune threshold per customer tier."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "New source IP (no prior requests in 30 days) issues a POST to"
                    " /v1/chat/completions with no Authorization header and receives 200"
                ),
                severity="critical",
                notes=(
                    "Novel IP + open inference in a single request. No context needed."
                    " This is the minimum viable jacking event - alert immediately."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "GET /config or /config/yaml returns 200 from any IP not in the"
                    " management CIDR allowlist"
                ),
                severity="critical",
                notes=(
                    "Config access from outside management network = active exfil attempt."
                    " Block and alert. If management CIDR is undefined, any /config 200 is the trigger."
                ),
            ),
        ]

        stealth_considerations = [
            "Careful operators space requests 15-30 seconds apart with realistic jitter; "
            "per-request rate-limit triggers fire at 10 req/10s by default in LiteLLM. "
            "Residual signal: the time-gap pattern itself is anomalous (real clients batch requests).",

            "Rotating User-Agent strings evades simple UA-based detection. "
            "Residual signal: legitimate LLM clients use consistent SDK UA strings (openai-python/1.x);"
            " generic curl or Python-requests UAs on admin paths are already suspicious.",

            "Using /openapi.json to enumerate routes before probing avoids directory brute-force "
            "detection rules entirely. Residual signal: the schema fetch itself from a novel IP.",

            "Spacing inference requests to blend with normal traffic volume avoids rate anomaly alerts. "
            "Residual signal: the absence of auth header is non-negotiable and unblendable.",

            "Piggybacking on a compromised user's session (after obtaining a virtual key)"
            " bypasses IP-based detection entirely. Residual signal: request volume diverging"
            " from the compromised user's historical baseline.",
        ]

        return DetectionTelemetry(
            logging_recommendations=logging_recs,
            detection_ideas=detection_ideas,
            stealth_considerations=stealth_considerations,
        )

    def _h_open_gateways(self, options: Dict) -> Hardening:
        return Hardening(
            quick_wins=[
                "Set LITELLM_MASTER_KEY to a strong random value (32+ chars); never leave empty.",
                "Disable Swagger UI in production: LITELLM_ENABLE_DOCS=false (or set"
                " docs_url=None in the LiteLLM config).",
                "Bind admin endpoints to a separate internal-only listener or require a"
                " different LITELLM_MASTER_KEY for admin vs inference routes.",
                "Remove or gate /config, /config/yaml endpoints with network ACL or route-level auth.",
                "Set spend limits (max_budget) per virtual key and per user to cap blast radius"
                " of a compromised key.",
                "Rotate LITELLM_MASTER_KEY and all virtual keys immediately on any admin route 200 alert.",
            ],
            architectural_changes=[
                "Separate admin API from the inference API at the network layer: inference on"
                " port 4000 reachable from clients; admin on port 4001 bound to management VLAN only.",
                "Front the gateway with an auth proxy (e.g., Traefik + ForwardAuth, Kong key-auth plugin)"
                " so provider keys never touch the internet-facing surface.",
                "Store provider keys in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager);"
                " inject via environment at startup; never in config files or DB.",
                "Implement per-tenant virtual key scope restrictions: model allowlist, max token budget,"
                " source IP allowlist enforced at the gateway layer.",
                "Separate inference telemetry from admin telemetry into distinct log sinks with"
                " different retention policies and access controls.",
            ],
            detection_engineering_actions=[
                "Create an alert rule: response_code=200 AND path MATCHES /admin/* AND"
                " auth_header_present=false -> PagerDuty P1.",
                "Build a baseline per source_ip for inference token volume; alert on 2-sigma deviation.",
                "Implement honeypot virtual key: an unused key logged but never used; any inference"
                " request using it is a confirmed compromise indicator.",
                "Add a canary route (/admin/key/list/canary) that returns 200 with synthetic data"
                " and fires an alert on any 200 response - detects auth bypass via canary response.",
                "Log all requests to /openapi.json, /docs with source IP geo; alert on"
                " novel countries or Tor exit nodes.",
            ],
            template_guidance=[
                "LiteLLM: litellm_settings.master_key must be set; disable_spend_logs=false"
                " to preserve forensics; general_settings.alerting=['slack'] to get OOB notification.",
                "One-API: --channel-authed flag mandatory; root token in DOCKER_SECRET, never"
                " docker-compose.yml ENV block; --quota-enabled to cap spend.",
                "Kong: Use key-auth plugin on all routes; bind admin API (port 8001) to 127.0.0.1"
                " via admin_listen=127.0.0.1:8001; enable rate-limiting plugin.",
                "PortKey.ai: Enforce workspace-level API key requirements; disable public config"
                " endpoints; use Vault integration for key storage.",
            ],
        )

    # ==================================================================
    # SCENARIO: flowise_to_weaviate_pii_dump
    # ==================================================================

    def _tp_flowise_weaviate(self, options: Dict) -> TargetProfile:
        # TODO: replace stub counts with _query_host_summary(
        #     platforms=["Flowise", "Weaviate", "Elasticsearch"],
        #     min_severity=options.get("min_severity"),
        #     sectors=options.get("sector"),
        # )
        host_summary = {
            "total_hosts": 184,
            "severity_counts": {
                "info": 4, "low": 18, "medium": 52, "high": 74, "critical": 36,
            },
            "sector_counts": {
                "commercial": 98, "research": 44, "university": 22,
                "healthcare": 14, "government": 6,
            },
            "auth_posture_counts": {"open": 131, "weak": 31, "auth": 16, "unknown": 6},
        }
        return TargetProfile(
            focus_type="attack_path",
            focus_value="flowise_to_weaviate_pii_dump",
            host_summary=host_summary,
            typical_platforms=["Flowise", "Weaviate", "Elasticsearch", "Qdrant"],
            notable_patterns=[
                "Flowise instances expose chatflow definitions at /api/v1/chatflows without auth;"
                " these configs embed Weaviate hostnames, collection names, and API keys.",
                "Weaviate HTTP API (port 8080) co-deployed with Flowise on the same host or"
                " adjacent host with no network segmentation; direct object reads require no auth.",
                "Collection names in Weaviate frequently mirror document categories:"
                " 'Contracts', 'HR_Documents', 'CustomerRecords' - enabling targeted PII extraction.",
                "Document ingestion pipelines load S3 or Google Drive content into the vector"
                " store without PII scanning; embedding stores become unintentional PII repositories.",
                "Flowise admin endpoints (/api/v1/apikey) accessible without auth, yielding"
                " API keys used to connect to downstream LLM providers and data sources.",
            ],
            representative_notes=(
                "Typical target: Flowise on port 3000, Weaviate on 8080, commercial or university operator. "
                "GET /api/v1/chatflows returns all agent workflows including Weaviate connection configs. "
                "GET /v1/schema on Weaviate returns collection definitions without auth. "
                "GET /v1/objects?class=CustomerRecords returns object payloads including source document text. "
                "The chain: Flowise config -> Weaviate hostname/key -> schema enum -> targeted class dump."
            ),
        )

    def _recon_flowise_weaviate(self, options: Dict) -> ReconMapping:
        surface_elements = [
            SurfaceElement("http_path", "/api/v1/chatflows",
                           "Flowise: all chatflow definitions; contains Weaviate/ES connection configs"),
            SurfaceElement("http_path", "/api/v1/nodes",
                           "Flowise: node type inventory; reveals available integration types"),
            SurfaceElement("http_path", "/api/v1/apikey",
                           "Flowise: API key list; used to authenticate downstream LLM and data services"),
            SurfaceElement("http_path", "/v1/schema",
                           "Weaviate: collection schema; reveals class names and property definitions"),
            SurfaceElement("http_path", "/v1/objects",
                           "Weaviate: object retrieval; ?class=X returns all objects in a collection"),
            SurfaceElement("http_path", "/v1/graphql",
                           "Weaviate: GraphQL API; Get{} queries fetch objects with full payload"),
            SurfaceElement("http_path", "/v1/meta",
                           "Weaviate: version and module info; confirms auth disabled if 200 with no creds"),
            SurfaceElement("port", "3000",
                           "Flowise default port"),
            SurfaceElement("port", "8080",
                           "Weaviate default HTTP port"),
            SurfaceElement("port", "50051",
                           "Weaviate gRPC port; less commonly exposed; same auth model as HTTP"),
            SurfaceElement("banner_pattern", '"class":"',
                           "Weaviate /v1/schema body; confirms Weaviate and lists collection names"),
            SurfaceElement("banner_pattern", '"chatflows":',
                           "Flowise /api/v1/chatflows response body indicator"),
        ]

        probe_patterns = [
            HTTPProbePattern(
                id="FW-P-001",
                description="Flowise liveness and platform confirm",
                methods=["GET"],
                paths=["/", "/api/v1/chatflows", "/api/v1/nodes"],
                headers={},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Confirm Flowise version from response headers or body",
                    "Determine if /api/v1/chatflows requires authentication",
                    "Enumerate chatflow count and names without fetching full config",
                ],
                notes=(
                    "Flowise pre-1.4 has no auth at all. Post-1.4 auth is optional and"
                    " disabled by default. A 200 on /api/v1/chatflows = open."
                ),
            ),
            HTTPProbePattern(
                id="FW-P-002",
                description="Chatflow config extraction: Weaviate and data source discovery",
                methods=["GET"],
                paths=["/api/v1/chatflows", "/api/v1/chatflows/{id}"],
                headers={},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Extract Weaviate hostnames, ports, and API keys from chatflow node configs",
                    "Identify S3 bucket names, Google Drive credentials, or DB connection strings",
                    "Map downstream LLM provider keys embedded in chatflow node properties",
                ],
                notes=(
                    "Parse flowData JSON field in each chatflow. Weaviate nodes contain"
                    " 'weaviateApiKey' and 'weaviateURL' in their data property."
                ),
            ),
            HTTPProbePattern(
                id="FW-P-003",
                description="Flowise API key enumeration",
                methods=["GET"],
                paths=["/api/v1/apikey", "/api/v1/credentials", "/api/v1/variables"],
                headers={},
                body_shape=None,
                aggressiveness="medium",
                goals=[
                    "List all API credentials stored in Flowise",
                    "Extract key values for downstream LLM providers, vector DBs, and data sources",
                    "Identify which chatflows use which credentials (blast radius mapping)",
                ],
                notes=(
                    "/api/v1/credentials returns credential objects; some versions include"
                    " the plaintext key value. /api/v1/apikey returns Flowise's own API keys."
                ),
            ),
            HTTPProbePattern(
                id="WV-P-001",
                description="Weaviate schema enumeration",
                methods=["GET"],
                paths=["/v1/meta", "/v1/schema", "/v1/schema/{className}"],
                headers={},
                body_shape=None,
                aggressiveness="low_noise",
                goals=[
                    "Confirm Weaviate version and authentication mode",
                    "List all collection (class) names and their property definitions",
                    "Identify collections containing text properties that may hold PII",
                ],
                notes=(
                    "/v1/meta with 200 + no auth = confirmed open Weaviate."
                    " /v1/schema returns all class definitions. Class names often"
                    " directly reflect document categories."
                ),
            ),
            HTTPProbePattern(
                id="WV-P-002",
                description="Weaviate object sampling: targeted PII collection reads",
                methods=["GET"],
                paths=["/v1/objects", "/v1/objects/{uuid}"],
                headers={},
                body_shape=None,
                aggressiveness="medium",
                goals=[
                    "Read object payloads from high-value collections (Contracts, HR, Customer*)",
                    "Confirm presence of PII in vector store object text properties",
                    "Estimate collection size (totalResults in response) to scope the finding",
                ],
                notes=(
                    "GET /v1/objects?class=<ClassName>&limit=1 confirms PII presence with"
                    " minimal reads. Stop after confirming one PII record. Do not bulk-dump."
                    " Record class name and object count as the evidence artifact."
                ),
            ),
            HTTPProbePattern(
                id="WV-P-003",
                description="Weaviate GraphQL targeted query",
                methods=["POST"],
                paths=["/v1/graphql"],
                headers={"Content-Type": "application/json"},
                body_shape=(
                    "POST body: {query: '{ Get { <ClassName> { _additional { id } <field1> <field2> } } }'}"
                    " where ClassName and fields come from /v1/schema discovery."
                ),
                aggressiveness="medium",
                goals=[
                    "Confirm GraphQL endpoint is auth-free",
                    "Retrieve specific fields from PII-bearing collections",
                    "Test whether nearText vector search exposes cross-collection data",
                ],
                notes=(
                    "GraphQL Get{} queries are more flexible than /v1/objects REST."
                    " nearText allows semantic search - useful for confirming PII type"
                    " (e.g., query for 'social security number' to confirm SSN presence)."
                ),
            ),
        ]

        recon_phases = [
            ReconPhase(
                id="FW-PHASE-1",
                name="Flowise enumeration",
                description=(
                    "Confirm Flowise is open, enumerate chatflow count and names,"
                    " extract Weaviate connection details from chatflow configs."
                ),
                probe_ids=["FW-P-001", "FW-P-002"],
            ),
            ReconPhase(
                id="FW-PHASE-2",
                name="Weaviate schema mapping",
                description=(
                    "Using Weaviate coordinates from Phase 1, confirm Weaviate is open,"
                    " enumerate collection names, identify PII-bearing classes."
                ),
                probe_ids=["WV-P-001"],
            ),
            ReconPhase(
                id="FW-PHASE-3",
                name="Targeted PII confirmation",
                description=(
                    "Minimal-footprint read from identified PII collections to confirm"
                    " data class and severity. One object per class is sufficient."
                ),
                probe_ids=["WV-P-002"],
            ),
            ReconPhase(
                id="FW-PHASE-4",
                name="Credential extraction and full chain confirmation",
                description=(
                    "Extract stored credentials from Flowise (/api/v1/credentials)."
                    " Confirm full chain: Flowise open -> Weaviate keys extracted ->"
                    " Weaviate open -> PII confirmed."
                ),
                probe_ids=["FW-P-003", "WV-P-003"],
            ),
        ]

        return ReconMapping(
            surface_elements=surface_elements,
            http_probe_patterns=probe_patterns,
            recon_phases=recon_phases,
        )

    def _tm_flowise_weaviate(self, options: Dict) -> ThreatModel:
        assets = [
            Asset(
                name="rag_corpus",
                description=(
                    "Vector store contents: source document text, embedded chunks,"
                    " metadata including source path, author, and timestamp."
                    " May contain PII, IP, or confidential business documents."
                ),
                criticality="mission_critical",
            ),
            Asset(
                name="pii_documents",
                description=(
                    "Source documents ingested into the RAG pipeline: contracts, HR records,"
                    " customer lists, medical records, financial statements."
                    " PII class drives regulatory and legal exposure."
                ),
                criticality="mission_critical",
            ),
            Asset(
                name="agent_workflows",
                description=(
                    "Flowise chatflow definitions encoding agent logic, tool use patterns,"
                    " prompt engineering, and system prompts. IP and business logic."
                ),
                criticality="high",
            ),
            Asset(
                name="data_source_credentials",
                description=(
                    "Credentials stored in Flowise for S3, Google Drive, databases, LLM providers."
                    " Extraction enables lateral movement to upstream data sources."
                ),
                criticality="mission_critical",
            ),
            Asset(
                name="vector_embeddings",
                description=(
                    "Embedding vectors for all indexed documents. May enable reconstruction"
                    " of source text via inversion attacks (embedding model known)."
                ),
                criticality="medium",
            ),
        ]

        hypotheses = [
            ThreatHypothesis(
                id="FW-H-001",
                description=(
                    "Flowise /api/v1/chatflows returns all workflow configs including"
                    " Weaviate connection strings, API keys, and LLM provider credentials"
                    " without any authentication."
                ),
                related_categories=["agent_surfaces", "leaky_data_stores", "key_abuse"],
                related_attack_paths=["flowise_to_weaviate_pii_dump"],
                impact_if_confirmed="critical",
                confidence="high",
                notes=(
                    "Flowise stores credentials embedded in flowData JSON. Auth is disabled"
                    " by default in most versions. Survey confirms >70% of Flowise instances"
                    " in scope have open /api/v1/chatflows."
                ),
            ),
            ThreatHypothesis(
                id="FW-H-002",
                description=(
                    "Weaviate HTTP API returns all collection schemas and object payloads"
                    " without authentication; PII from ingested documents is directly readable."
                ),
                related_categories=["leaky_data_stores", "agent_surfaces"],
                related_attack_paths=["flowise_to_weaviate_pii_dump"],
                impact_if_confirmed="critical",
                confidence="high",
                notes=(
                    "Weaviate ships with authentication_anonymous_access_enabled=true by default."
                    " Authentication requires explicit AUTHENTICATION_OIDC_ENABLED or"
                    " AUTHENTICATION_APIKEY_ENABLED env vars. Most deployments skip this."
                ),
            ),
            ThreatHypothesis(
                id="FW-H-003",
                description=(
                    "Source document text stored verbatim in Weaviate object properties"
                    " (typically a 'text' or 'content' field) enabling bulk export of"
                    " the full RAG document corpus without requiring vector inversion."
                ),
                related_categories=["leaky_data_stores"],
                related_attack_paths=["flowise_to_weaviate_pii_dump"],
                impact_if_confirmed="critical",
                confidence="high",
                notes=(
                    "LangChain/Flowise vectorization pipelines store both the embedding"
                    " and the source text chunk in the same object. /v1/objects returns both."
                ),
            ),
            ThreatHypothesis(
                id="FW-H-004",
                description=(
                    "Flowise /api/v1/credentials endpoint returns stored credential objects"
                    " including plaintext key values for all configured integrations."
                ),
                related_categories=["agent_surfaces", "key_abuse"],
                related_attack_paths=["flowise_to_weaviate_pii_dump", "open_gateway_llmjacking"],
                impact_if_confirmed="critical",
                confidence="medium",
                notes=(
                    "Flowise credential storage is version-dependent. Pre-1.4 stores plaintext."
                    " Later versions may encrypt at rest but expose via API without auth."
                    " Confirmation requires probing the specific version."
                ),
            ),
        ]

        return ThreatModel(assets=assets, hypotheses=hypotheses)

    def _tc_flowise_weaviate(self, options: Dict) -> List[TestCase]:
        return [
            TestCase(
                id="FW-TC-001",
                objective="Enumerate open Flowise chatflows and extract downstream service connections.",
                preconditions=[
                    "Flowise port 3000 confirmed open via banner/liveness check.",
                    "Authorization scope confirmed for this target.",
                ],
                steps_summary=[
                    "GET /api/v1/chatflows with no auth header. Confirm 200 and JSON response.",
                    "Parse response array: extract id, name, flowData fields per chatflow.",
                    "For each chatflow, parse flowData.nodes array. Filter nodes where type"
                    " contains 'Weaviate', 'Pinecone', 'Qdrant', 'Elasticsearch', 'Chroma'.",
                    "From matching nodes, extract data.inputs: weaviateURL, weaviateApiKey,"
                    " esURL, esApiKey, pineconeApiKey etc.",
                    "Also extract LLM provider nodes: data.inputs.openAIApiKey,"
                    " anthropicApiKey, azureOpenAIApiKey.",
                    "Construct a connection inventory: service -> URL -> key prefix for each finding.",
                ],
                expected_weak_signals=[
                    "200 OK on GET /api/v1/chatflows with no auth header.",
                    "JSON array containing flowData.nodes with VectorStore or LLM node types.",
                    "weaviateURL or esURL fields containing internal or public hostnames.",
                    "weaviateApiKey or openAIApiKey fields with key values (even empty = no auth needed downstream).",
                ],
                severity_if_confirmed="critical",
                noise_level="low_noise",
                detection_focus=["anomalous_paths", "chatflow_config_access"],
                related_assets=["agent_workflows", "data_source_credentials"],
                notes=(
                    "The chatflow config is the map to all downstream services. This single request"
                    " may yield Weaviate coords, LLM keys, and S3/Drive credentials simultaneously."
                ),
            ),
            TestCase(
                id="FW-TC-002",
                objective="Confirm Weaviate is open and enumerate collection schema.",
                preconditions=[
                    "Weaviate hostname:port obtained from FW-TC-001 chatflow config or"
                    " direct discovery on port 8080 of same/adjacent host.",
                ],
                steps_summary=[
                    "GET /v1/meta on the Weaviate host with no auth. Confirm 200 and version field.",
                    "GET /v1/schema with no auth. Parse classes array: extract class.class"
                    " (collection name) and class.properties fields.",
                    "For each class, note property.name and property.dataType. Look for:"
                    " 'text', 'content', 'source', 'pageContent', 'email', 'name', 'ssn' patterns.",
                    "GET /v1/objects?limit=1 per class with highest PII-indicator property names.",
                    "Confirm totalResults count from response to scope the collection size.",
                ],
                expected_weak_signals=[
                    "200 OK on GET /v1/meta without Authorization header.",
                    "200 OK on GET /v1/schema returning a classes array with one or more collections.",
                    "Class names reflecting document categories: Contracts, HR_Policy, CustomerData, MedicalRecords.",
                    "Property definitions containing 'text', 'pageContent', 'source' fields (vector store chunk pattern).",
                ],
                severity_if_confirmed="critical",
                noise_level="low_noise",
                detection_focus=["schema_discovery", "vector_store_enumeration"],
                related_assets=["rag_corpus", "pii_documents"],
                notes=(
                    "Collection names are the fast-path PII classifier. A class named 'PatientRecords'"
                    " in a healthcare operator is a HIPAA finding before any object read."
                ),
            ),
            TestCase(
                id="FW-TC-003",
                objective="Confirm PII presence via targeted single-object read from high-value collections.",
                preconditions=[
                    "FW-TC-002 complete: collection names and property schemas known.",
                    "At least one collection with PII-indicator name or properties identified.",
                ],
                steps_summary=[
                    "GET /v1/objects?class=<HighValueClassName>&limit=1 with no auth.",
                    "Parse response: extract objects[0].properties.<text_field> value.",
                    "Classify PII type in the text field: name, email, SSN, DoB, account number,"
                    " medical diagnosis, contract terms.",
                    "Note objects[0].id (UUID) as the proof artifact.",
                    "Record totalResults field as the collection object count (scope indicator).",
                    "Stop after confirming one PII record. Do not iterate over full collection.",
                ],
                expected_weak_signals=[
                    "200 OK on /v1/objects with objects array containing one or more entries.",
                    "properties.<text_field> containing identifiable personal information.",
                    "totalResults > 0 confirming the collection is populated.",
                    "source or _additional.id metadata enabling document attribution.",
                ],
                severity_if_confirmed="critical",
                noise_level="low_noise",
                detection_focus=["vector_store_object_read", "pii_exposure"],
                related_assets=["pii_documents", "rag_corpus"],
                notes=(
                    "Minimum-viable-proof read. One object from one class is sufficient to"
                    " establish severity = CRITICAL (PII confirmed unauth). The totalResults"
                    " count is the scope multiplier for the risk narrative."
                ),
            ),
            TestCase(
                id="FW-TC-004",
                objective="Extract stored credentials from Flowise credential store.",
                preconditions=[
                    "FW-TC-001 confirmed Flowise open. Credential types identified from chatflow node configs.",
                ],
                steps_summary=[
                    "GET /api/v1/credentials with no auth. Observe response structure.",
                    "Parse response: extract credentialName, plainDataObj fields per credential.",
                    "If plainDataObj contains key values: note key type and prefix only for report.",
                    "GET /api/v1/credentials/{id} for individual credential objects (IDs from list endpoint).",
                    "Identify which chatflows reference each credential (from FW-TC-001 flowData).",
                ],
                expected_weak_signals=[
                    "200 OK on /api/v1/credentials with credential array.",
                    "plainDataObj fields containing OpenAI, Anthropic, or other provider keys.",
                    "Credential objects with credentialName matching patterns from chatflow config.",
                ],
                severity_if_confirmed="critical",
                noise_level="low_noise",
                detection_focus=["credential_access", "anomalous_paths"],
                related_assets=["data_source_credentials"],
                notes=(
                    "Some Flowise versions return the credential value encrypted; others plaintext."
                    " The encrypted form is still a finding (key storage in app layer, not secrets manager)."
                ),
            ),
        ]

    def _ac_flowise_weaviate(self, options: Dict) -> List[AttackChain]:
        return [
            AttackChain(
                id="FW-AC-001",
                name="Flowise to Weaviate PII Corpus Dump",
                steps=["FW-TC-001", "FW-TC-002", "FW-TC-003"],
                summary=(
                    "Enumerate open Flowise to obtain Weaviate connection details, confirm"
                    " Weaviate is open, map collection schema to identify PII-bearing classes,"
                    " and confirm PII with a single targeted object read. Full chain requires"
                    " zero credentials and leaves a minimal read-only footprint."
                ),
                overall_noise_profile="low_noise",
                defender_learning_goals=[
                    "Detect /api/v1/chatflows access from IPs without prior authenticated Flowise sessions.",
                    "Correlate Flowise chatflow access event with subsequent Weaviate /v1/schema"
                    " request from the same source IP - the pivot moment in this chain.",
                    "Alert on /v1/objects requests from source IPs not in the Flowise container CIDR.",
                ],
                related_attack_paths=["flowise_to_weaviate_pii_dump"],
            ),
            AttackChain(
                id="FW-AC-002",
                name="Credential Harvest and LLM Provider Pivot",
                steps=["FW-TC-001", "FW-TC-004", "TC-001"],
                summary=(
                    "Enumerate Flowise chatflows to identify LLM provider credentials,"
                    " extract from /api/v1/credentials, then pivot to the LLM gateway or"
                    " provider directly using the extracted keys."
                ),
                overall_noise_profile="low_noise",
                defender_learning_goals=[
                    "Detect /api/v1/credentials access immediately - no legitimate user"
                    " needs to browse the credential list outside of admin setup.",
                    "Alert on inference requests to LLM provider APIs from source IPs"
                    " not matching Flowise's egress CIDR (indicates key extraction + use).",
                ],
                related_attack_paths=["flowise_to_weaviate_pii_dump", "open_gateway_llmjacking"],
            ),
        ]

    def _dt_flowise_weaviate(self, options: Dict) -> DetectionTelemetry:
        logging_recs = [
            LoggingRecommendation(
                event="flowise_chatflow_list_access",
                fields=["timestamp", "source_ip", "method", "path", "response_code",
                        "auth_header_present", "user_agent", "response_body_size"],
                notes=(
                    "Log all GET /api/v1/chatflows requests. auth_header_present=false + 200 = critical."
                    " body_size delta: a large response body indicates full chatflow configs returned."
                ),
            ),
            LoggingRecommendation(
                event="flowise_credential_access",
                fields=["timestamp", "source_ip", "method", "path", "credential_id",
                        "response_code", "auth_header_present"],
                notes=(
                    "/api/v1/credentials access is an admin-only operation. Any 200 from outside"
                    " the management network = alert. Include credential_id from path parameter."
                ),
            ),
            LoggingRecommendation(
                event="weaviate_schema_read",
                fields=["timestamp", "source_ip", "path", "response_code",
                        "class_count", "user_agent"],
                notes=(
                    "Weaviate default logging is minimal. Enable QUERY_DEFAULTS_LIMIT logging."
                    " class_count derived from parsing /v1/schema response before forwarding."
                ),
            ),
            LoggingRecommendation(
                event="weaviate_object_read",
                fields=["timestamp", "source_ip", "class_name", "object_count_returned",
                        "limit_param", "offset_param", "response_code"],
                notes=(
                    "Track class_name from query parameter, object_count from totalResults."
                    " A single IP reading 1 object from 3+ classes in sequence = enumeration."
                ),
            ),
        ]

        detection_ideas = [
            DetectionIdea(
                pattern=(
                    "Source IP accesses /api/v1/chatflows (Flowise) followed within 5 minutes by"
                    " /v1/schema request to Weaviate host referenced in chatflow config"
                ),
                severity="critical",
                notes=(
                    "Cross-service correlation: Flowise config pivot to Weaviate. The 5-minute"
                    " window and cross-host correlation is the chain signature."
                    " Requires unified logging across Flowise and Weaviate into same SIEM."
                ),
            ),
            DetectionIdea(
                pattern="200 OK on /api/v1/chatflows where auth_header_present=false",
                severity="critical",
                notes=(
                    "Single-event alert. Chatflow config exposure is a confirmed finding."
                    " The downstream Weaviate pivot is the escalation, not the triggering event."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "Weaviate /v1/objects requests to 3+ distinct class names from the same"
                    " source IP within a 10-minute window"
                ),
                severity="high",
                notes=(
                    "Schema-informed collection enumeration. A legitimate RAG query hits one or"
                    " two classes; walking multiple classes systematically = bulk enumeration."
                ),
            ),
            DetectionIdea(
                pattern=(
                    "GET /api/v1/credentials returns 200 from any IP not in Flowise management CIDR"
                ),
                severity="critical",
                notes=(
                    "Credential list access is admin-only. Single-event alert; no threshold."
                    " If management CIDR is undefined, any /api/v1/credentials 200 triggers."
                ),
            ),
        ]

        stealth_considerations = [
            "The Flowise chatflow list read is a single GET request indistinguishable from"
            " a chatbot user navigating the UI - except that it comes from a non-browser UA."
            " Residual signal: user_agent field (curl, Python, Go HTTP client).",

            "Weaviate reads against specific class names look identical to the Flowise container's"
            " own RAG queries. Residual signal: source IP will differ from the Flowise egress IP.",

            "A careful attacker reads exactly one object per class to avoid volume-based detection."
            " Residual signal: even one-object reads from multiple classes within a session is anomalous.",

            "If the attacker uses the Weaviate key extracted from Flowise, their requests are"
            " authenticated - evading unauthenticated-access detection rules entirely."
            " Residual signal: authenticated access from a source IP outside Flowise container CIDR.",
        ]

        return DetectionTelemetry(
            logging_recommendations=logging_recs,
            detection_ideas=detection_ideas,
            stealth_considerations=stealth_considerations,
        )

    def _h_flowise_weaviate(self, options: Dict) -> Hardening:
        return Hardening(
            quick_wins=[
                "Enable Flowise authentication: set FLOWISE_USERNAME + FLOWISE_PASSWORD env vars;"
                " all API routes require auth when these are set.",
                "Enable Weaviate API key authentication:"
                " AUTHENTICATION_APIKEY_ENABLED=true, AUTHENTICATION_APIKEY_ALLOWED_KEYS=<key>.",
                "Bind Weaviate to localhost or internal VLAN only; it has no reason to be"
                " internet-accessible directly.",
                "Store LLM provider keys in Flowise via a secrets manager integration, not"
                " plaintext in the credential store.",
                "Disable anonymous access explicitly:"
                " AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false in Weaviate.",
            ],
            architectural_changes=[
                "Place Weaviate behind Flowise in the network topology: Weaviate should only"
                " be reachable from Flowise's egress IP, not from the public internet.",
                "Implement PII scanning on document ingestion pipeline: scan before embedding,"
                " redact or reject documents containing PII fields not intended for RAG.",
                "Use separate Weaviate API keys per chatflow/tenant; rotate on chatflow deletion.",
                "Implement a data classification layer on the vector store: tag objects with"
                " their PII class at ingest time; enforce read policy by classification.",
                "Run Flowise and Weaviate in separate network namespaces with explicit egress"
                " rules: Flowise -> Weaviate only, Weaviate -> nothing outbound.",
            ],
            detection_engineering_actions=[
                "Create SIEM correlation rule: Flowise chatflow access + Weaviate schema access"
                " from same source IP within 5 minutes = alert.",
                "Implement Weaviate audit logging module (if using enterprise version) or a"
                " reverse-proxy layer in front of Weaviate to log all requests.",
                "Build baseline: Flowise container egress IPs are the only expected sources"
                " of Weaviate requests. Alert on any other source IP.",
                "Deploy a honeypot collection in Weaviate (class: 'SensitiveDocuments_DO_NOT_READ')"
                " with canary objects; any read from this class fires an immediate alert.",
            ],
            template_guidance=[
                "Flowise docker-compose: set FLOWISE_USERNAME, FLOWISE_PASSWORD, FLOWISE_SECRETKEY_OVERWRITE"
                " in a .env file (never in docker-compose.yml directly); use Docker secrets for prod.",
                "Weaviate docker-compose: add AUTHENTICATION_APIKEY_ENABLED=true and"
                " AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false to the environment block.",
                "Ingestion pipeline: add a PII detection step (presidio, Comprehend Medical,"
                " Deduce) before calling vectorstore.add_documents().",
                "Network: use Docker network isolation - define an internal 'rag-internal' network"
                " for Flowise<->Weaviate traffic; only Flowise's HTTP port is on the external network.",
            ],
        )

    # ==================================================================
    # GENERIC FALLBACK
    # ==================================================================

    def _tp_generic(self, focus_type: str, focus_value: str, options: Dict) -> TargetProfile:
        # TODO: wire to _query_host_summary() with platform/category inference
        return TargetProfile(
            focus_type=focus_type,  # type: ignore[arg-type]
            focus_value=focus_value,
            host_summary=dict(_STUB_HOST_SUMMARY_EMPTY),
            typical_platforms=ExposureCategory.PLATFORMS.get(focus_value, []),
            notable_patterns=["TODO: populate from survey data for this focus."],
            representative_notes=f"TODO: build representative profile for {focus_type}={focus_value}.",
        )

    def _recon_generic(self, focus_type: str, focus_value: str, options: Dict) -> ReconMapping:
        return ReconMapping(
            surface_elements=[
                SurfaceElement("http_path", "/health", "TODO: add platform-specific paths"),
            ],
            http_probe_patterns=[
                HTTPProbePattern(
                    id="P-GEN-001",
                    description="Generic liveness probe",
                    methods=["GET"],
                    paths=["/health", "/status"],
                    headers={},
                    body_shape=None,
                    aggressiveness="low_noise",
                    goals=["Confirm service liveness"],
                    notes=f"TODO: add {focus_value}-specific probe patterns.",
                )
            ],
            recon_phases=[
                ReconPhase(
                    id="PHASE-GEN-1",
                    name="Baseline liveness",
                    description="Confirm target is live before implementing specialized probes.",
                    probe_ids=["P-GEN-001"],
                )
            ],
        )

    def _tm_generic(self, focus_type: str, focus_value: str, options: Dict) -> ThreatModel:
        return ThreatModel(
            assets=[
                Asset(
                    name="generic_service_data",
                    description=f"TODO: identify assets for {focus_value}.",
                    criticality="medium",
                )
            ],
            hypotheses=[
                ThreatHypothesis(
                    id="H-GEN-001",
                    description=f"TODO: define threat hypotheses for {focus_value}.",
                    related_categories=[focus_value],
                    related_attack_paths=[],
                    impact_if_confirmed="medium",
                    confidence="low",
                    notes="Generic stub - implement specialized builder for this focus.",
                )
            ],
        )

    def _tc_generic(self, focus_type: str, focus_value: str, options: Dict) -> List[TestCase]:
        return [
            TestCase(
                id="TC-GEN-001",
                objective=f"TODO: define test cases for {focus_value}.",
                preconditions=["Service confirmed live."],
                steps_summary=["TODO: implement test case steps."],
                expected_weak_signals=["TODO: define expected signals."],
                severity_if_confirmed="medium",
                noise_level="low_noise",
                detection_focus=["anomalous_paths"],
                related_assets=["generic_service_data"],
                notes="Generic stub - implement specialized builder for this focus.",
            )
        ]

    def _ac_generic(self, focus_type: str, focus_value: str, options: Dict) -> List[AttackChain]:
        return [
            AttackChain(
                id="AC-GEN-001",
                name=f"TODO: define attack chain for {focus_value}",
                steps=["TC-GEN-001"],
                summary="TODO: implement attack chain for this focus.",
                overall_noise_profile="low_noise",
                defender_learning_goals=["TODO: define defender learning goals."],
                related_attack_paths=[],
            )
        ]

    def _dt_generic(self, focus_type: str, focus_value: str, options: Dict) -> DetectionTelemetry:
        return DetectionTelemetry(
            logging_recommendations=[
                LoggingRecommendation(
                    event="generic_service_access",
                    fields=["timestamp", "source_ip", "path", "response_code"],
                    notes=f"TODO: define logging for {focus_value}.",
                )
            ],
            detection_ideas=[
                DetectionIdea(
                    pattern=f"TODO: define detection patterns for {focus_value}.",
                    severity="medium",
                    notes="Generic stub.",
                )
            ],
            stealth_considerations=["TODO: add stealth analysis for this focus."],
        )

    def _h_generic(self, focus_type: str, focus_value: str, options: Dict) -> Hardening:
        return Hardening(
            quick_wins=[f"TODO: define hardening for {focus_value}."],
            architectural_changes=["TODO: define architectural changes."],
            detection_engineering_actions=["TODO: define detection engineering actions."],
            template_guidance=["TODO: define template guidance."],
        )

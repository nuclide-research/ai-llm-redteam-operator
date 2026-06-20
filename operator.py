"""
AI_LLM_RedTeam_Operator — main class.

Wire to nuclide.db, coords.json, and details.json by passing real paths;
the stubs below mark exactly where SQL/JSON loading goes.

Tactical playbook is in playbook.py; models are in models.py.
Adding a new category/platform/attack-path only requires a playbook entry --
no changes here.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .models import (
    Asset, AttackChain, DetectionIdea, DetectionTelemetry,
    Hardening, HostSummary, HTTPProbePattern, LoggingRecommendation,
    ReconMapping, ScenarioPacket, SurfaceElement, TargetProfile,
    TestCase, ThreatHypothesis, ThreatModel,
)
from .playbook import get_playbook_entry, list_focus_values


# ---------------------------------------------------------------------------
# Operator
# ---------------------------------------------------------------------------

class AI_LLM_RedTeam_Operator:
    """
    Operator-grade scenario packet generator for AI/LLM infrastructure assessments.

    Usage:
        op = AI_LLM_RedTeam_Operator("nuclide.db", "coords.json", "details.json")
        packet = op.generate_scenario_packet("category", "open_gateways")
        print(op.render_markdown(packet))
        print(json.dumps(packet, indent=2))  # machine-consumable
    """

    def __init__(self, db_path: str, coords_path: str, details_path: str):
        self.db_path      = db_path
        self.coords_path  = coords_path
        self.details_path = details_path

        self._conn: Optional[sqlite3.Connection] = None
        self._details: Optional[List[Dict]]      = None
        self._coords:  Optional[List[Dict]]      = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_scenario_packet(
        self,
        focus_type: str,
        focus_value: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a full scenario packet for the given focus.

        Args:
            focus_type:  "category" | "platform" | "attack_path"
            focus_value: matching value from the appropriate enum
            options:     optional filters:
                           min_severity: str (default None)
                           sectors: list[str] (default all)
                           limit: int (max hosts returned in summary, default 500)

        Returns:
            JSON-serializable dict with all seven packet fields.
        """
        opts = options or {}
        pb   = get_playbook_entry(focus_type, focus_value)

        if not pb:
            known = list_focus_values(focus_type)
            raise ValueError(
                f"Unknown {focus_type} value '{focus_value}'. "
                f"Known values: {known}"
            )

        rows    = self._query_hosts(focus_type, focus_value, opts)
        details = self._query_details(focus_type, focus_value, opts)

        packet = ScenarioPacket(
            target_profile     = self._build_target_profile(focus_type, focus_value, pb, rows, details),
            recon_mapping      = self._build_recon_mapping(pb),
            threat_model       = self._build_threat_model(pb),
            test_cases         = self._build_test_cases(pb),
            attack_chains      = self._build_attack_chains(pb),
            detection_telemetry= self._build_detection_telemetry(pb),
            hardening          = self._build_hardening(pb),
        )
        return packet.to_dict()

    def render_markdown(self, packet: Dict[str, Any]) -> str:
        """Render a scenario packet dict as a human-readable Markdown report."""
        from .render import render_markdown
        return render_markdown(packet)

    # ------------------------------------------------------------------
    # Data access (stub with clear SQL comments for production wiring)
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _load_details(self) -> List[Dict]:
        if self._details is None:
            try:
                with open(self.details_path) as fh:
                    self._details = json.load(fh)
            except (FileNotFoundError, json.JSONDecodeError):
                self._details = []
        return self._details

    def _query_hosts(
        self, focus_type: str, focus_value: str, opts: Dict
    ) -> List[Dict]:
        """
        Return host rows from nuclide.db matching the focus.

        Production SQL patterns:

          -- category focus:
          SELECT ip, owner, country, sector, severity, survey_id
          FROM hosts
          WHERE category = :focus_value
            AND (:min_severity IS NULL OR severity_rank >= severity_rank(:min_severity))
            AND (:sectors IS NULL OR sector IN (:sectors))
          LIMIT :limit

          -- platform focus (join to a details/platform table or JSON):
          SELECT h.ip, h.owner, h.country, h.sector, h.severity
          FROM hosts h
          JOIN host_platform hp ON h.ip = hp.ip
          WHERE hp.platform = :focus_value
          LIMIT :limit

          -- attack_path focus (route to related category):
          -- same as category query; use pb["related_category"] to derive filter
        """
        try:
            conn   = self._get_conn()
            cursor = conn.cursor()

            limit = int(opts.get("limit", 500))

            if focus_type == "category":
                # Real query: WHERE category = focus_value
                cursor.execute(
                    "SELECT ip, owner, country, sector, severity, survey_id "
                    "FROM hosts LIMIT ?",
                    (limit,),
                )
            elif focus_type == "platform":
                # Real query: join host_platform or filter on platform field
                cursor.execute(
                    "SELECT ip, owner, country, sector, severity, survey_id "
                    "FROM hosts LIMIT ?",
                    (limit,),
                )
            else:
                # attack_path: derive related category and re-query
                cursor.execute(
                    "SELECT ip, owner, country, sector, severity, survey_id "
                    "FROM hosts LIMIT ?",
                    (limit,),
                )

            rows = [dict(r) for r in cursor.fetchall()]
        except (sqlite3.OperationalError, FileNotFoundError):
            # DB not wired yet; return stub rows so the packet still builds
            rows = self._stub_rows()

        # Apply optional severity filter in Python (cheap at this scale)
        min_sev = opts.get("min_severity")
        if min_sev:
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            rows = [r for r in rows if rank.get(r.get("severity", ""), 0) >= rank.get(min_sev, 0)]

        sectors = opts.get("sectors")
        if sectors:
            rows = [r for r in rows if r.get("sector") in sectors]

        return rows

    def _query_details(
        self, focus_type: str, focus_value: str, opts: Dict
    ) -> List[Dict]:
        """
        Return detail records from details.json for hosts in scope.

        Production approach:
          details = load_json(details_path)
          ips_in_scope = {r["ip"] for r in host_rows}
          return [d for d in details if d["ip"] in ips_in_scope
                  and d.get("platform") == focus_value]  # if platform focus
        """
        raw = self._load_details()
        if focus_type == "platform":
            return [d for d in raw if d.get("platform", "") == focus_value]
        return raw  # for category/attack_path all details contribute

    # ------------------------------------------------------------------
    # Stage builders
    # ------------------------------------------------------------------

    def _build_target_profile(
        self,
        focus_type: str,
        focus_value: str,
        pb: Dict,
        rows: List[Dict],
        details: List[Dict],
    ) -> TargetProfile:
        """
        Summarise host population for the chosen focus.

        Severity/sector counts come from nuclide.db rows.
        Auth posture counts come from details.json records.
        Typical platforms come from the playbook (or are inferred from details for
        attack_path / category focuses where platform is known).

        Extend: add geo distribution (coords.json), CVE density, survey_id grouping.
        """
        severity_counts:    Dict[str, int] = defaultdict(int)
        sector_counts:      Dict[str, int] = defaultdict(int)
        auth_posture_counts:Dict[str, int] = defaultdict(int)

        for r in rows:
            severity_counts[r.get("severity", "unknown")] += 1
            sector_counts[r.get("sector",   "unknown")] += 1

        for d in details:
            auth_posture_counts[d.get("auth_posture", "unknown")] += 1

        typical_platforms = pb.get("typical_platforms", [])

        # If details have platform data, surface the top-3 as a cross-check
        if details:
            from collections import Counter
            top = Counter(d.get("platform", "") for d in details if d.get("platform")).most_common(3)
            inferred = [p for p, _ in top if p]
            if inferred and not typical_platforms:
                typical_platforms = inferred

        # Build the representative note using playbook template or derive from data
        sector_top = sorted(sector_counts, key=sector_counts.get, reverse=True)[:2]
        platform_hint = typical_platforms[0] if typical_platforms else focus_value
        rep_notes = (
            f"Population of {len(rows)} hosts focused on {focus_value.replace('_', ' ')}. "
            f"Top sectors: {', '.join(sector_top) or 'unknown'}. "
            f"Most common platform class: {platform_hint}. "
            f"Auth posture breakdown reflects details.json subset."
        )

        return TargetProfile(
            focus_type=focus_type,
            focus_value=focus_value,
            host_summary=HostSummary(
                total_hosts=len(rows),
                severity_counts=dict(severity_counts),
                sector_counts=dict(sector_counts),
                auth_posture_counts=dict(auth_posture_counts),
            ),
            typical_platforms=typical_platforms,
            representative_notes=rep_notes,
        )

    def _build_recon_mapping(self, pb: Dict) -> ReconMapping:
        """
        Build surface element list, HTTP probe patterns, and mapping strategy.

        Source: playbook surface_elements, http_probe_patterns, mapping_strategy.

        Extension points:
          - Augment surface_elements with shadow ports discovered by the scanner
            step (nuclide.db host_ports table if present).
          - Add version-specific probes when aimap version data is available.
          - Incorporate dork strings from tome for passive pre-validation.

        Consistent with Hacking APIs (Ball): enumerate base paths via OpenAPI first,
        then probe for BOLA/BFLA/unauthenticated access on discovered resources.
        Web App Security (Hoffman): layer passive fingerprinting before any active probe.
        """
        surface_elements = [
            SurfaceElement(**e) for e in pb.get("surface_elements", [])
        ]
        http_probe_patterns = [
            HTTPProbePattern(**p) for p in pb.get("http_probe_patterns", [])
        ]
        mapping_strategy = pb.get("mapping_strategy", [])
        return ReconMapping(surface_elements, http_probe_patterns, mapping_strategy)

    def _build_threat_model(self, pb: Dict) -> ThreatModel:
        """
        Build asset list and threat hypotheses.

        Assets describe what is at risk if the attack surface is exploited.
        Hypotheses are falsifiable: a hypothesis is confirmed only when a
        specific test case returns a defined positive signal.

        This follows the OWASP API Security Top-10 framing:
          - API1: BOLA (multi-tenant routes, cross-user doc access)
          - API2: Broken Auth (open proxy, weak/no token)
          - API3: BOPLA (config endpoints returning privileged data)
          - API8: Security Misconfiguration (CORS, open admin, default creds)

        Extend: add hypothesis confidence scores, MITRE ATLAS mapping,
        and link hypotheses to specific CVEs when version data is available
        from aimap output.
        """
        assets     = [Asset(**a)            for a in pb.get("assets",     [])]
        hypotheses = [ThreatHypothesis(**h) for h in pb.get("hypotheses", [])]
        return ThreatModel(assets, hypotheses)

    def _build_test_cases(self, pb: Dict) -> List[TestCase]:
        """
        Build ordered test cases from playbook.

        Each test case is independent and verifiable. Steps are high-level
        descriptions, not tool commands, to remain tool-agnostic.

        Sequencing: test cases are ordered from lowest-risk probe (passive/metadata)
        to highest-impact confirmation (code execution, data retrieval).

        Consistent with Practical Web Penetration Testing (Khawaja): test in phases,
        confirm auth posture before touching data, document weak signals before
        asserting exploitability.

        Extend: add test case templates per aimap auth_status value (open/weak/auth)
        to auto-skip confirmed-auth hosts at the test runner layer.
        """
        return [TestCase(**tc) for tc in pb.get("test_cases", [])]

    def _build_attack_chains(self, pb: Dict) -> List[AttackChain]:
        """
        Link test cases into multi-step attack chains.

        A chain describes the narrative from initial access to impact.
        steps[] references TestCase IDs in execution order.

        Extend: add inter-chain dependencies (e.g., AC1 of open_gateways feeds
        into AC1 of key_abuse as a prerequisite) to support automated chain replay.
        """
        return [AttackChain(**ac) for ac in pb.get("attack_chains", [])]

    def _build_detection_telemetry(self, pb: Dict) -> DetectionTelemetry:
        """
        Build logging recommendations and detection patterns.

        Logging recs describe what fields to capture per event type.
        Detection ideas describe observable patterns and their severity.

        Blue-team framing: detection is designed from the offensive playbook.
        Every step in an attack chain should have a corresponding log event.
        If a step has no detection idea, add one.

        Consistent with Web App Security (Hoffman, 2e): correlate access patterns
        (not just individual requests) to surface automated probing from
        human-paced navigation.
        """
        log_recs = [
            LoggingRecommendation(**r) for r in pb.get("logging_recommendations", [])
        ]
        det_ideas = [
            DetectionIdea(**d) for d in pb.get("detection_ideas", [])
        ]
        return DetectionTelemetry(log_recs, det_ideas)

    def _build_hardening(self, pb: Dict) -> Hardening:
        """
        Build hardening recommendations at three horizons:
          - quick_wins:            config changes deployable in < 1 hour
          - architectural_changes: design-level fixes requiring planning
          - template_guidance:     bake-in recommendations for deployment baselines

        Ordered by impact/effort ratio. Quick wins should eliminate the
        most common exploitation path with minimal operational disruption.

        Consistent with Beginner's Guide to Web App Pentest (Abdollahi):
        remediation must be specific and actionable, not generic advice.
        Each recommendation maps to a specific test case or hypothesis.
        """
        return Hardening(
            quick_wins           = pb.get("quick_wins",            []),
            architectural_changes= pb.get("architectural_changes", []),
            template_guidance    = pb.get("template_guidance",     []),
        )

    # ------------------------------------------------------------------
    # Stub data (used when DB is not wired or empty)
    # ------------------------------------------------------------------

    @staticmethod
    def _stub_rows() -> List[Dict]:
        """Placeholder rows returned when nuclide.db is not yet connected."""
        return [
            {"ip": "10.0.0.1", "owner": "Commercial Inc",  "country": "US", "sector": "commercial",  "severity": "critical", "survey_id": "stub-1"},
            {"ip": "10.0.0.2", "owner": "University A",    "country": "DE", "sector": "university",  "severity": "high",     "survey_id": "stub-1"},
            {"ip": "10.0.0.3", "owner": "Research Lab",    "country": "US", "sector": "research",    "severity": "medium",   "survey_id": "stub-2"},
            {"ip": "10.0.0.4", "owner": "Healthcare Sys",  "country": "US", "sector": "healthcare",  "severity": "critical", "survey_id": "stub-2"},
            {"ip": "10.0.0.5", "owner": "Gov Agency",      "country": "US", "sector": "government",  "severity": "high",     "survey_id": "stub-3"},
        ]

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def list_known_values(self, focus_type: str) -> List[str]:
        """Return all known values for a given focus type."""
        return list_focus_values(focus_type)

    def close(self):
        """Close the SQLite connection if open."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

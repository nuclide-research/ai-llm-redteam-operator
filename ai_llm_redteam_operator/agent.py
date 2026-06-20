"""
Agentic execution layer for ai-llm-redteam-operator.

The planner (operator.py) writes a ScenarioPacket: the policy. This module
runs it. RedTeamAgent is a sense-plan-act loop that walks the packet's attack
chains against a single authorized target, sends the recon probes the packet
prescribes, evaluates the responses against each test case's weak signals, and
advances a chain only when the prior step confirms. It produces a RunReport:
an evidence ledger of what was sent, what came back, and which hypotheses the
evidence actually supports.

Design constraints (these are the safety contract, not decoration):

  * Authorization gate. The agent refuses to send a single byte without an
    explicit authorization reference (the engagement / scope identifier) and a
    target. No default target, no implicit scope.
  * Dry-run by default. The default mode plans requests and sends nothing.
    Live traffic requires opting in. Dry-run can never produce a "confirmed"
    finding, because nothing was exercised.
  * Single-host scope. Every request is the base target's scheme+host with a
    packet path appended, and redirects are captured rather than followed, so a
    probe can never walk the agent off the target host.
  * Aggressiveness cap. Read probes are ranked low_noise < medium < high. The
    cap defaults to medium (read-only GET/HEAD up to medium noise). Mutating
    methods are governed by a separate gate, allow_writes, which is off by
    default: a write never goes out on the noise cap alone.
  * Restraint. One proof artifact per step, then stop. Response bodies are
    sampled to a byte cap, never bulk-pulled. A global request budget bounds
    the whole run.

Standard library only. The optional LLM strategist also uses urllib, so even
the AI-assisted path pulls in no third-party package.
"""

from __future__ import annotations

import datetime
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AuthorizationError(Exception):
    """Raised when an agent run is attempted without an authorization reference."""


class ScopeError(Exception):
    """Raised when a target is malformed or a request would leave the target host."""


# ---------------------------------------------------------------------------
# Aggressiveness ordering
# ---------------------------------------------------------------------------

_AGG_RANK = {"low_noise": 0, "medium": 1, "high": 2}
_AGG_MAX = max(_AGG_RANK.values())


def _agg_rank(level: str) -> int:
    # Fail safe: an unrecognized probe label is treated as the highest noise
    # tier, so a typo or out-of-vocabulary aggressiveness is filtered out under
    # any cap below "high" rather than firing under the default.
    return _AGG_RANK.get(level, _AGG_MAX)


# Methods that can change target state. Off unless the cap is raised past read-only.
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------------------
# Run configuration
# ---------------------------------------------------------------------------

@dataclass
class RunConfig:
    """Everything that governs a single agent run.

    target and authorization are mandatory for any send. dry_run defaults True:
    the safe default is to plan, not fire.
    """
    target: str                              # base URL, e.g. https://10.0.0.5:8000
    authorization: str                       # engagement / scope reference, free text but required
    dry_run: bool = True
    max_aggressiveness: str = "medium"       # low_noise | medium | high (filters READ probes)
    allow_writes: bool = False               # independent gate: permit POST/PUT/PATCH/DELETE
    request_timeout: float = 8.0             # seconds per request
    delay_seconds: float = 0.5               # pause before each live request
    max_body_bytes: int = 4096               # response body sample cap
    max_requests: int = 60                   # global budget for the whole run
    user_agent: str = "ai-llm-redteam-operator/0.2 (authorized-assessment)"
    verify_tls: bool = False                 # self-signed targets are common; off by default
    # Optional LLM strategist (OpenAI-compatible chat endpoint, called via urllib).
    llm_endpoint: Optional[str] = None       # e.g. http://127.0.0.1:11434/v1/chat/completions
    llm_api_key: Optional[str] = None
    llm_model: str = "gpt-4o-mini"

    def public_view(self) -> Dict:
        """Config snapshot for the report, with the LLM key redacted."""
        d = asdict(self)
        if d.get("llm_api_key"):
            d["llm_api_key"] = "***redacted***"
        return d


# ---------------------------------------------------------------------------
# Ledger records
# ---------------------------------------------------------------------------

@dataclass
class Observation:
    seq: int
    probe_id: str
    method: str
    url: str
    path: str
    aggressiveness: str
    sent: bool                               # False = dry-run plan or skipped
    skipped_reason: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    status: Optional[int] = None
    reason: Optional[str] = None
    final_url: Optional[str] = None          # responding URL; must equal `url`
    elapsed_ms: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_sample: Optional[str] = None
    body_truncated: bool = False
    error: Optional[str] = None


@dataclass
class Finding:
    test_case_id: str
    objective: str
    confirmed: bool
    severity_if_confirmed: str
    matched_signals: List[Dict] = field(default_factory=list)  # {signal, seq, kind}
    evidence_seqs: List[int] = field(default_factory=list)
    note: str = ""


@dataclass
class ChainOutcome:
    chain_id: str
    name: str
    status: str                              # confirmed | stalled | planned | blocked
    reached_step: Optional[str]
    confirmed_steps: List[str] = field(default_factory=list)
    summary: str = ""
    defender_learning_goals: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class RunReport:
    tool_version: str
    mode: str                                # dry_run | live
    focus_type: str
    focus_value: str
    target: str
    authorization: str
    started_at: str
    finished_at: Optional[str] = None
    config: Dict = field(default_factory=dict)
    requests_sent: int = 0
    requests_planned: int = 0
    requests_skipped: int = 0
    observations: List[Observation] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    chain_outcomes: List[ChainOutcome] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Probe runner (the "act")
# ---------------------------------------------------------------------------

class _NoFollowRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect. urllib's default opener auto-follows 3xx to any
    host, which would walk the agent off the authorized target. We return the
    3xx as a terminal observation instead: the operator sees the Location and
    decides, the agent never makes a hidden off-host hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do not follow; urlopen returns the 3xx response as-is


class ProbeRunner:
    """Sends one HTTP request and returns the raw facts. stdlib urllib only.

    A 401/403/404 is a *response*, not an error: the differential is the signal.
    Redirects are captured, not followed. Only transport failures (refused,
    timeout, DNS) land in `error`.
    """

    def __init__(self, config: RunConfig, sleeper: Callable[[float], None] = time.sleep):
        self.config = config
        self._sleep = sleeper
        if config.verify_tls:
            self._ssl_ctx = ssl.create_default_context()
        else:
            # CERT_NONE is scoped to the one authorized target host (self-signed
            # in-scope hosts are common). It is never applied off-host because
            # redirects are not followed.
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            _NoFollowRedirect(),
            urllib.request.HTTPSHandler(context=self._ssl_ctx),
        )

    def send(self, method: str, url: str, headers: Dict[str, str],
             body: Optional[bytes], expected_netloc: Optional[str] = None) -> Dict:
        if self.config.delay_seconds > 0:
            self._sleep(self.config.delay_seconds)

        req = urllib.request.Request(url=url, method=method, data=body)
        for k, v in headers.items():
            req.add_header(k, v)

        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.config.request_timeout) as resp:
                return self._capture(resp, start, expected_netloc)
        except urllib.error.HTTPError as exc:
            # A real HTTP response carrying a non-2xx status. Capture it.
            return self._capture(exc, start, expected_netloc)
        except urllib.error.URLError as exc:
            return {"error": f"urlerror: {getattr(exc, 'reason', exc)}",
                    "elapsed_ms": int((time.monotonic() - start) * 1000)}
        except (ssl.SSLError, ConnectionError, OSError) as exc:
            return {"error": f"transport: {exc}",
                    "elapsed_ms": int((time.monotonic() - start) * 1000)}

    def _capture(self, resp, start: float, expected_netloc: Optional[str]) -> Dict:
        # Defense in depth: even with no-follow, assert the responding host is
        # the one we addressed. If anything left the host, discard the body and
        # record a scope error rather than ledger off-host data as in-scope.
        final_url = None
        try:
            final_url = resp.geturl()
        except Exception:
            final_url = None
        if final_url and expected_netloc:
            if urllib.parse.urlparse(final_url).netloc != expected_netloc:
                return {"error": "scope: response came from off-host url %s" % final_url,
                        "final_url": final_url,
                        "elapsed_ms": int((time.monotonic() - start) * 1000)}

        cap = self.config.max_body_bytes
        raw = resp.read(cap + 1)
        truncated = len(raw) > cap
        body_sample = raw[:cap].decode("utf-8", errors="replace")
        hdrs = {k: v for k, v in resp.headers.items()}
        status = getattr(resp, "status", None) or getattr(resp, "code", None)
        reason = getattr(resp, "reason", None)
        return {
            "status": status,
            "reason": reason,
            "final_url": final_url,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
            "response_headers": hdrs,
            "body_sample": body_sample,
            "body_truncated": truncated,
        }


# ---------------------------------------------------------------------------
# Signal evaluator (the "sense")
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(r"\b([1-5]\d\d)\b")
_PATH_RE = re.compile(r"(/[A-Za-z0-9_\-./{}]+)")
_HEADER_RE = re.compile(r"\b([A-Za-z]+(?:-[A-Za-z0-9]+){1,})\b")
_QUOTED_RE = re.compile(r"[\"'`]([^\"'`]{2,40})[\"'`]")
_AUTH_OPEN_RE = re.compile(
    r"\b(unauth|unauthenticated|without auth|no auth|no-auth|anonymous|open(?:\s|$)|no login|without login)\b",
    re.IGNORECASE,
)
# Concrete tokens worth grepping a body for if a signal names them.
_BODY_TOKENS = [
    "sk-", "sk-ant-", "aiza", "api_key", "apikey", "secret", "password",
    "openai_api_key", "anthropic", "bearer", "uid=", "root", "model",
    "models", "objects", "collections", "buckets", "experiments",
]


def _paths_in(text: str) -> List[str]:
    """Extract path tokens from signal prose, stripping trailing punctuation so
    '/v1/models.' does not become a distinct path from '/v1/models'."""
    out = []
    for p in _PATH_RE.findall(text):
        p = p.rstrip(".,;:)").lower()
        if p and p != "/":
            out.append(p)
    return out


def _path_scopes(obs_path: str, sig_paths: List[str]) -> bool:
    """Single-direction scope: an observation satisfies a signal's path when the
    signal path equals the observation path or is a parent segment of it. The
    reverse direction (a broad signal matching a narrow observation, or vice
    versa via plain substring) is deliberately excluded to stop /v1 matching
    /v1/spend/logs and friends."""
    if not sig_paths:
        return True
    op = obs_path.lower()
    for sp in sig_paths:
        if op == sp or op.startswith(sp.rstrip("/") + "/"):
            return True
    return False


def _is_2xx(status: Optional[int]) -> bool:
    return bool(status) and 200 <= status < 300


class SignalEvaluator:
    """Maps a test case's expected_weak_signals onto concrete observations.

    Conservative by construction: a match must point at a real, *sent*
    observation. Dry-run observations (sent=False) can never satisfy a signal,
    so a dry-run produces only unconfirmed findings. Each match record carries
    the backing observation's status and whether it returned a body, so
    confirmation can demand hard evidence (see _is_confirming).
    """

    def evaluate(self, test_case: Dict,
                 observations: List[Observation]) -> Tuple[List[Dict], List[int]]:
        signals = test_case.get("expected_weak_signals", []) or []
        sent = [o for o in observations if o.sent and o.error is None]
        by_seq = {o.seq: o for o in sent}
        matched: List[Dict] = []
        evidence: List[int] = []

        for sig in signals:
            hit = self._match_one(sig, sent)
            if hit is None:
                continue
            kind, seq = hit
            o = by_seq.get(seq)
            matched.append({
                "signal": sig, "seq": seq, "kind": kind,
                "status": o.status if o else None,
                "has_body": bool(o and o.body_sample),
            })
            if seq not in evidence:
                evidence.append(seq)  # one piece of evidence per signal (restraint)
        return matched, evidence

    def _match_one(self, sig: str, sent: List[Observation]) -> Optional[Tuple[str, int]]:
        sig_l = sig.lower()
        paths = _paths_in(sig)
        statuses = [int(s) for s in _STATUS_RE.findall(sig)]

        # 1. Status-code match. When the signal names several codes (e.g. a
        #    "403 then 200 differential"), prefer a 2xx observation over a
        #    4xx/5xx so signal prose order does not decide evidence strength.
        status_hits = []
        for code in statuses:
            for o in sent:
                if o.status == code and _path_scopes(o.path, paths):
                    status_hits.append((code, o))
        if status_hits:
            status_hits.sort(key=lambda ch: 0 if _is_2xx(ch[0]) else 1)
            code, o = status_hits[0]
            return ("status_%d" % code, o.seq)

        # 2. Header-presence match ("x-litellm-call-id header present").
        if "header" in sig_l:
            for cand in _HEADER_RE.findall(sig):
                if "-" not in cand:
                    continue
                cl = cand.lower()
                for o in sent:
                    if any(cl == h.lower() for h in o.response_headers):
                        return ("header_%s" % cl, o.seq)

        # 3. Body-token match: quoted tokens or known sensitive tokens in body.
        tokens = [t.lower() for t in _QUOTED_RE.findall(sig)]
        tokens += [t for t in _BODY_TOKENS if t in sig_l]
        for tok in tokens:
            for o in sent:
                if o.body_sample and tok in o.body_sample.lower():
                    return ("body:%s" % tok, o.seq)

        # 4. Auth-open: an unauth signal backed by any 2xx response (supporting
        #    evidence, never hard confirmation on its own).
        if _AUTH_OPEN_RE.search(sig):
            for o in sent:
                if _is_2xx(o.status) and _path_scopes(o.path, paths):
                    return ("auth_open_2xx", o.seq)
        return None


def _is_confirming(matched: List[Dict]) -> bool:
    """A finding is confirmed only by hard, sent evidence:
      * a 2xx status that actually returned a body (a bare 204/205 confirms
        nothing exfiltrable), or
      * a body token or header presence ON a 2xx observation (a token echoed in
        a 403 error body is not confirmation that access was granted).
    An auth_open hint alone is supporting, not confirming."""
    for m in matched:
        kind = m["kind"]
        status = m.get("status")
        if kind.startswith("status_2"):
            if _is_2xx(status) and m.get("has_body"):
                return True
        elif kind.startswith("body:") or kind.startswith("header_"):
            if _is_2xx(status):
                return True
    return False


# ---------------------------------------------------------------------------
# Optional LLM strategist (the "plan", AI-assisted)
# ---------------------------------------------------------------------------

class LLMStrategist:
    """Optional advisor backed by an OpenAI-compatible chat endpoint.

    One job today: rank which attack chains to pursue first, given a recon
    digest. Called via urllib (no SDK). Any failure is swallowed and the agent
    falls back to deterministic order, so the strategist can never break a run.

    Data-egress note: it transmits a recon digest (one "METHOD path -> status"
    line per live observation, no response bodies) to the configured endpoint.
    It is off unless an endpoint is supplied, and the run report records the
    egress. `endpoint_warning` is non-empty when the endpoint is a non-loopback
    plaintext or remote host, so the report can surface where data is going.
    """

    def __init__(self, endpoint: str, model: str, api_key: Optional[str],
                 timeout: float = 20.0):
        self.endpoint = endpoint
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.calls = 0
        self.endpoint_warning = self._assess_endpoint(endpoint)

    @staticmethod
    def _assess_endpoint(endpoint: str) -> str:
        parsed = urllib.parse.urlparse(endpoint)
        host = (parsed.hostname or "").lower()
        loopback = host in ("127.0.0.1", "localhost", "::1")
        if parsed.scheme == "http" and not loopback:
            return ("endpoint is plaintext http to a non-loopback host (%s): "
                    "the recon digest egresses unencrypted" % host)
        if not loopback:
            return "endpoint is a remote host (%s): recon digest leaves the box" % host
        return ""

    def _chat(self, system: str, user: str) -> Optional[str]:
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        req = urllib.request.Request(self.endpoint, data=payload,
                                     headers=headers, method="POST")
        try:
            self.calls += 1
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    def rank_chains(self, chains: List[Dict], recon_digest: str) -> Optional[List[str]]:
        if not chains:
            return None
        listing = "\n".join("- %s: %s" % (c["id"], c.get("summary", c.get("name", "")))
                            for c in chains)
        out = self._chat(
            "You are a red-team planner. Given recon results and candidate attack "
            "chains, return ONLY a JSON array of chain ids, most promising first.",
            "Recon digest:\n%s\n\nChains:\n%s\n\nJSON array of ids:" % (recon_digest, listing),
        )
        if not out:
            return None
        try:
            ids = json.loads(out[out.index("["):out.rindex("]") + 1])
            valid = {c["id"] for c in chains}
            return [i for i in ids if i in valid] or None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# The agent (the loop)
# ---------------------------------------------------------------------------

class RedTeamAgent:
    """Runs a ScenarioPacket against one authorized target as a kill-chain loop."""

    def __init__(self, config: RunConfig,
                 runner: Optional[ProbeRunner] = None,
                 evaluator: Optional[SignalEvaluator] = None,
                 strategist: Optional[LLMStrategist] = None,
                 tool_version: str = "0.2.0"):
        self.config = config
        self.runner = runner or ProbeRunner(config)
        self.evaluator = evaluator or SignalEvaluator()
        self.strategist = strategist
        self.tool_version = tool_version
        self._seq = 0
        self._budget_hit = False

    # -- scope -------------------------------------------------------------

    def _scope(self) -> Tuple[str, str]:
        parsed = urllib.parse.urlparse(self.config.target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ScopeError(
                "target must be an absolute http(s) URL with a host, got: %r"
                % self.config.target)
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        return base, parsed.netloc

    def _url_for(self, base: str, netloc: str, path: str) -> str:
        # Reject anything that could resolve to another host: an absolute URL
        # ("http://evil/x"), a scheme-relative path ("//evil/x"), or an embedded
        # scheme. A packet path is a path, not a URL.
        if "://" in path or path.startswith("//"):
            raise ScopeError("packet path must be host-relative, got: %r" % path)
        if not path.startswith("/"):
            path = "/" + path
        url = base + path
        # Defense in depth: re-parse and assert we never left the host.
        if urllib.parse.urlparse(url).netloc != netloc:
            raise ScopeError("constructed url leaves target host: %s" % url)
        return url

    # -- packet helpers ----------------------------------------------------

    @staticmethod
    def _probe_index(packet: Dict) -> Dict[str, Dict]:
        rm = packet.get("recon_mapping", {})
        return {p["id"]: p for p in rm.get("http_probe_patterns", [])}

    @staticmethod
    def _ordered_probe_ids(packet: Dict) -> List[str]:
        rm = packet.get("recon_mapping", {})
        ordered: List[str] = []
        seen = set()
        for phase in rm.get("recon_phases", []):
            for pid in phase.get("probe_ids", []):
                if pid not in seen:
                    ordered.append(pid)
                    seen.add(pid)
        # Any probe not referenced by a phase still gets run, after the phases.
        for p in rm.get("http_probe_patterns", []):
            if p["id"] not in seen:
                ordered.append(p["id"])
                seen.add(p["id"])
        return ordered

    @staticmethod
    def _test_case_index(packet: Dict) -> Dict[str, Dict]:
        return {t["id"]: t for t in packet.get("test_cases", [])}

    # -- request construction ---------------------------------------------

    def _body_for(self, probe: Dict, method: str) -> Tuple[Optional[bytes], Optional[str]]:
        """Minimal benign body for a write probe. We never fabricate a mutating
        payload from the packet's free-text body_shape; we send the smallest
        thing that reveals the auth differential."""
        if method not in _WRITE_METHODS:
            return None, None
        shape = (probe.get("body_shape") or "").lower()
        if "json" in shape or shape.startswith("{"):
            return b"{}", "{}"
        return None, None

    def _headers_for(self, probe: Dict) -> Dict[str, str]:
        headers = dict(probe.get("headers") or {})
        headers.setdefault("User-Agent", self.config.user_agent)
        return headers

    @staticmethod
    def _sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        out = {}
        for k, v in headers.items():
            if k.lower() == "authorization":
                out[k] = "***redacted***"
            else:
                out[k] = v
        return out

    # -- the recon pre-pass ------------------------------------------------

    def _run_probe(self, probe: Dict, base: str, netloc: str,
                   report: RunReport) -> List[Observation]:
        observations: List[Observation] = []
        agg = probe.get("aggressiveness", "medium")
        methods = probe.get("methods") or ["GET"]
        paths = probe.get("paths") or ["/"]

        for method in methods:
            for path in paths:
                self._seq += 1
                obs = Observation(
                    seq=self._seq, probe_id=probe["id"], method=method,
                    url=self._url_for(base, netloc, path), path=path,
                    aggressiveness=agg, sent=False)

                # Write-method gate: independent of the noise cap. A mutating
                # method never goes out unless writes are explicitly allowed,
                # however low the packet rated its noise.
                if method.upper() in _WRITE_METHODS and not self.config.allow_writes:
                    obs.skipped_reason = (
                        "write method %s blocked (pass --allow-writes to permit)" % method)
                    report.requests_skipped += 1
                    observations.append(obs)
                    report.observations.append(obs)
                    continue

                # Aggressiveness cap.
                if _agg_rank(agg) > _agg_rank(self.config.max_aggressiveness):
                    obs.skipped_reason = (
                        "aggressiveness %s exceeds cap %s"
                        % (agg, self.config.max_aggressiveness))
                    report.requests_skipped += 1
                    observations.append(obs)
                    report.observations.append(obs)
                    continue

                # Global request budget.
                if report.requests_sent + report.requests_planned >= self.config.max_requests:
                    obs.skipped_reason = "request budget (%d) exhausted" % self.config.max_requests
                    self._budget_hit = True
                    report.requests_skipped += 1
                    observations.append(obs)
                    report.observations.append(obs)
                    continue

                headers = self._headers_for(probe)
                body, body_str = self._body_for(probe, method)
                obs.request_headers = self._sanitize_headers(headers)
                obs.request_body = body_str

                if self.config.dry_run:
                    obs.skipped_reason = "dry-run: planned, not sent"
                    report.requests_planned += 1
                    observations.append(obs)
                    report.observations.append(obs)
                    continue

                result = self.runner.send(method, obs.url, headers, body,
                                          expected_netloc=netloc)
                obs.sent = True
                report.requests_sent += 1
                obs.status = result.get("status")
                obs.reason = result.get("reason")
                obs.final_url = result.get("final_url")
                obs.elapsed_ms = result.get("elapsed_ms")
                obs.response_headers = result.get("response_headers", {}) or {}
                obs.body_sample = result.get("body_sample")
                obs.body_truncated = result.get("body_truncated", False)
                obs.error = result.get("error")
                observations.append(obs)
                report.observations.append(obs)

        return observations

    # -- the loop ----------------------------------------------------------

    def run(self, packet: Dict) -> RunReport:
        if not self.config.authorization or not str(self.config.authorization).strip():
            raise AuthorizationError(
                "agent run requires --authorize <scope/engagement reference>; "
                "refusing to send without it")
        if not self.config.target:
            raise AuthorizationError("agent run requires a --target")

        base, netloc = self._scope()
        tp = packet.get("target_profile", {})
        report = RunReport(
            tool_version=self.tool_version,
            mode="dry_run" if self.config.dry_run else "live",
            focus_type=tp.get("focus_type", "unknown"),
            focus_value=tp.get("focus_value", "unknown"),
            target=base,
            authorization=str(self.config.authorization),
            started_at=datetime.datetime.now().isoformat(timespec="seconds"),
            config=self.config.public_view(),
        )
        if self.config.dry_run:
            report.notes.append(
                "DRY RUN: requests were planned, not sent. No finding can be "
                "confirmed in dry-run. Re-run with --live to exercise the plan.")
        if self.strategist is not None:
            if self.config.dry_run:
                report.notes.append(
                    "LLM strategist configured: on --live it will transmit a recon "
                    "digest to %s (data egress). Nothing was sent in dry-run."
                    % self.config.llm_endpoint)
            else:
                report.notes.append(
                    "LLM strategist ENABLED: a recon digest was transmitted to %s "
                    "(data egress)." % self.config.llm_endpoint)
            if getattr(self.strategist, "endpoint_warning", ""):
                report.notes.append("WARNING: %s" % self.strategist.endpoint_warning)

        probe_idx = self._probe_index(packet)
        tc_idx = self._test_case_index(packet)
        cache: Dict[str, List[Observation]] = {}

        # --- recon pre-pass: run every in-cap probe once -------------------
        for pid in self._ordered_probe_ids(packet):
            probe = probe_idx.get(pid)
            if not probe:
                continue
            cache[pid] = self._run_probe(probe, base, netloc, report)
            if self._budget_hit:
                report.notes.append("Stopped early: request budget exhausted.")
                break

        all_obs = report.observations

        # --- optional LLM chain ranking ------------------------------------
        chains = packet.get("attack_chains", []) or []
        order = list(range(len(chains)))
        if self.strategist is not None and not self.config.dry_run and chains:
            digest = self._recon_digest(all_obs)
            ranked = self.strategist.rank_chains(chains, digest)
            if ranked:
                by_id = {c["id"]: i for i, c in enumerate(chains)}
                order = [by_id[i] for i in ranked if i in by_id]
                order += [i for i in range(len(chains)) if i not in order]
                report.notes.append("LLM strategist reordered chains: %s"
                                    % ", ".join(ranked))

        # --- evaluate EVERY test case, independent of chain walking ---------
        # A confirmable exposure must land in the ledger even if the only chain
        # that references it stalls at an earlier step, or no chain references
        # it at all. Findings are the evidence record; chains are the narrative.
        findings_by_tc: Dict[str, Finding] = {}
        for tc_id, tc in tc_idx.items():
            findings_by_tc[tc_id] = self._build_finding(tc_id, tc, all_obs)

        # --- chain execution: advance only on confirmation -----------------
        for idx in order:
            chain = chains[idx]
            report.chain_outcomes.append(
                self._walk_chain(chain, tc_idx, all_obs, findings_by_tc))

        report.findings = list(findings_by_tc.values())
        held_writes = sum(1 for o in report.observations
                          if o.skipped_reason and o.skipped_reason.startswith("write method"))
        if held_writes:
            report.notes.append(
                "%d write-method probe(s) held back (mutation gate). Pass "
                "--allow-writes to permit them." % held_writes)
        report.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
        return report

    def _walk_chain(self, chain: Dict, tc_idx: Dict[str, Dict],
                    all_obs: List[Observation],
                    findings_by_tc: Dict[str, Finding]) -> ChainOutcome:
        outcome = ChainOutcome(
            chain_id=chain.get("id", "?"),
            name=chain.get("name", ""),
            status="planned" if self.config.dry_run else "blocked",
            reached_step=None,
            summary=chain.get("summary", ""),
            defender_learning_goals=chain.get("defender_learning_goals", []) or [],
        )
        steps = chain.get("steps", []) or []
        for tc_id in steps:
            outcome.reached_step = tc_id
            tc = tc_idx.get(tc_id)
            if tc is None:
                outcome.note = "step %s has no matching test case in packet" % tc_id
                outcome.status = "blocked"
                return outcome

            finding = findings_by_tc.get(tc_id)
            if finding is None:  # defensive: tc exists, so this should not happen
                finding = self._build_finding(tc_id, tc, all_obs)
                findings_by_tc[tc_id] = finding

            if finding.confirmed:
                outcome.confirmed_steps.append(tc_id)
                outcome.status = "confirmed" if not self.config.dry_run else "planned"
                continue  # restraint: one proof, advance to next step

            # Step did not confirm. In live mode the chain stalls here: the
            # agent does not pursue a step whose precondition it could not meet.
            if self.config.dry_run:
                outcome.status = "planned"
            else:
                outcome.status = "stalled"
                outcome.note = "stalled at %s: %s" % (tc_id, finding.note)
            return outcome

        if not self.config.dry_run and outcome.confirmed_steps and \
                len(outcome.confirmed_steps) == len(steps):
            outcome.status = "confirmed"
        return outcome

    # -- finding builder / selection / digest ------------------------------

    def _build_finding(self, tc_id: str, tc: Dict,
                       all_obs: List[Observation]) -> Finding:
        relevant = self._observations_for(tc, all_obs)
        matched, evidence = self.evaluator.evaluate(tc, relevant)
        confirmed = (not self.config.dry_run) and _is_confirming(matched)
        if self.config.dry_run:
            note = "dry-run: not exercised"
        elif confirmed:
            note = "confirmed: %d signal(s) backed by sent evidence" % len(matched)
        elif matched:
            note = "indicative only (no hard 2xx/body/header evidence)"
        else:
            note = "no expected weak signals observed"
        return Finding(
            test_case_id=tc_id,
            objective=tc.get("objective", ""),
            confirmed=confirmed,
            severity_if_confirmed=tc.get("severity_if_confirmed", "info"),
            matched_signals=matched,
            evidence_seqs=evidence,
            note=note,
        )

    @staticmethod
    def _observations_for(test_case: Dict, all_obs: List[Observation]) -> List[Observation]:
        """Observations relevant to a test case: those whose path the case's text
        names (single-direction scoping). Falls back to all observations when the
        case names no path, so a case is never starved of evidence."""
        text = " ".join(test_case.get("steps_summary", []) or []) + " " + \
            test_case.get("objective", "")
        paths = _paths_in(text)
        if not paths:
            return all_obs
        scoped = [o for o in all_obs if _path_scopes(o.path, paths)]
        return scoped or all_obs

    @staticmethod
    def _recon_digest(observations: List[Observation], limit: int = 20) -> str:
        lines = []
        for o in observations:
            if not o.sent:
                continue
            lines.append("%s %s -> %s" % (o.method, o.path, o.status or o.error))
            if len(lines) >= limit:
                break
        return "\n".join(lines) or "(no live observations)"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_run_report_markdown(report: RunReport) -> str:
    L: List[str] = []
    L.append("# Agent run report: %s / %s" % (report.focus_type, report.focus_value))
    L.append("")
    L.append("- **mode**: `%s`" % report.mode)
    L.append("- **target**: `%s`" % report.target)
    L.append("- **authorization**: %s" % report.authorization)
    L.append("- **started**: %s  **finished**: %s"
             % (report.started_at, report.finished_at))
    L.append("- **requests**: %d sent, %d planned, %d skipped"
             % (report.requests_sent, report.requests_planned, report.requests_skipped))
    if report.notes:
        L.append("")
        for n in report.notes:
            L.append("> %s" % n)

    L.append("")
    L.append("## Findings")
    if not report.findings:
        L.append("")
        L.append("_No test cases were evaluated._")
    else:
        L.append("")
        L.append("| test case | confirmed | severity | evidence | note |")
        L.append("|-----------|-----------|----------|----------|------|")
        for f in report.findings:
            mark = "yes" if f.confirmed else "no"
            ev = ",".join("#%d" % s for s in f.evidence_seqs) or "-"
            L.append("| `%s` | %s | %s | %s | %s |"
                     % (f.test_case_id, mark, f.severity_if_confirmed, ev, f.note))

    L.append("")
    L.append("## Attack chains")
    if not report.chain_outcomes:
        L.append("")
        L.append("_No chains in packet._")
    else:
        for c in report.chain_outcomes:
            L.append("")
            L.append("### %s (`%s`) - %s" % (c.name or c.chain_id, c.chain_id, c.status))
            if c.summary:
                L.append("")
                L.append(c.summary)
            L.append("")
            L.append("- reached step: `%s`" % (c.reached_step or "-"))
            L.append("- confirmed steps: %s"
                     % (", ".join("`%s`" % s for s in c.confirmed_steps) or "none"))
            if c.note:
                L.append("- note: %s" % c.note)
            if c.defender_learning_goals:
                L.append("- defender learning goals:")
                for g in c.defender_learning_goals:
                    L.append("  - %s" % g)

    L.append("")
    L.append("## Evidence ledger")
    L.append("")
    L.append("| # | probe | method | path | status | sent | note |")
    L.append("|---|-------|--------|------|--------|------|------|")
    for o in report.observations:
        status = o.status if o.status is not None else (o.error or "-")
        note = o.skipped_reason or ("truncated" if o.body_truncated else "")
        L.append("| %d | `%s` | %s | `%s` | %s | %s | %s |"
                 % (o.seq, o.probe_id, o.method, o.path, status,
                    "yes" if o.sent else "no", note))

    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Convenience builder
# ---------------------------------------------------------------------------

def build_agent(config: RunConfig, tool_version: str = "0.2.0") -> RedTeamAgent:
    strategist = None
    if config.llm_endpoint:
        strategist = LLMStrategist(
            endpoint=config.llm_endpoint,
            model=config.llm_model,
            api_key=config.llm_api_key,
        )
    return RedTeamAgent(config, strategist=strategist, tool_version=tool_version)

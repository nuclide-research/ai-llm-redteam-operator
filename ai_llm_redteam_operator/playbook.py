"""
Tactical knowledge base for AI_LLM_RedTeam_Operator.

Structure: three top-level dicts keyed on focus value.
  CATEGORY_PLAYBOOK  -- keyed on ExposureCategory string
  PLATFORM_PLAYBOOK  -- keyed on platform name string
  ATTACK_PATH_PLAYBOOK -- keyed on AttackPath string

Each entry is a plain dict that maps 1:1 onto the model fields.
The operator builders destructure these and combine with live DB data.

Add a new category/platform/attack path by adding one dict entry here;
no changes needed in operator.py.
"""

# ---------------------------------------------------------------------------
# CATEGORY PLAYBOOK
# ---------------------------------------------------------------------------

CATEGORY_PLAYBOOK: dict = {

    # -----------------------------------------------------------------------
    "open_gateways": {
        "typical_platforms": ["LiteLLM", "One API", "LobeChat (proxy)", "OpenRouter-self-hosted", "LM Studio"],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/v1/models",               "notes": "OpenAI-compat model list; 200 unauth = open proxy"},
            {"type": "http_path",      "pattern": "/api/v1/models",           "notes": "LiteLLM model list; same signal"},
            {"type": "http_path",      "pattern": "/v1/chat/completions",     "notes": "Primary inference endpoint; POST without auth = key abuse surface"},
            {"type": "http_path",      "pattern": "/health",                  "notes": "Uptime + version; sometimes exposes backend names"},
            {"type": "http_path",      "pattern": "/config",                  "notes": "LiteLLM admin config dump; may return provider key names"},
            {"type": "http_path",      "pattern": "/admin",                   "notes": "Admin UI; default creds common on self-hosted"},
            {"type": "http_path",      "pattern": "/swagger",                 "notes": "OpenAPI spec; maps full attack surface without active probing"},
            {"type": "http_path",      "pattern": "/openapi.json",            "notes": "Same; prefer this for programmatic surface mapping"},
            {"type": "http_path",      "pattern": "/metrics",                 "notes": "Prometheus metrics; leaks token counts, model names, upstream costs"},
            {"type": "http_path",      "pattern": "/v1/completions",          "notes": "Legacy completion endpoint; sometimes less guarded than /chat"},
            {"type": "header_pattern", "pattern": "Authorization: Bearer sk-", "notes": "Default LiteLLM key format; trivially guessable in weak configs"},
            {"type": "banner_pattern", "pattern": "LiteLLM",                 "notes": "HTTP response body or title confirms platform"},
        ],
        "http_probe_patterns": [
            {
                "description": "Unauthenticated model listing - confirms open proxy",
                "methods": ["GET"],
                "paths": ["/v1/models", "/api/v1/models", "/openai/models"],
                "headers": {},
                "notes": "HTTP 200 with a JSON list is a finding. Compare model IDs against known provider model names to infer upstream (e.g., gpt-4o, claude-3-* = billing key present).",
            },
            {
                "description": "Inference passthrough without credentials",
                "methods": ["POST"],
                "paths": ["/v1/chat/completions", "/api/v1/chat/completions"],
                "headers": {"Content-Type": "application/json"},
                "notes": "Send a minimal payload (model+single user message). A streaming or JSON response = billing key consumed. Record response headers for upstream hints (x-ratelimit-*, cf-ray).",
            },
            {
                "description": "Weak bearer bypass - send garbage token",
                "methods": ["GET", "POST"],
                "paths": ["/v1/models", "/v1/chat/completions"],
                "headers": {"Authorization": "Bearer invalid-token-probe"},
                "notes": "200 on garbage token = auth check absent or misconfigured. Distinguish from 401 with WWW-Authenticate header.",
            },
            {
                "description": "Config and admin surface enumeration",
                "methods": ["GET"],
                "paths": ["/config", "/admin", "/admin/config", "/litellm/config", "/v1/config"],
                "headers": {},
                "notes": "Look for key_name, api_key, OPENAI_API_KEY, ANTHROPIC_API_KEY fields. Even partial redaction (sk-***) confirms key class.",
            },
            {
                "description": "CORS preflight - checks for misconfigured cross-origin access",
                "methods": ["OPTIONS"],
                "paths": ["/v1/chat/completions", "/v1/models"],
                "headers": {"Origin": "https://attacker.example.com", "Access-Control-Request-Method": "POST"},
                "notes": "Access-Control-Allow-Origin: * or echoed Origin = browser-exploitable via XHR from any page.",
            },
            {
                "description": "Prometheus metrics scrape",
                "methods": ["GET"],
                "paths": ["/metrics", "/metrics/system", "/actuator/prometheus"],
                "headers": {},
                "notes": "Token usage, model call counts, and cost-per-model reveal upstream provider and consumption volume without touching inference.",
            },
        ],
        "mapping_strategy": [
            "1. GET /v1/models without auth; bucket by status code (200/401/403). 200 = open; log model list.",
            "2. GET /openapi.json or /swagger; parse paths to build full endpoint inventory before active probing.",
            "3. Probe /config, /admin, /admin/config for config dump. Any 200 with key-shaped fields = stop and document.",
            "4. POST to /v1/chat/completions with no auth header; 200/streaming response = key is live.",
            "5. OPTIONS preflight on inference endpoint; ACAO: * or echoed origin = browser-side lateral move possible.",
            "6. GET /metrics; extract litellm_spend_per_model or similar; correlate with provider from model IDs.",
            "7. Cross-reference banner responses and HTTP headers to confirm platform and version for CVE scoping.",
        ],
        "assets": [
            {"name": "provider_api_keys",    "description": "Billing keys (OpenAI, Anthropic, Cohere, etc.) stored in gateway config or env."},
            {"name": "multi_tenant_routes",  "description": "Per-customer model routes; BOLA may expose one tenant's config/usage to another."},
            {"name": "gpu_and_inference_budget", "description": "Reserved GPU/API credit spend; key abuse drains without detection."},
            {"name": "model_inventory",      "description": "Internal model names reveal provider contracts and cost tiers."},
            {"name": "usage_telemetry",      "description": "Token counts and latency data in metrics endpoints."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Gateway exposes /v1/models without authentication, confirming open proxy and enabling key abuse.",
                "related_categories": ["open_gateways", "key_abuse"],
                "related_attack_paths": ["open_gateway_llmjacking"],
                "impact_if_confirmed": "critical",
            },
            {
                "id": "H2",
                "description": "Config or admin endpoint leaks provider key names or partial values.",
                "related_categories": ["open_gateways", "key_abuse"],
                "related_attack_paths": ["open_gateway_llmjacking"],
                "impact_if_confirmed": "critical",
            },
            {
                "id": "H3",
                "description": "CORS wildcard on inference endpoint allows browser-based cross-site key abuse.",
                "related_categories": ["open_gateways"],
                "related_attack_paths": [],
                "impact_if_confirmed": "high",
            },
            {
                "id": "H4",
                "description": "Multi-tenant gateway lacks route isolation; BOLA on /v1/config/{tenant_id} exposes peer config.",
                "related_categories": ["open_gateways"],
                "related_attack_paths": [],
                "impact_if_confirmed": "high",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm unauthenticated model listing via /v1/models.",
                "preconditions": ["Host reachable on target port", "No IP allowlist in place"],
                "steps_summary": [
                    "GET /v1/models with no Authorization header.",
                    "GET /api/v1/models as fallback.",
                    "Record HTTP status and response body.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with JSON array of model objects.",
                    "Model IDs containing provider prefixes (gpt-, claude-, command-).",
                    "X-Request-ID or cf-ray in response headers hinting upstream routing.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Distinguish from a 200 that returns an empty list - empty may indicate the proxy requires auth for inference but lists nothing.",
            },
            {
                "id": "TC2",
                "objective": "Confirm unauthenticated inference passthrough (key abuse surface).",
                "preconditions": ["TC1 confirmed open model list", "Target responds on port"],
                "steps_summary": [
                    "POST /v1/chat/completions with Content-Type: application/json.",
                    "Use minimal payload: messages=[{role:user, content: short probe}], model from TC1 list.",
                    "Send without Authorization header.",
                    "If 200: record streaming vs non-streaming, latency, and any cost headers.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with completion text or stream chunks.",
                    "x-ratelimit-remaining-requests header present (proves upstream key in use).",
                    "Response time consistent with provider latency (not a mock).",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Confirm response is real inference and not a cached stub. Single-token probe is sufficient to establish key consumption.",
            },
            {
                "id": "TC3",
                "objective": "Enumerate config and admin endpoints for key leakage.",
                "preconditions": ["Host reachable", "HTTP accessible"],
                "steps_summary": [
                    "GET /config, /admin, /admin/config, /litellm/config, /v1/config in order.",
                    "Record any 200 with JSON body.",
                    "Scan body for fields: api_key, key, secret, OPENAI_API_KEY, token, credentials.",
                    "Note partial values (sk-****, ant-01-****) as confirming key class even if redacted.",
                ],
                "expected_weak_signals": [
                    "JSON response containing key-shaped field names.",
                    "HTTP 200 on /admin with an HTML admin panel (check default creds separately).",
                    "Response body containing environment variable names referencing secrets.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Even a partial key suffix is enough to confirm class and establish vendor contact for disclosure. Do not exfiltrate full key values beyond what is needed to prove existence.",
            },
            {
                "id": "TC4",
                "objective": "Test CORS misconfiguration on inference endpoint.",
                "preconditions": ["Inference endpoint accessible"],
                "steps_summary": [
                    "Send OPTIONS to /v1/chat/completions with Origin: https://attacker.example.com.",
                    "Include Access-Control-Request-Method: POST and Access-Control-Request-Headers: Authorization.",
                    "Inspect Access-Control-Allow-Origin and Access-Control-Allow-Credentials in response.",
                ],
                "expected_weak_signals": [
                    "ACAO: * (wildcard) - browser-exploitable without credentials.",
                    "ACAO: https://attacker.example.com (origin reflection) with ACAC: true - worst case.",
                    "ACAO absent but inference endpoint returns 200 to cross-origin POST - CORS moot if no auth.",
                ],
                "severity_if_confirmed": "high",
                "notes": "CORS only matters if there is auth worth bypassing. If TC2 already confirms no auth, CORS is informational in that context.",
            },
            {
                "id": "TC5",
                "objective": "Scrape Prometheus metrics for cost and model telemetry without credentials.",
                "preconditions": ["Host reachable on metrics port (usually same or 9090/9091)"],
                "steps_summary": [
                    "GET /metrics.",
                    "Parse for litellm_* metrics, request_count, token_count, model label.",
                    "Note model names in labels to infer provider.",
                ],
                "expected_weak_signals": [
                    "litellm_spend_per_model metric present with $ values.",
                    "model= label containing gpt-4o, claude-3, command-r+ confirming live billing.",
                    "request_total by endpoint revealing usage patterns.",
                ],
                "severity_if_confirmed": "medium",
                "notes": "Metrics alone are medium severity; combined with TC1/TC2 they establish active billing key consumption at scale.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Open Gateway LLMjacking",
                "steps": ["TC1", "TC2", "TC3", "TC5"],
                "summary": "Confirm open model list, verify unauthenticated inference, locate config endpoint for key names, then scrape metrics to measure upstream spend. At this point the gateway is fully open for LLMjacking - token budget can be exhausted via the attacker's own prompts or resold.",
            },
        ],
        "logging_recommendations": [
            {"event": "model_list_no_auth",     "fields": ["ip", "user_agent", "path", "status", "timestamp"],       "notes": "Baseline; spikes without auth indicate scanning or abuse."},
            {"event": "inference_no_auth",      "fields": ["ip", "model", "input_tokens", "path", "status"],         "notes": "Critical: every unauthenticated completion request should alert."},
            {"event": "config_endpoint_access", "fields": ["ip", "user_agent", "path", "status", "response_size"],   "notes": "Any 200 on /config or /admin from external IP = P0 alert."},
            {"event": "provider_key_rotation",  "fields": ["key_id", "rotated_by", "timestamp", "reason"],           "notes": "Track rotation cadence; absence of recent rotation post-incident = re-exposure."},
            {"event": "token_spend_anomaly",    "fields": ["model", "tokens", "period", "requester_id"],              "notes": "Alert when per-IP or per-session token spend exceeds baseline by 5x."},
        ],
        "detection_ideas": [
            {"pattern": "GET /v1/models > 50 times from single IP in 60s without auth",   "severity": "high",     "notes": "Scanning or automation; confirm by checking if subsequent inference follows."},
            {"pattern": "POST /v1/chat/completions with no Authorization header, 200",    "severity": "critical", "notes": "Direct evidence of LLMjacking; page immediately."},
            {"pattern": "GET /config or /admin returns 200 from external IP",             "severity": "critical", "notes": "Config exfiltration in progress."},
            {"pattern": "Token spend rate increases 10x with no new user registrations",   "severity": "high",     "notes": "Unusual spend without matching user growth = key abuse."},
            {"pattern": "OPTIONS requests with non-whitelisted Origin headers",            "severity": "medium",   "notes": "CORS probe; correlate with subsequent POST attempts."},
        ],
        "quick_wins": [
            "Require a static master API key on all /v1/* paths via reverse proxy (nginx auth_request) immediately.",
            "Block /config, /admin, /metrics endpoints at the load balancer for all non-loopback sources.",
            "Set CORS origin allowlist to your frontend domain only; never wildcard on authenticated endpoints.",
            "Enable LiteLLM spend tracking and alert on > $X/hour from any single key.",
            "Add a rate limit (50 req/min) per IP on /v1/chat/completions as a stop-gap.",
        ],
        "architectural_changes": [
            "Place gateway behind an internal VPC/VPN; never expose port 4000/8000 publicly.",
            "Implement per-user virtual keys so provider keys never leave the gateway process.",
            "Separate admin plane (config/metrics) from inference data plane; different ports, different auth.",
            "Route all external inference through a WAF with a ruleset for prompt injection and key exfil patterns.",
            "Add SIEM integration so every provider API call generates a structured log event.",
        ],
        "template_guidance": [
            "Secure AI Deployment baseline: all LLM gateway ports must be firewall-protected; only VPN/internal reachable.",
            "Template must include a secrets management block: no plaintext provider keys in config files or env vars checked into repos.",
            "Enforce per-deployment key rotation policy: max 90-day key lifetime, rotation triggered on any suspected exposure.",
            "Include Prometheus metrics endpoint in internal-only network segment in all deployment templates.",
        ],
    },

    # -----------------------------------------------------------------------
    "exposed_model_runtimes": {
        "typical_platforms": ["Ollama", "vLLM", "llama.cpp server", "LM Studio", "Aphrodite Engine", "TabbyAPI"],
        "surface_elements": [
            {"type": "port",           "pattern": "11434",          "notes": "Ollama default; TCP open without auth in default config"},
            {"type": "port",           "pattern": "8000",           "notes": "vLLM default API port"},
            {"type": "port",           "pattern": "8080",           "notes": "llama.cpp server default"},
            {"type": "http_path",      "pattern": "/api/tags",      "notes": "Ollama: returns list of locally installed models"},
            {"type": "http_path",      "pattern": "/api/generate",  "notes": "Ollama: direct text generation, no auth by default"},
            {"type": "http_path",      "pattern": "/api/ps",        "notes": "Ollama: running model processes and GPU allocation"},
            {"type": "http_path",      "pattern": "/api/show",      "notes": "Ollama: model metadata including parameter counts"},
            {"type": "http_path",      "pattern": "/api/pull",      "notes": "Ollama: pulls model from registry; attacker-controlled model loading"},
            {"type": "http_path",      "pattern": "/v1/models",     "notes": "vLLM OpenAI-compat; lists loaded model"},
            {"type": "banner_pattern", "pattern": "Ollama is running", "notes": "Ollama root response body; definitive fingerprint"},
        ],
        "http_probe_patterns": [
            {
                "description": "Model inventory via Ollama /api/tags",
                "methods": ["GET"],
                "paths": ["/api/tags"],
                "headers": {},
                "notes": "Returns JSON with models[], each entry has name, modified_at, size. Model names reveal capability and potential data handled (e.g., llava = vision, code models = dev context).",
            },
            {
                "description": "Running model process inspection",
                "methods": ["GET"],
                "paths": ["/api/ps"],
                "headers": {},
                "notes": "Lists currently loaded models with GPU memory allocation. Shows if a model is actively serving requests - i.e., live production use.",
            },
            {
                "description": "Model metadata dump",
                "methods": ["POST"],
                "paths": ["/api/show"],
                "headers": {"Content-Type": "application/json"},
                "notes": "POST {name: <model>}. Returns modelfile content including system prompt, which may reveal deployment context (company name, purpose, instructions).",
            },
            {
                "description": "Unauthenticated inference on local runtime",
                "methods": ["POST"],
                "paths": ["/api/generate", "/api/chat"],
                "headers": {"Content-Type": "application/json"},
                "notes": "POST {model: <name>, prompt: <text>}. 200 with generated text confirms unauth exec. Record model used and any system-prompt bleed.",
            },
            {
                "description": "Arbitrary model pull attempt",
                "methods": ["POST"],
                "paths": ["/api/pull"],
                "headers": {"Content-Type": "application/json"},
                "notes": "POST {name: <registry-model>}. Success = attacker can load arbitrary models from Ollama registry, consuming GPU and disk. Also can pull a custom model from an attacker-controlled registry if model:// URL accepted.",
            },
        ],
        "mapping_strategy": [
            "1. Confirm port 11434 open with a TCP banner grab; look for 'Ollama is running' on GET /.",
            "2. GET /api/tags to inventory installed models; size and modification dates give deployment age.",
            "3. GET /api/ps to check live model load; active = production inference running.",
            "4. POST /api/show for each model; extract modelfile system prompt for context leakage.",
            "5. POST /api/generate with a short prompt; confirm unauthenticated inference.",
            "6. Attempt POST /api/pull with a known-safe model name; observe if pull initiates (auth not required).",
            "7. Check host HTTP headers for server version to scope to known Ollama CVEs.",
        ],
        "assets": [
            {"name": "gpu_compute",    "description": "GPU resources consumed per inference; open access enables compute theft at scale."},
            {"name": "model_weights",  "description": "Locally stored fine-tuned or proprietary model files; readable via show or filesystem if RCE achieved."},
            {"name": "system_prompts", "description": "Deployment-specific system prompts embedded in modelfiles reveal operational context."},
            {"name": "host_os_surface","description": "Runtime is usually root or privileged; inference RCE = OS-level access."},
            {"name": "training_data_hints", "description": "Model names and system prompts hint at what data the model was trained or fine-tuned on."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Ollama instance is Internet-exposed on 11434 with no auth; any host can invoke inference and consume GPU.",
                "related_categories": ["exposed_model_runtimes", "key_abuse"],
                "related_attack_paths": ["ollama_11434_host_takeover"],
                "impact_if_confirmed": "critical",
            },
            {
                "id": "H2",
                "description": "System prompt in modelfile leaks deployment context (org name, use case, data class).",
                "related_categories": ["exposed_model_runtimes"],
                "related_attack_paths": [],
                "impact_if_confirmed": "medium",
            },
            {
                "id": "H3",
                "description": "Unauthenticated /api/pull allows attacker to load arbitrary models from public or attacker-controlled registry.",
                "related_categories": ["exposed_model_runtimes"],
                "related_attack_paths": ["ollama_11434_host_takeover"],
                "impact_if_confirmed": "high",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm Ollama model inventory is publicly readable.",
                "preconditions": ["Port 11434 open and TCP-reachable"],
                "steps_summary": [
                    "GET http://target:11434/ to confirm 'Ollama is running'.",
                    "GET /api/tags to retrieve model list.",
                    "Record model names, sizes, and modification dates.",
                ],
                "expected_weak_signals": [
                    "JSON response with models[] array.",
                    "Model sizes in GB suggesting fine-tuned or large production models.",
                    "Recent modification dates confirming active use.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Model list alone is medium-high. Combine with unauthenticated inference for critical.",
            },
            {
                "id": "TC2",
                "objective": "Extract system prompt from Ollama modelfile.",
                "preconditions": ["TC1 confirmed model list"],
                "steps_summary": [
                    "POST /api/show with {name: <model-name>} for each model in inventory.",
                    "Parse 'modelfile' field in response for SYSTEM block.",
                    "Document any org-identifying content in system prompt.",
                ],
                "expected_weak_signals": [
                    "SYSTEM block with company name or product name.",
                    "Instructions referencing specific data types (medical records, code repos, financial data).",
                    "User persona names or internal tool references.",
                ],
                "severity_if_confirmed": "medium",
                "notes": "Treat system prompt content as operational intelligence, not just info. Combine with sector data from nuclide.db to assess regulatory exposure.",
            },
            {
                "id": "TC3",
                "objective": "Confirm unauthenticated text generation (GPU theft surface).",
                "preconditions": ["TC1 confirmed at least one model"],
                "steps_summary": [
                    "POST /api/generate with {model: <from TC1>, prompt: short benign string, stream: false}.",
                    "Record HTTP status, response time, and generated text.",
                    "Confirm response is real inference (latency > 100ms, coherent output).",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with {response: <generated text>}.",
                    "eval_duration field > 0 in response metadata.",
                    "Latency consistent with model size (7B ~ 500ms, 70B ~ 3-10s).",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Single probe sufficient. Do not run generation loops - one confirmation establishes the finding.",
            },
            {
                "id": "TC4",
                "objective": "Test whether unauthenticated model pull is allowed.",
                "preconditions": ["Outbound network access from target likely (infer from model sources in TC1)"],
                "steps_summary": [
                    "POST /api/pull with {name: <small known-safe model>}.",
                    "Observe streaming progress response vs 403/401.",
                    "If pull initiates, cancel immediately (stream: false is not always respected).",
                ],
                "expected_weak_signals": [
                    "Response stream begins with {status: 'pulling manifest'}.",
                    "HTTP 200 with a progress stream rather than error.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Pull is high severity because it demonstrates host control of what code executes. Do not pull a large model; use smallest available to test the path, then abort.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Ollama Port 11434 Host Takeover",
                "steps": ["TC1", "TC2", "TC3", "TC4"],
                "summary": "Enumerate installed models to understand deployment context, extract system prompts for operational intel, confirm unauthenticated inference for GPU abuse surface, then test arbitrary model pull to establish persistent host manipulation capability.",
            },
        ],
        "logging_recommendations": [
            {"event": "model_list_external_ip",  "fields": ["ip", "path", "status", "user_agent"],                 "notes": "GET /api/tags from non-RFC1918 IP should alert immediately."},
            {"event": "unauthenticated_generate", "fields": ["ip", "model", "prompt_length", "eval_tokens"],       "notes": "Every /api/generate or /api/chat request with source IP."},
            {"event": "model_pull_initiated",     "fields": ["ip", "model_name", "registry", "timestamp"],         "notes": "Any /api/pull from external IP is a P0."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/tags from non-RFC1918 IP",           "severity": "critical", "notes": "Direct exposure; no legitimate reason for external model listing."},
            {"pattern": "POST /api/pull from external IP",             "severity": "critical", "notes": "Attacker-controlled model load; potential for code execution via modelfile."},
            {"pattern": "GPU utilization spike without internal jobs",  "severity": "high",     "notes": "Unauthenticated inference in progress; check /api/ps for active model."},
        ],
        "quick_wins": [
            "Bind Ollama to 127.0.0.1 immediately (OLLAMA_HOST=127.0.0.1 in systemd unit or .env).",
            "Add OLLAMA_ORIGINS to restrict which origins can reach the API if reverse-proxied.",
            "Firewall port 11434 externally at the host or cloud security group level.",
        ],
        "architectural_changes": [
            "Run Ollama behind an auth-enforcing reverse proxy (Caddy + forward_auth or nginx auth_request).",
            "Isolate Ollama host on a GPU-dedicated subnet; no direct Internet routing.",
            "Implement network egress filtering to prevent arbitrary model pulls from public registries.",
        ],
        "template_guidance": [
            "All model runtime deployments must bind to loopback or VPN interface only; no 0.0.0.0 defaults.",
            "GPU workload host template must include firewall rules blocking 11434/8000/8080 from external ranges.",
            "Model pull must require registry auth tokens; pull from public registries without auth must be disabled.",
        ],
    },

    # -----------------------------------------------------------------------
    "notebooks": {
        "typical_platforms": ["JupyterHub", "JupyterLab", "Jupyter Notebook", "Google Colab (self-hosted)", "Zeppelin"],
        "surface_elements": [
            {"type": "port",           "pattern": "8888",            "notes": "Jupyter Notebook classic default"},
            {"type": "port",           "pattern": "8889",            "notes": "JupyterLab alternate"},
            {"type": "port",           "pattern": "8080",            "notes": "JupyterHub proxy default"},
            {"type": "http_path",      "pattern": "/api/kernels",    "notes": "Kernel inventory; running = active sessions"},
            {"type": "http_path",      "pattern": "/api/terminals",  "notes": "Terminal inventory; terminal open = OS shell exposure"},
            {"type": "http_path",      "pattern": "/api/contents",   "notes": "Filesystem tree; enumerates notebooks and data files"},
            {"type": "http_path",      "pattern": "/api/sessions",   "notes": "Active session list; reveals users and notebooks in use"},
            {"type": "http_path",      "pattern": "/tree",           "notes": "Classic Jupyter file browser UI; no-auth 200 = full FS access"},
            {"type": "http_path",      "pattern": "/lab",            "notes": "JupyterLab UI; no-auth 200 = code execution"},
            {"type": "header_pattern", "pattern": "X-XSRFToken",     "notes": "Jupyter CSRF token; may be bypassable on old versions"},
        ],
        "http_probe_patterns": [
            {
                "description": "Kernel enumeration - confirms active code execution environment",
                "methods": ["GET"],
                "paths": ["/api/kernels"],
                "headers": {},
                "notes": "200 with kernel list = unauth access to execution state. Kernel IDs can be used to attach WebSocket sessions. Running kernels indicate live user sessions.",
            },
            {
                "description": "Filesystem enumeration via contents API",
                "methods": ["GET"],
                "paths": ["/api/contents", "/api/contents/", "/api/contents/.."],
                "headers": {},
                "notes": "Returns directory tree. Look for .env files, credentials.json, SSH keys, API key files in notebook paths.",
            },
            {
                "description": "Terminal inventory",
                "methods": ["GET"],
                "paths": ["/api/terminals"],
                "headers": {},
                "notes": "Open terminal = OS shell without code execution path. Higher impact than notebook-only.",
            },
            {
                "description": "No-token UI access",
                "methods": ["GET"],
                "paths": ["/tree", "/lab", "/notebooks"],
                "headers": {},
                "notes": "Redirect to login page = some auth. Direct 200 with notebook UI HTML = fully open. Check for ?token= requirement in redirect.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/kernels without token; 200 with list = open.",
            "2. GET /api/contents to enumerate filesystem; flag sensitive extensions (.env, .pem, credentials.json, .ipynb with API keys).",
            "3. GET /api/terminals; open terminal is OS-level access.",
            "4. Check GET /tree or /lab for no-auth HTML response.",
            "5. If kernels listed, attempt WebSocket connect to kernel exec endpoint to confirm code execution without token.",
            "6. GET /api/sessions to see user activity and notebook paths.",
        ],
        "assets": [
            {"name": "gpu_compute",         "description": "GPU-attached Jupyter often deployed for AI training; arbitrary exec = full GPU access."},
            {"name": "credentials_on_disk",  "description": "Notebooks commonly co-located with .env, cloud credentials, and SSH keys."},
            {"name": "training_datasets",    "description": "Data files in notebook FS may contain PII or proprietary training data."},
            {"name": "os_shell",             "description": "Terminal API or !shell cells = direct OS access at notebook user privilege."},
            {"name": "cloud_iam_metadata",   "description": "EC2/GCE metadata endpoint reachable from notebook = IMDS credential theft."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Jupyter is exposed without a token or password; anyone can execute arbitrary Python as the notebook user.",
                "related_categories": ["notebooks"],
                "related_attack_paths": ["open_jupyter_gpu_rce"],
                "impact_if_confirmed": "critical",
            },
            {
                "id": "H2",
                "description": "Notebook filesystem contains credentials or API keys readable via /api/contents.",
                "related_categories": ["notebooks", "key_abuse"],
                "related_attack_paths": [],
                "impact_if_confirmed": "critical",
            },
            {
                "id": "H3",
                "description": "Open terminal endpoint provides OS shell without needing code execution path.",
                "related_categories": ["notebooks"],
                "related_attack_paths": ["open_jupyter_gpu_rce"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm unauthenticated kernel and session access.",
                "preconditions": ["Port 8888 or 8080 open"],
                "steps_summary": [
                    "GET /api/kernels without Authorization header.",
                    "GET /api/sessions to list active notebooks.",
                    "Record kernel IDs and session paths.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with JSON list (even empty) rather than 401.",
                    "Active kernel entries with non-zero execution_count.",
                    "Session paths revealing notebook names and paths.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Empty kernel list still confirms API is open; execution may still be possible by creating a new kernel.",
            },
            {
                "id": "TC2",
                "objective": "Enumerate filesystem for credentials via contents API.",
                "preconditions": ["TC1 confirmed open API"],
                "steps_summary": [
                    "GET /api/contents to get root directory listing.",
                    "Recursively GET subdirectories flagged as likely to contain credentials.",
                    "List files matching: .env, credentials.json, *.pem, *.key, config.yaml.",
                ],
                "expected_weak_signals": [
                    "File listing including .env or credentials.json paths.",
                    "Notebook files with names suggesting API keys (secrets_notebook, keys_setup, etc.).",
                    "Unexpected directories (.aws, .gcloud, .ssh) in notebook root.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "File listing alone is high; confirming readable content is critical. Only read filenames and metadata to establish the finding.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Open Jupyter GPU RCE Chain",
                "steps": ["TC1", "TC2"],
                "summary": "Confirm open kernel API, enumerate filesystem for credentials, then demonstrate code execution capability. GPU access and cloud credential theft via IMDS are the primary impacts.",
            },
        ],
        "logging_recommendations": [
            {"event": "kernel_create_no_auth",    "fields": ["ip", "user_agent", "timestamp", "kernel_id"],    "notes": "Any kernel creation from external IP without session token."},
            {"event": "contents_api_traversal",   "fields": ["ip", "path", "depth", "file_count"],              "notes": "Deep filesystem enumeration from single IP in short window."},
            {"event": "terminal_open_external",   "fields": ["ip", "terminal_id", "user_agent"],                "notes": "P0: terminal opened from non-internal IP."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/kernels 200 from external IP", "severity": "critical", "notes": "Exposed Jupyter; immediate action required."},
            {"pattern": "GET /api/contents recursive from external IP in < 30s", "severity": "high", "notes": "Automated FS enumeration."},
        ],
        "quick_wins": [
            "Restart Jupyter with --ip=127.0.0.1 flag immediately.",
            "Set c.NotebookApp.token to a strong random token if public exposure is required.",
            "Add c.NotebookApp.password with argon2-hashed password via jupyter notebook password.",
        ],
        "architectural_changes": [
            "Deploy JupyterHub behind an OAuth2 proxy (oauth2-proxy + institutional SSO).",
            "Isolate notebook containers; no host network mode, no GPU passthrough without explicit auth.",
            "Restrict /api/terminals to admin-role users only via JupyterHub spawner config.",
        ],
        "template_guidance": [
            "All Jupyter deployments must configure token auth or OAuth2; --NotebookApp.token='' is forbidden.",
            "Notebook host template must not include cloud credential files in notebook working directory.",
            "GPU notebook deployments require VPN or SSO gate; direct Internet exposure is prohibited.",
        ],
    },

    # -----------------------------------------------------------------------
    "chat_uis": {
        "typical_platforms": ["Open WebUI", "LibreChat", "LobeChat", "ChatGPT-Next-Web", "BetterChatGPT"],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/signup",                     "notes": "Open registration page; immediate seat creation"},
            {"type": "http_path",      "pattern": "/api/v1/auths/signup",        "notes": "Open WebUI API signup; POST creates account"},
            {"type": "http_path",      "pattern": "/api/auth/register",          "notes": "LibreChat registration endpoint"},
            {"type": "http_path",      "pattern": "/api/v1/users",               "notes": "Open WebUI user list; may expose all registered users"},
            {"type": "http_path",      "pattern": "/api/v1/models",              "notes": "Accessible model list; may show all backend models"},
            {"type": "http_path",      "pattern": "/api/v1/documents",           "notes": "Open WebUI RAG document store; may list uploaded docs"},
            {"type": "http_path",      "pattern": "/api/v1/knowledge",           "notes": "Knowledge bases (RAG); listing = PII exposure risk"},
            {"type": "banner_pattern", "pattern": "Open WebUI",                  "notes": "Title confirms platform; check /api/v1/config for ENABLE_SIGNUP"},
        ],
        "http_probe_patterns": [
            {
                "description": "Open signup availability check",
                "methods": ["GET"],
                "paths": ["/signup", "/register", "/api/v1/auths/signup"],
                "headers": {},
                "notes": "GET /signup returning a registration form HTML (200) = open signup. GET /api/v1/config returning ENABLE_SIGNUP: true is the cleanest machine-readable signal.",
            },
            {
                "description": "User list enumeration",
                "methods": ["GET"],
                "paths": ["/api/v1/users", "/api/users"],
                "headers": {},
                "notes": "200 with user list before auth = IDOR; even auth-required list may be accessible with a freshly-created account.",
            },
            {
                "description": "RAG document and knowledge base enumeration",
                "methods": ["GET"],
                "paths": ["/api/v1/documents", "/api/v1/knowledge", "/api/v1/files"],
                "headers": {},
                "notes": "Exposed document lists reveal uploaded content; in multi-user orgs this is often multi-tenant PII.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/v1/config or /config to check ENABLE_SIGNUP, AUTH_TYPE, DEFAULT_USER_ROLE.",
            "2. If signup enabled, attempt to enumerate existing users via GET /api/v1/users before creating account.",
            "3. Create a test account if open signup confirmed; document what is accessible post-auth.",
            "4. As new user, GET /api/v1/documents, /api/v1/knowledge, /api/v1/files to check multi-tenant isolation.",
            "5. Check /api/v1/models to see if all backend models are accessible to any registered user.",
        ],
        "assets": [
            {"name": "rag_corpus",      "description": "Uploaded documents in RAG store; may contain org-confidential or PII data."},
            {"name": "user_identities", "description": "Registered user email list; IDOR on user list is a direct PII leak."},
            {"name": "model_access",    "description": "Any authenticated user may have access to all connected models."},
            {"name": "conversation_history", "description": "Stored chat history; if shared or globally accessible, cross-user data exposure."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Open signup allows external attacker to create an account and access all RAG documents as a legitimate user.",
                "related_categories": ["chat_uis"],
                "related_attack_paths": ["open_webui_open_signup_rag_seat"],
                "impact_if_confirmed": "high",
            },
            {
                "id": "H2",
                "description": "New-user account can list all documents in the knowledge base, exposing multi-tenant data.",
                "related_categories": ["chat_uis", "leaky_data_stores"],
                "related_attack_paths": ["open_webui_open_signup_rag_seat"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm open user registration is enabled.",
                "preconditions": ["Chat UI is Internet-accessible"],
                "steps_summary": [
                    "GET /api/v1/config or /config and inspect ENABLE_SIGNUP or equivalent field.",
                    "GET /signup or /register and confirm form is rendered without redirect to admin approval.",
                ],
                "expected_weak_signals": [
                    "ENABLE_SIGNUP: true in config response.",
                    "HTML signup form with email/password fields rendered on GET.",
                ],
                "severity_if_confirmed": "medium",
                "notes": "Open signup alone is medium; combined with accessible RAG corpus becomes critical.",
            },
            {
                "id": "TC2",
                "objective": "Enumerate document store accessibility to newly registered user.",
                "preconditions": ["TC1 confirmed open signup", "Account registered"],
                "steps_summary": [
                    "Authenticate with created credentials to get JWT token.",
                    "GET /api/v1/documents, /api/v1/knowledge, /api/v1/files with auth token.",
                    "Count document entries and sample metadata (filenames, upload dates, uploaders).",
                ],
                "expected_weak_signals": [
                    "Non-empty document list including files uploaded by other users.",
                    "Knowledge base names referencing confidential topics.",
                    "Document metadata with real usernames or email addresses.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Do not download document contents; filenames and metadata establish the finding.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Open WebUI Open Signup RAG Seat",
                "steps": ["TC1", "TC2"],
                "summary": "Confirm signup is open, register an attacker-controlled account, then enumerate the RAG document corpus accessible to that account. If multi-tenant documents are visible, any external user becomes a legitimate data exfiltration path.",
            },
        ],
        "logging_recommendations": [
            {"event": "account_created",       "fields": ["ip", "email", "timestamp", "user_agent"],       "notes": "Log all registrations; flag disposable email domains."},
            {"event": "document_list_access",  "fields": ["user_id", "ip", "doc_count", "timestamp"],      "notes": "Track how many docs each user can enumerate post-login."},
        ],
        "detection_ideas": [
            {"pattern": "Account created with disposable email domain", "severity": "high",   "notes": "Reconnaissance account creation."},
            {"pattern": "New account enumerates entire document list within 60s of signup", "severity": "critical", "notes": "Automated data exfiltration via RAG."},
        ],
        "quick_wins": [
            "Set ENABLE_SIGNUP=false and invite only, or require admin approval for new accounts.",
            "Restrict document visibility to the uploading user's workspace by default.",
        ],
        "architectural_changes": [
            "Implement workspace/tenant isolation in document store: users can only see docs they uploaded or were explicitly shared.",
            "Add SSO (SAML/OIDC) instead of local accounts; eliminates open self-registration entirely.",
        ],
        "template_guidance": [
            "Chat UI deployment baseline: ENABLE_SIGNUP must be false; use invite-only or SSO.",
            "RAG document isolation must be enforced at the data layer, not just the UI.",
        ],
    },

    # -----------------------------------------------------------------------
    "leaky_data_stores": {
        "typical_platforms": ["Weaviate", "Qdrant", "Chroma", "Milvus", "Pinecone (self-hosted)", "Elasticsearch+kNN"],
        "surface_elements": [
            {"type": "port",      "pattern": "8080",  "notes": "Weaviate REST default"},
            {"type": "port",      "pattern": "6333",  "notes": "Qdrant REST default"},
            {"type": "port",      "pattern": "8000",  "notes": "Chroma default"},
            {"type": "port",      "pattern": "19530", "notes": "Milvus gRPC default"},
            {"type": "port",      "pattern": "9200",  "notes": "Elasticsearch (used as vector store)"},
            {"type": "http_path", "pattern": "/v1/schema",           "notes": "Weaviate: full schema dump"},
            {"type": "http_path", "pattern": "/v1/objects",          "notes": "Weaviate: object listing; default limit returns first N records"},
            {"type": "http_path", "pattern": "/v1/graphql",          "notes": "Weaviate: GraphQL; arbitrary object queries"},
            {"type": "http_path", "pattern": "/v1/collections",      "notes": "Qdrant: collection list"},
            {"type": "http_path", "pattern": "/v1/collections/{name}/points", "notes": "Qdrant: point (vector+payload) retrieval"},
            {"type": "http_path", "pattern": "/api/v1/collections",  "notes": "Chroma: collection list"},
            {"type": "http_path", "pattern": "/api/v1/collections/{id}/get", "notes": "Chroma: document retrieval"},
        ],
        "http_probe_patterns": [
            {
                "description": "Schema enumeration - maps data model before any object access",
                "methods": ["GET"],
                "paths": ["/v1/schema", "/_cat/indices?v", "/api/v1/collections"],
                "headers": {},
                "notes": "Schema reveals class/field names. Fields like email, ssn, phone, patient_id, user_id indicate PII-class data. Class names like 'Document', 'Memory', 'Chunk' indicate RAG corpus.",
            },
            {
                "description": "Object sample retrieval",
                "methods": ["GET"],
                "paths": ["/v1/objects?limit=5", "/v1/collections/{name}/points?limit=5"],
                "headers": {},
                "notes": "Small sample (5 objects) is sufficient to confirm data class. Payload fields are the actual stored data. Vector values confirm embeddings are present but are not the sensitive element.",
            },
            {
                "description": "GraphQL unrestricted query (Weaviate)",
                "methods": ["POST"],
                "paths": ["/v1/graphql"],
                "headers": {"Content-Type": "application/json"},
                "notes": "POST a Get query for any class with a limit. Returns objects with all payload fields. No auth = arbitrary query without restriction.",
            },
        ],
        "mapping_strategy": [
            "1. Port scan for 6333, 8080, 8000, 19530; fingerprint response to confirm platform.",
            "2. GET schema or collection list to understand data model without touching records.",
            "3. Identify high-value classes (those with PII-indicative field names).",
            "4. Retrieve 1-5 sample objects from highest-value class only to confirm data class.",
            "5. Estimate total record count via schema totalCount or collection info endpoint.",
            "6. Document schema, record count, and field names; this is sufficient to establish severity.",
        ],
        "assets": [
            {"name": "rag_corpus_contents",  "description": "Embedded document chunks; may contain full text of org documents."},
            {"name": "user_pii",             "description": "Customer or patient records stored as vector payloads with raw field values."},
            {"name": "conversation_memory",  "description": "Agent conversation histories stored as embedding-searchable memory."},
            {"name": "proprietary_embeddings", "description": "Custom-model embeddings represent IP; extractable without model access."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Vector DB is exposed without API key; schema reveals PII-class field names; sample objects confirm unencrypted PII readable.",
                "related_categories": ["leaky_data_stores"],
                "related_attack_paths": ["flowise_to_weaviate_pii_dump"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Enumerate vector DB schema to identify PII-class collections.",
                "preconditions": ["Vector DB port accessible"],
                "steps_summary": [
                    "GET /v1/schema (Weaviate) or GET /v1/collections (Qdrant) or GET /api/v1/collections (Chroma).",
                    "Parse class/collection names and field names.",
                    "Flag fields matching PII patterns: email, name, phone, address, ssn, dob, patient, user.",
                ],
                "expected_weak_signals": [
                    "Schema contains classes with PII-indicative names.",
                    "No Authorization header required for schema access.",
                    "totalCount or vectors_count field indicates scale of stored data.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Schema alone is high. Confirm actual payload field values in TC2 for critical.",
            },
            {
                "id": "TC2",
                "objective": "Confirm PII is readable in object payloads without authentication.",
                "preconditions": ["TC1 identified PII-class collection"],
                "steps_summary": [
                    "Retrieve 3-5 sample objects from highest-risk class.",
                    "Inspect payload fields for real values (email addresses, names, medical terms).",
                    "Record field names and data class; do not retain actual PII values beyond what is needed for the finding.",
                ],
                "expected_weak_signals": [
                    "Payload contains actual email addresses or names.",
                    "Medical or financial field content confirms HIPAA/PCI-class data.",
                    "Document text field contains org-internal content (code, reports, internal comms).",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Critical if PII confirmed. Do not retrieve more than minimal sample needed to establish data class.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Leaky Vector DB PII Dump",
                "steps": ["TC1", "TC2"],
                "summary": "Schema dump to identify PII-class collections, then minimal object sampling to confirm data class. At this point unauth full-corpus access is established; regulatory notification may be required by the target org.",
            },
        ],
        "logging_recommendations": [
            {"event": "schema_access_external",   "fields": ["ip", "path", "timestamp"],       "notes": "Any external IP accessing schema endpoint."},
            {"event": "bulk_object_retrieval",    "fields": ["ip", "collection", "count"],      "notes": "Large limit query from external IP."},
        ],
        "detection_ideas": [
            {"pattern": "GET /v1/schema from external IP without API key", "severity": "critical", "notes": "Data enumeration in progress."},
            {"pattern": "GraphQL query with high limit (> 100) from external IP", "severity": "critical", "notes": "Bulk data exfiltration attempt."},
        ],
        "quick_wins": [
            "Enable Weaviate API key auth (AUTHENTICATION_APIKEY_ENABLED=true) immediately.",
            "Firewall vector DB ports (6333, 8080, 8000) to only application server IPs.",
        ],
        "architectural_changes": [
            "Deploy vector DB in a private subnet; application layer is the only network path to it.",
            "Implement record-level access control via Weaviate multi-tenancy or Qdrant collection-level API keys.",
        ],
        "template_guidance": [
            "Vector DB deployments must enable authentication before any data is loaded.",
            "Template network rules: 6333/8080/8000/19530 must not be reachable from Internet.",
        ],
    },

    # -----------------------------------------------------------------------
    "observability": {
        "typical_platforms": ["Langfuse", "MLflow", "Weights & Biases (self-hosted)", "Helicone (self-hosted)", "Langsmith (self-hosted)"],
        "surface_elements": [
            {"type": "port",      "pattern": "3000",  "notes": "Langfuse default"},
            {"type": "port",      "pattern": "5000",  "notes": "MLflow default"},
            {"type": "http_path", "pattern": "/api/public/projects",      "notes": "Langfuse: project list"},
            {"type": "http_path", "pattern": "/api/public/traces",        "notes": "Langfuse: LLM call trace log"},
            {"type": "http_path", "pattern": "/api/public/observations",  "notes": "Langfuse: per-step inputs/outputs"},
            {"type": "http_path", "pattern": "/api/2.0/mlflow/experiments/list", "notes": "MLflow: experiment list"},
            {"type": "http_path", "pattern": "/api/2.0/mlflow/runs/search",      "notes": "MLflow: run metadata and metrics"},
            {"type": "http_path", "pattern": "/#/",  "notes": "MLflow UI redirect; 200 = open web access"},
        ],
        "http_probe_patterns": [
            {
                "description": "Langfuse trace enumeration",
                "methods": ["GET"],
                "paths": ["/api/public/traces", "/api/public/observations"],
                "headers": {},
                "notes": "Traces contain full LLM inputs and outputs. Prompt content, user queries, model responses - all logged. No auth = complete conversation history exposure.",
            },
            {
                "description": "MLflow experiment and artifact access",
                "methods": ["GET"],
                "paths": ["/api/2.0/mlflow/experiments/list", "/api/2.0/mlflow/runs/search"],
                "headers": {},
                "notes": "Experiment names reveal ML projects; run artifacts may include model files, training data samples, evaluation results.",
            },
        ],
        "mapping_strategy": [
            "1. Fingerprint port 3000/5000 for Langfuse/MLflow via HTTP title or API response structure.",
            "2. GET /api/public/projects (Langfuse) or /api/2.0/mlflow/experiments/list (MLflow) without auth.",
            "3. If project list returns, sample trace/observation endpoint for one project.",
            "4. Inspect trace content for prompt content, PII in inputs, or API key values in outputs.",
            "5. For MLflow, check artifact URI paths for s3:// or gs:// paths; these may be directly accessible.",
        ],
        "assets": [
            {"name": "llm_call_logs",     "description": "Full input/output logs for every LLM call; may contain user PII, internal prompts, credentials."},
            {"name": "system_prompts_in_traces", "description": "System prompts logged per-call; reveals operational instructions."},
            {"name": "model_artifacts",   "description": "MLflow logged model files, training datasets, evaluation sets."},
            {"name": "api_keys_in_traces","description": "Provider API keys sometimes logged inadvertently in trace metadata or env vars."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Observability platform is open; LLM call traces expose user queries, model responses, and potentially provider keys in plaintext.",
                "related_categories": ["observability", "key_abuse"],
                "related_attack_paths": [],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm unauthenticated access to LLM trace logs.",
                "preconditions": ["Observability port reachable"],
                "steps_summary": [
                    "GET /api/public/traces (Langfuse) or /api/public/observations.",
                    "Inspect trace content fields: input, output, metadata, model.",
                    "Flag any credential-shaped values in metadata or output fields.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with trace array containing input/output fields.",
                    "Trace metadata with user-identifying information.",
                    "Output fields containing real LLM responses indicating live inference.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Even metadata exposure (model names, timestamps, latency) combined with scale is a finding. Full trace content = critical.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Observability Platform Trace Harvest",
                "steps": ["TC1"],
                "summary": "Access open observability platform; enumerate trace logs to extract user conversations, system prompts, and potentially credentials embedded in trace metadata.",
            },
        ],
        "logging_recommendations": [
            {"event": "trace_access_external",  "fields": ["ip", "trace_count", "project_id"], "notes": "Any external access to trace endpoints."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/public/traces without auth from external IP", "severity": "critical", "notes": "Active log exfiltration."},
        ],
        "quick_wins": [
            "Enable Langfuse auth (NEXTAUTH_SECRET + DATABASE_URL auth required); restart immediately.",
            "Firewall port 3000/5000 to application-only subnet.",
        ],
        "architectural_changes": [
            "Deploy observability platform on internal network only; no public route.",
            "Implement RBAC on trace access: only the owning project members can see traces.",
        ],
        "template_guidance": [
            "Observability deployments must not expose trace APIs publicly; internal-only routing required.",
            "Trace retention policy must account for PII in LLM inputs/outputs; apply data masking at ingest.",
        ],
    },

    # -----------------------------------------------------------------------
    "agent_surfaces": {
        "typical_platforms": ["Flowise", "LangServe", "OpenHands", "n8n", "Dify", "AutoGPT (self-hosted)"],
        "surface_elements": [
            {"type": "http_path", "pattern": "/api/v1/chatflows",   "notes": "Flowise: flow inventory; reveals agent topology"},
            {"type": "http_path", "pattern": "/api/v1/credentials", "notes": "Flowise: stored credentials; may return decrypted values"},
            {"type": "http_path", "pattern": "/api/v1/nodes",       "notes": "Flowise: available node types; fingerprints capabilities"},
            {"type": "http_path", "pattern": "/app",                "notes": "LangServe: deployed chain listing"},
            {"type": "http_path", "pattern": "/playground",         "notes": "LangServe: interactive chain execution"},
            {"type": "http_path", "pattern": "/api/v1/info",        "notes": "OpenHands: instance config including auth mode"},
            {"type": "port",      "pattern": "3000",                "notes": "Flowise default"},
            {"type": "port",      "pattern": "8000",                "notes": "LangServe, Dify default"},
        ],
        "http_probe_patterns": [
            {
                "description": "Flowise chatflow and credential enumeration",
                "methods": ["GET"],
                "paths": ["/api/v1/chatflows", "/api/v1/credentials", "/api/v1/tools"],
                "headers": {},
                "notes": "Chatflows reveal full agent topology including connected vector stores, tools, and upstream API endpoints. Credentials endpoint may return actual key values if encryption is weak.",
            },
            {
                "description": "Agent execution without auth",
                "methods": ["POST"],
                "paths": ["/api/v1/prediction/{flow_id}", "/api/v1/chatflows/{id}/message"],
                "headers": {"Content-Type": "application/json"},
                "notes": "POST to prediction endpoint with flow ID from enumeration; successful response = agent execution without auth. Full tool-use capabilities are available.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/v1/chatflows without auth; list all agent flows.",
            "2. GET /api/v1/credentials; check if values are returned decrypted.",
            "3. GET /api/v1/nodes to understand tool surface (code execution, web access, DB access nodes).",
            "4. POST to prediction endpoint for a simple flow to confirm unauthenticated agent execution.",
            "5. Map connected external resources (vector stores, LLMs, databases) from flow configs.",
        ],
        "assets": [
            {"name": "agent_credentials",  "description": "API keys and connection strings stored in agent platform; Flowise may return these decrypted."},
            {"name": "tool_access",        "description": "Agents with code execution, web browsing, or DB access tools = arbitrary capability."},
            {"name": "connected_systems",  "description": "Agent flows reveal integration map: which DBs, APIs, and internal services are reachable."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Agent platform exposes flow configs and credentials without auth; attacker gains full knowledge of connected system topology.",
                "related_categories": ["agent_surfaces", "key_abuse"],
                "related_attack_paths": ["flowise_to_weaviate_pii_dump"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Enumerate agent flows and identify connected external resources.",
                "preconditions": ["Agent platform port reachable"],
                "steps_summary": [
                    "GET /api/v1/chatflows to list all flows.",
                    "GET individual flow details for each flow ID.",
                    "Extract node types and their configuration (API endpoints, vector store hosts, DB connection strings).",
                ],
                "expected_weak_signals": [
                    "Flow configs containing host names or IP addresses of connected services.",
                    "Node types indicating code execution capability (Python tool, JS tool).",
                    "Credential node references indicating stored secrets.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Flow topology alone is high; confirms connected system map. Combined with credential access = critical.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Agent Surface to Connected System Pivot",
                "steps": ["TC1"],
                "summary": "Enumerate agent flows to extract connected system topology, then use credential disclosure or unauthenticated execution to pivot into connected vector stores, databases, or LLM backends.",
            },
        ],
        "logging_recommendations": [
            {"event": "chatflow_list_external",  "fields": ["ip", "flow_count", "timestamp"],     "notes": "External IP accessing flow inventory."},
            {"event": "agent_execution_no_auth", "fields": ["ip", "flow_id", "input_length"],     "notes": "Unauthenticated agent execution."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/v1/chatflows from external IP without auth", "severity": "high",     "notes": "Topology enumeration."},
            {"pattern": "POST to prediction endpoint without auth token",      "severity": "critical", "notes": "Unauthenticated agent execution."},
        ],
        "quick_wins": [
            "Enable Flowise username/password auth (FLOWISE_USERNAME, FLOWISE_PASSWORD env vars).",
            "Remove credential node decryption from API responses; return credential ID only.",
        ],
        "architectural_changes": [
            "Implement per-flow access control; not all users should be able to execute all flows.",
            "Deploy agent platform in internal-only network segment; no public route.",
        ],
        "template_guidance": [
            "Agent platform deployments must have auth enabled before any flows are created.",
            "Credential storage must use envelope encryption; raw key values must never appear in API responses.",
        ],
    },

    # -----------------------------------------------------------------------
    "key_abuse": {
        "typical_platforms": ["LiteLLM", "Flowise", "Langfuse", "Open WebUI", "any platform with .env"],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/config",           "notes": "Config dump endpoints frequently include key_name or api_key fields"},
            {"type": "http_path",      "pattern": "/.env",             "notes": "Exposed dotenv file if web server misconfigured"},
            {"type": "http_path",      "pattern": "/api/v1/credentials","notes": "Flowise credential store; may return plaintext values"},
            {"type": "http_path",      "pattern": "/metrics",          "notes": "Provider key identity inferable from model names in labels"},
            {"type": "banner_pattern", "pattern": "sk-",               "notes": "OpenAI key prefix in any response body"},
            {"type": "banner_pattern", "pattern": "ANTHROPIC_API_KEY", "notes": "Key env var name leaked in config or error response"},
        ],
        "http_probe_patterns": [
            {
                "description": "Dotenv and config file exposure",
                "methods": ["GET"],
                "paths": ["/.env", "/.env.local", "/config.yaml", "/config.json", "/app.config.js"],
                "headers": {},
                "notes": "Web servers with misconfigured document root may serve .env files. 200 with key-value pairs = direct credential harvest.",
            },
        ],
        "mapping_strategy": [
            "1. Scan for .env, config.yaml, config.json at web root.",
            "2. Check error responses for stack traces containing env var names.",
            "3. Enumerate /config, /admin endpoints for key-shaped fields.",
            "4. Infer key class from model names in metrics or /v1/models response.",
        ],
        "assets": [
            {"name": "provider_api_keys", "description": "OpenAI, Anthropic, Cohere, Google keys; each enables billing fraud and data access."},
            {"name": "db_connection_strings", "description": "Often co-located with API keys in .env; direct DB access."},
            {"name": "oauth_client_secrets",  "description": "SSO integration secrets; may allow session forgery."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Provider API keys are accessible via config or .env endpoint exposure.",
                "related_categories": ["key_abuse"],
                "related_attack_paths": ["open_gateway_llmjacking"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Check for .env and config file exposure at web root.",
                "preconditions": ["Web server accessible on target port"],
                "steps_summary": [
                    "GET /.env, /.env.local, /.env.production.",
                    "GET /config.yaml, /config.json.",
                    "Inspect 200 responses for key-value pairs matching credential patterns.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 with text/plain or text/yaml Content-Type for .env paths.",
                    "OPENAI_API_KEY=, ANTHROPIC_API_KEY= lines in response body.",
                    "DATABASE_URL= with embedded credentials.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Any confirmed key in a 200 response is immediately critical. Do not test key validity after confirming format.",
            },
        ],
        "attack_chains": [],
        "logging_recommendations": [
            {"event": "env_file_access",  "fields": ["ip", "path", "status", "response_size"], "notes": "GET /.env from any external IP."},
        ],
        "detection_ideas": [
            {"pattern": "GET /.env returns 200", "severity": "critical", "notes": "Direct credential exposure."},
        ],
        "quick_wins": [
            "Add location ~* /\\.env { deny all; } block to nginx config immediately.",
            "Rotate any key that appeared in a web-accessible response.",
        ],
        "architectural_changes": [
            "Move all secrets to a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager); remove .env files from server filesystem.",
        ],
        "template_guidance": [
            "Deployment template must deny direct access to dotenv files at the reverse proxy layer.",
            "Secrets must be injected at runtime from secrets manager; no .env files in container images.",
        ],
    },
}


# ---------------------------------------------------------------------------
# PLATFORM PLAYBOOK
# ---------------------------------------------------------------------------

PLATFORM_PLAYBOOK: dict = {

    "LiteLLM": {
        "related_category": "open_gateways",
        "typical_ports": [4000, 8000],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/v1/models",       "notes": "Model list; open = LLMjacking surface"},
            {"type": "http_path",      "pattern": "/health/liveliness","notes": "Health probe; version in response"},
            {"type": "http_path",      "pattern": "/config",          "notes": "Admin config dump; may contain key names"},
            {"type": "http_path",      "pattern": "/v1/spend/logs",   "notes": "Spend tracking; usage patterns"},
            {"type": "banner_pattern", "pattern": "litellm",          "notes": "HTTP response body or title"},
        ],
        "assets": [
            {"name": "provider_api_keys", "description": "Keys for all configured upstream providers."},
            {"name": "virtual_key_pool",  "description": "Per-user virtual keys that map to real provider keys."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "LiteLLM deployed without LITELLM_MASTER_KEY or with default; model list and inference are open.",
                "related_categories": ["open_gateways", "key_abuse"],
                "related_attack_paths": ["open_gateway_llmjacking"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm no master key protection on /v1/models.",
                "preconditions": ["Port 4000 or 8000 reachable"],
                "steps_summary": [
                    "GET /v1/models without Authorization header.",
                    "GET /health/liveliness for version.",
                    "GET /config for key presence indicators.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on /v1/models with model list.",
                    "/health/liveliness returns {status: 'healthy'} with version.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Verify LITELLM_MASTER_KEY is absent by checking if garbage token also returns 200.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "LiteLLM Open Proxy LLMjacking",
                "steps": ["TC1"],
                "summary": "Confirm open model list and inference; use provider models for attacker inference at zero cost.",
            },
        ],
        "logging_recommendations": [
            {"event": "model_list_no_key",   "fields": ["ip", "user_agent", "timestamp"], "notes": "Any access without Authorization."},
        ],
        "detection_ideas": [
            {"pattern": "GET /v1/models without Authorization returns 200", "severity": "critical", "notes": "Open LiteLLM proxy."},
        ],
        "quick_wins": ["Set LITELLM_MASTER_KEY environment variable and restart immediately."],
        "architectural_changes": ["Place LiteLLM behind VPN; never expose port 4000 publicly."],
        "template_guidance": ["LiteLLM template must include LITELLM_MASTER_KEY; absent key = deployment failure."],
    },

    "Flowise": {
        "related_category": "agent_surfaces",
        "typical_ports": [3000],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/api/v1/chatflows",   "notes": "Flow inventory; entire agent topology"},
            {"type": "http_path",      "pattern": "/api/v1/credentials", "notes": "Stored credentials; may return plaintext"},
            {"type": "http_path",      "pattern": "/api/v1/nodes",       "notes": "Available node types; capabilities fingerprint"},
            {"type": "banner_pattern", "pattern": "Flowise",             "notes": "HTTP title confirms platform"},
        ],
        "assets": [
            {"name": "flow_credentials",  "description": "API keys and connection strings stored in credential nodes."},
            {"name": "vector_store_hosts","description": "Weaviate/Qdrant/Chroma hosts referenced in flow configs."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Flowise deployed without FLOWISE_USERNAME/PASSWORD; chatflows and credentials accessible to anyone.",
                "related_categories": ["agent_surfaces", "key_abuse"],
                "related_attack_paths": ["flowise_to_weaviate_pii_dump"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Enumerate Flowise chatflows and extract connected resource map.",
                "preconditions": ["Port 3000 reachable"],
                "steps_summary": [
                    "GET /api/v1/chatflows without auth.",
                    "For each flow, inspect node configs for external host references.",
                    "GET /api/v1/credentials; check if values are returned.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on /api/v1/chatflows with flow list.",
                    "Node configs containing host:port references to vector stores.",
                    "/api/v1/credentials returning credential objects with populated value fields.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Vector store hosts from flow configs are the pivot point to leaky_data_stores chain.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Flowise to Weaviate PII Dump",
                "steps": ["TC1"],
                "summary": "Extract Weaviate host from Flowise flow config, then access Weaviate directly for schema dump and object retrieval.",
            },
        ],
        "logging_recommendations": [
            {"event": "chatflow_list_access", "fields": ["ip", "path", "timestamp", "flow_count"], "notes": "External access to flow inventory."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/v1/chatflows from external IP without auth", "severity": "high", "notes": "Topology reconnaissance."},
        ],
        "quick_wins": ["Set FLOWISE_USERNAME and FLOWISE_PASSWORD and restart immediately."],
        "architectural_changes": ["Credential nodes must return ID only, never values, via API."],
        "template_guidance": ["Flowise deployment must include auth env vars; unauthenticated template is rejected."],
    },

    "OpenHands": {
        "related_category": "agent_surfaces",
        "typical_ports": [3000, 3001],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/api/options/config",            "notes": "Runtime config incl APP_MODE; APP_MODE=oss means single-user OSS mode with no login enforced"},
            {"type": "http_path",      "pattern": "/api/settings",                  "notes": "Agent LLM settings: llm_model, llm_base_url, whether llm_api_key is set, agent, confirmation_mode"},
            {"type": "http_path",      "pattern": "/api/options/models",            "notes": "Model IDs the instance can route to"},
            {"type": "http_path",      "pattern": "/api/options/agents",            "notes": "Agent classes; CodeActAgent = code-execution capable"},
            {"type": "http_path",      "pattern": "/api/options/security-analyzers","notes": "Configured analyzers; empty = no guardrail on agent actions"},
            {"type": "http_path",      "pattern": "/api/conversations",             "notes": "Stored conversation/session list; existence = prior agent runs recoverable"},
            {"type": "http_path",      "pattern": "/config.json",                   "notes": "Frontend runtime config blob"},
            {"type": "banner_pattern", "pattern": "OpenHands",                      "notes": "SPA title / favicon mmh3 -1222104632 confirm platform; note the SPA returns 200 for unknown /api paths (catchall)"},
        ],
        "assets": [
            {"name": "upstream_model_backend", "description": "llm_base_url from settings points at the model runtime (often an internal Ollama/vLLM/LiteLLM); the public agent surface is the path to it."},
            {"name": "agent_code_execution",   "description": "OpenHands runs a code-acting agent in a sandbox; an open instance with confirmation_mode off is an unauthenticated code-execution surface."},
            {"name": "provider_api_key_state",  "description": "settings reveals whether llm_api_key is set; a configured key on an open instance is abusable inference spend."},
            {"name": "conversation_history",    "description": "Prior agent conversations may hold source code, secrets, and internal context."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "OpenHands runs in APP_MODE=oss with no login; /api/settings and /api/options/* are readable without auth.",
                "related_categories": ["agent_surfaces"],
                "related_attack_paths": [],
                "impact_if_confirmed": "high",
            },
            {
                "id": "H2",
                "description": "settings leaks an internal model backend (llm_base_url on an RFC1918 or docker host), bridging the public agent surface to a runtime that is not itself exposed.",
                "related_categories": ["agent_surfaces", "exposed_model_runtimes"],
                "related_attack_paths": ["ollama_11434_host_takeover"],
                "impact_if_confirmed": "high",
            },
            {
                "id": "H3",
                "description": "Open instance offers a code-acting agent (CodeActAgent) with confirmation_mode off and no security analyzer, i.e. unauthenticated code execution.",
                "related_categories": ["agent_surfaces"],
                "related_attack_paths": [],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "OH-TC1",
                "objective": "Confirm the instance serves config without authentication and read its auth mode.",
                "preconditions": ["Port 3000/3001 reachable", "Authorization scope confirmed for this host"],
                "steps_summary": [
                    "GET /api/options/config with no Authorization header.",
                    "Read APP_MODE from the JSON body.",
                ],
                "expected_weak_signals": [
                    "JSON body contains \"APP_MODE\".",
                    "APP_MODE value indicates single-user OSS mode (no login).",
                ],
                "severity_if_confirmed": "medium",
                "notes": "Anchor on the APP_MODE JSON field, never a bare 200: the SPA returns 200 for unknown paths, so only a distinctive JSON field token confirms a real API read.",
            },
            {
                "id": "OH-TC2",
                "objective": "Read agent settings and confirm leakage of the upstream model backend.",
                "preconditions": ["OH-TC1 indicates an open instance"],
                "steps_summary": [
                    "GET /api/settings with no Authorization header.",
                    "Read llm_model, llm_base_url, and whether llm_api_key is set.",
                ],
                "expected_weak_signals": [
                    "JSON body contains \"llm_base_url\".",
                    "JSON body contains \"llm_model\".",
                ],
                "severity_if_confirmed": "high",
                "notes": "llm_base_url is the pivot: an internal host:port here bridges the public surface to a runtime that is not itself exposed. Record the value; do not call the backend.",
            },
            {
                "id": "OH-TC3",
                "objective": "Enumerate agent classes to scope capability (code execution ceiling).",
                "preconditions": ["OH-TC1 indicates an open instance"],
                "steps_summary": [
                    "GET /api/options/agents with no Authorization header.",
                    "Note whether a code-acting agent (CodeActAgent) is offered.",
                ],
                "expected_weak_signals": [
                    "JSON body contains \"CodeActAgent\".",
                ],
                "severity_if_confirmed": "medium",
                "notes": "A CodeActAgent offering plus an open instance is the unauth-code-execution ceiling; do not exercise it. Capability scoping only.",
            },
            {
                "id": "OH-TC4",
                "objective": "Check whether prior conversations/sessions are listable without auth.",
                "preconditions": ["OH-TC1 indicates an open instance"],
                "steps_summary": [
                    "GET /api/conversations with no Authorization header.",
                    "Note whether IDs/metadata are returned.",
                ],
                "expected_weak_signals": [
                    "JSON body contains \"conversation_id\".",
                ],
                "severity_if_confirmed": "high",
                "notes": "Existence of recoverable sessions is the data-exposure leg. Read metadata only; do not open a conversation.",
            },
        ],
        "attack_chains": [
            {
                "id": "OH-AC1",
                "name": "Open OpenHands Agent Surface to Internal Backend",
                "steps": ["OH-TC1", "OH-TC2", "OH-TC3"],
                "summary": "Confirm the agent UI is unauthenticated (APP_MODE=oss), read settings to recover the upstream model backend and key state, then scope agent capability. The open public surface is the bridge to a model runtime that is usually not reachable on its own.",
            },
        ],
        "logging_recommendations": [
            {"event": "settings_read_no_auth", "fields": ["ip", "path", "status", "user_agent", "timestamp"], "notes": "GET /api/settings or /api/options/* from an external IP with no session is reconnaissance."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/settings returns a JSON body to an external IP with no session", "severity": "high", "notes": "Open OpenHands settings leak; the response carries the upstream backend URL."},
            {"pattern": "GET /api/options/config reachable from the internet with APP_MODE=oss", "severity": "high", "notes": "Instance is running single-user OSS mode with no login on a public interface."},
        ],
        "quick_wins": [
            "Put the instance behind authentication; never expose APP_MODE=oss on a public interface.",
            "Bind OpenHands to loopback or an internal VLAN and reach it over VPN.",
            "Leave confirmation_mode on and set a security analyzer so agent actions are gated.",
        ],
        "architectural_changes": [
            "Keep the model backend (llm_base_url) on an internal network only; the agent process should be its sole client.",
            "Run the agent runtime in a sandbox with no host network and no credentials beyond a single scoped provider key.",
        ],
        "template_guidance": [
            "OpenHands deployment template must enforce auth in front of port 3000; an unauthenticated APP_MODE=oss instance on a public interface is a deployment failure.",
            "Provider keys belong in a secrets store injected at runtime, never returned by an unauthenticated settings endpoint.",
        ],
    },

    "JupyterHub": {
        "related_category": "notebooks",
        "typical_ports": [8000, 8888],
        "surface_elements": [
            {"type": "http_path", "pattern": "/hub/api/users",          "notes": "User list; admin-only but check unauth access"},
            {"type": "http_path", "pattern": "/hub/api/authorizations", "notes": "Token validation endpoint; probing reveals auth config"},
            {"type": "http_path", "pattern": "/user/{username}/api/kernels", "notes": "Per-user kernel API; check if other users' kernels accessible"},
        ],
        "assets": [
            {"name": "per_user_servers",  "description": "Each JupyterHub user has an isolated server; IDOR may cross boundaries."},
            {"name": "hub_admin_token",   "description": "JupyterHub admin API token; compromise = all user data access."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "JupyterHub is deployed with null authenticator or allows anonymous spawning; any user can get a server.",
                "related_categories": ["notebooks"],
                "related_attack_paths": ["open_jupyter_gpu_rce"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm JupyterHub authenticator type and anonymous access.",
                "preconditions": ["Port 8000 or 8888 reachable"],
                "steps_summary": [
                    "GET / and check for login redirect vs direct notebook access.",
                    "Check for NullAuthenticator by attempting GET /hub/api without credentials.",
                    "If PAMAuthenticator, check for default or weak credentials.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on / without any authentication challenge.",
                    "NullAuthenticator in hub config (inferred from no-auth access).",
                    "Hub admin panel accessible without token.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "NullAuthenticator is a known misconfig in teaching deployments that sometimes reach production.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "JupyterHub GPU RCE",
                "steps": ["TC1"],
                "summary": "Confirm open access, spawn server, execute arbitrary code in GPU-attached environment.",
            },
        ],
        "logging_recommendations": [
            {"event": "hub_server_spawn",  "fields": ["username", "ip", "server_url", "timestamp"], "notes": "All server spawns, especially from external IPs."},
        ],
        "detection_ideas": [
            {"pattern": "Anonymous server spawn via NullAuthenticator from external IP", "severity": "critical", "notes": "Immediate GPU misuse."},
        ],
        "quick_wins": ["Replace NullAuthenticator with PAMAuthenticator or OAuth2 immediately."],
        "architectural_changes": ["Deploy JupyterHub with institutional SSO (SAML/OIDC); no local account creation."],
        "template_guidance": ["JupyterHub template must specify authenticator class; NullAuthenticator is banned."],
    },

    "Ollama": {
        "related_category": "exposed_model_runtimes",
        "typical_ports": [11434],
        "surface_elements": [
            {"type": "port",           "pattern": "11434",          "notes": "Default; TCP open without auth"},
            {"type": "http_path",      "pattern": "/api/tags",      "notes": "Model list"},
            {"type": "http_path",      "pattern": "/api/ps",        "notes": "Running processes"},
            {"type": "http_path",      "pattern": "/api/generate",  "notes": "Unauthenticated inference"},
            {"type": "http_path",      "pattern": "/api/pull",      "notes": "Arbitrary model pull"},
            {"type": "banner_pattern", "pattern": "Ollama is running", "notes": "Root path response body"},
        ],
        "assets": [
            {"name": "gpu_compute",    "description": "GPU resources; open port = compute theft."},
            {"name": "model_weights",  "description": "Locally stored models; may include fine-tuned proprietary variants."},
            {"name": "system_prompts", "description": "Modelfile system prompts reveal deployment context."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Ollama binds to 0.0.0.0 by default; any Internet host can invoke inference and drain GPU.",
                "related_categories": ["exposed_model_runtimes"],
                "related_attack_paths": ["ollama_11434_host_takeover"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm Ollama is Internet-accessible and enumerate installed models.",
                "preconditions": ["Port 11434 reachable"],
                "steps_summary": [
                    "GET http://target:11434/ and check for 'Ollama is running'.",
                    "GET /api/tags to list installed models.",
                    "GET /api/ps to check active model loads.",
                ],
                "expected_weak_signals": [
                    "'Ollama is running' in response body.",
                    "models[] array with entries.",
                    "Running model processes with GPU memory allocation.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Confirmed external Ollama access is critical without requiring inference verification.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Ollama 11434 Host Takeover",
                "steps": ["TC1"],
                "summary": "Confirm open port, enumerate models and system prompts, verify unauthenticated inference, then test model pull to establish persistent host access.",
            },
        ],
        "logging_recommendations": [
            {"event": "ollama_external_access", "fields": ["ip", "path", "method", "timestamp"], "notes": "Any non-loopback access."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/tags from external IP", "severity": "critical", "notes": "Exposed Ollama."},
        ],
        "quick_wins": ["Set OLLAMA_HOST=127.0.0.1 in systemd unit; restart ollama.service."],
        "architectural_changes": ["Deploy behind auth reverse proxy; isolate GPU host on private subnet."],
        "template_guidance": ["Ollama host template must set OLLAMA_HOST=127.0.0.1; 0.0.0.0 binding is prohibited."],
    },

    "Weaviate": {
        "related_category": "leaky_data_stores",
        "typical_ports": [8080],
        "surface_elements": [
            {"type": "port",      "pattern": "8080",             "notes": "Weaviate REST default"},
            {"type": "http_path", "pattern": "/v1/schema",       "notes": "Full schema dump; class names and field names"},
            {"type": "http_path", "pattern": "/v1/objects",      "notes": "Object retrieval; payload = actual stored data"},
            {"type": "http_path", "pattern": "/v1/graphql",      "notes": "Arbitrary query with no auth"},
            {"type": "http_path", "pattern": "/v1/.well-known/openid-configuration", "notes": "OIDC config; presence = auth configured"},
            {"type": "http_path", "pattern": "/v1/meta",         "notes": "Instance metadata including version and modules"},
        ],
        "assets": [
            {"name": "vector_payloads", "description": "Stored document chunks, user records, or conversation history in payload fields."},
            {"name": "schema_topology", "description": "Class and field structure reveals data architecture."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Weaviate deployed without API key auth (default); full schema and object access without credentials.",
                "related_categories": ["leaky_data_stores"],
                "related_attack_paths": ["flowise_to_weaviate_pii_dump"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm unauthenticated schema and object access.",
                "preconditions": ["Port 8080 reachable"],
                "steps_summary": [
                    "GET /v1/schema without auth header.",
                    "Inspect class names and property types for PII indicators.",
                    "GET /v1/objects?limit=5 to sample actual records.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on /v1/schema with class definitions.",
                    "Property names matching PII patterns (email, name, patient_id).",
                    "Object payload fields containing real data values.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Confirm PII class from schema before sampling objects. Sample limit 5 is sufficient.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Weaviate Unauth PII Dump",
                "steps": ["TC1"],
                "summary": "Schema enumeration to identify PII-class data, then minimal object sampling to confirm unauth read access to user or patient records.",
            },
        ],
        "logging_recommendations": [
            {"event": "schema_access", "fields": ["ip", "path", "timestamp"], "notes": "External schema access."},
            {"event": "object_retrieval", "fields": ["ip", "class", "limit", "count"], "notes": "Object reads with class and scale."},
        ],
        "detection_ideas": [
            {"pattern": "GET /v1/schema from external IP without API key", "severity": "critical", "notes": "Data enumeration."},
        ],
        "quick_wins": [
            "Set AUTHENTICATION_APIKEY_ENABLED=true and AUTHENTICATION_APIKEY_ALLOWED_KEYS in Weaviate env.",
            "Firewall port 8080 to application-tier IPs only.",
        ],
        "architectural_changes": ["Deploy Weaviate in private subnet; no direct Internet route."],
        "template_guidance": ["Weaviate template must enable API key auth; unauthenticated template is rejected."],
    },

    "Langfuse": {
        "related_category": "observability",
        "typical_ports": [3000],
        "surface_elements": [
            {"type": "http_path", "pattern": "/api/public/projects",     "notes": "Project list; entry point to trace access"},
            {"type": "http_path", "pattern": "/api/public/traces",       "notes": "Full LLM call trace log with inputs/outputs"},
            {"type": "http_path", "pattern": "/api/public/observations", "notes": "Per-step inputs, outputs, metadata"},
            {"type": "http_path", "pattern": "/api/public/scores",       "notes": "Evaluation scores; confirms eval pipeline in place"},
        ],
        "assets": [
            {"name": "llm_trace_logs",    "description": "Complete input/output for every LLM call; PII likely in user-facing apps."},
            {"name": "system_prompts",    "description": "System prompts logged per-trace; operational instructions exposed."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Langfuse deployed without auth (NEXTAUTH_SECRET not set or default); trace logs with full conversation content readable.",
                "related_categories": ["observability"],
                "related_attack_paths": [],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm unauthenticated trace access.",
                "preconditions": ["Port 3000 reachable"],
                "steps_summary": [
                    "GET /api/public/projects without auth.",
                    "For first project, GET /api/public/traces.",
                    "Inspect trace input/output fields.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on /api/public/traces with trace array.",
                    "Input field containing user messages.",
                    "Output field containing model responses.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Trace content = complete conversation history. GDPR/HIPAA exposure likely.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Langfuse Open Trace Harvest",
                "steps": ["TC1"],
                "summary": "Access open Langfuse instance, enumerate project traces to harvest conversation history, system prompts, and user PII.",
            },
        ],
        "logging_recommendations": [
            {"event": "trace_access_external", "fields": ["ip", "project_id", "trace_count"], "notes": "External trace access."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/public/traces from external IP without auth", "severity": "critical", "notes": "Active trace harvest."},
        ],
        "quick_wins": ["Set NEXTAUTH_SECRET to a strong random value and restart Langfuse."],
        "architectural_changes": ["Deploy Langfuse on internal-only network; no public route."],
        "template_guidance": ["Langfuse template must require NEXTAUTH_SECRET; absent = deployment blocked."],
    },
}


# ---------------------------------------------------------------------------
# ATTACK PATH PLAYBOOK
# ---------------------------------------------------------------------------

ATTACK_PATH_PLAYBOOK: dict = {

    "open_gateway_llmjacking": {
        "related_category": "open_gateways",
        "related_platforms": ["LiteLLM", "One API", "OpenRouter-self-hosted"],
        "description": "Attacker discovers an Internet-exposed LLM proxy with no authentication or trivially weak auth. Provider API keys are consumed at the attacker's direction, resulting in billing fraud, model abuse, and potential key extraction.",
        "typical_platforms": ["LiteLLM", "One API", "OpenRouter-self-hosted", "LM Studio"],
        "surface_elements": [
            {"type": "http_path",      "pattern": "/v1/models",            "notes": "Open model list = entry confirmation"},
            {"type": "http_path",      "pattern": "/v1/chat/completions",  "notes": "Open inference = key abuse"},
            {"type": "http_path",      "pattern": "/config",               "notes": "Config dump = key extraction path"},
        ],
        "http_probe_patterns": [
            {
                "description": "Full LLMjacking probe sequence",
                "methods": ["GET", "POST"],
                "paths": ["/v1/models", "/v1/chat/completions", "/config"],
                "headers": {},
                "notes": "Confirm open model list, then unauthenticated inference, then config access. All three together = full LLMjacking chain confirmed.",
            },
        ],
        "mapping_strategy": [
            "1. Confirm open /v1/models (GET, no auth).",
            "2. Confirm inference passthrough (POST /v1/chat/completions, no auth, minimal payload).",
            "3. Probe /config for key names.",
            "4. Scrape /metrics for spend data confirming active billing.",
        ],
        "assets": [
            {"name": "provider_api_keys",     "description": "Keys for all configured upstream providers."},
            {"name": "billing_credit",        "description": "Provider billing credit consumed by attacker inference."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Proxy is fully open; attacker can consume all upstream API credits.",
                "related_categories": ["open_gateways", "key_abuse"],
                "related_attack_paths": ["open_gateway_llmjacking"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Complete LLMjacking chain confirmation: open models + open inference + config access.",
                "preconditions": ["Gateway port reachable"],
                "steps_summary": [
                    "GET /v1/models - confirm 200 with model list.",
                    "POST /v1/chat/completions without auth - confirm 200 with completion.",
                    "GET /config - look for key_name fields.",
                    "GET /metrics - confirm billing model names.",
                ],
                "expected_weak_signals": [
                    "All three endpoints return 200.",
                    "Model list includes provider-specific model IDs (gpt-*, claude-*, command-*).",
                    "Inference returns real generated text with non-trivial latency.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "This is the defining LLMjacking scenario. One confirmed open inference endpoint is sufficient for the critical label.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "LLMjacking Full Chain",
                "steps": ["TC1"],
                "summary": "Confirm open model list, verify unauthenticated inference passthrough, extract provider key metadata from config, then document billing drain potential from metrics.",
            },
        ],
        "logging_recommendations": [
            {"event": "unauthenticated_inference", "fields": ["ip", "model", "tokens", "timestamp"], "notes": "Every unauth inference request."},
        ],
        "detection_ideas": [
            {"pattern": "Multiple model completions from external IP without auth within 60s", "severity": "critical", "notes": "Active LLMjacking in progress."},
        ],
        "quick_wins": ["Require auth key on all /v1/* paths immediately via reverse proxy."],
        "architectural_changes": ["Move gateway behind VPN; never expose inference ports to Internet."],
        "template_guidance": ["Gateway template must enforce auth; no-auth deployment is rejected at CI."],
    },

    "ollama_11434_host_takeover": {
        "related_category": "exposed_model_runtimes",
        "related_platforms": ["Ollama"],
        "description": "Ollama binds to all interfaces by default. An Internet-exposed instance allows any host to enumerate installed models, invoke unauthenticated inference, pull arbitrary models, and potentially execute code via malicious modelfile instructions.",
        "typical_platforms": ["Ollama"],
        "surface_elements": [
            {"type": "port",           "pattern": "11434",          "notes": "Ollama default binding"},
            {"type": "http_path",      "pattern": "/api/tags",      "notes": "Model inventory"},
            {"type": "http_path",      "pattern": "/api/generate",  "notes": "Unauthenticated inference"},
            {"type": "http_path",      "pattern": "/api/pull",      "notes": "Arbitrary model load"},
        ],
        "http_probe_patterns": [
            {
                "description": "Ollama host takeover chain",
                "methods": ["GET", "POST"],
                "paths": ["/api/tags", "/api/generate", "/api/show", "/api/pull"],
                "headers": {"Content-Type": "application/json"},
                "notes": "Sequential: enumerate -> show system prompt -> generate -> test pull. Each step adds an impact tier.",
            },
        ],
        "mapping_strategy": [
            "1. Confirm 'Ollama is running' on GET /.",
            "2. GET /api/tags to list installed models.",
            "3. POST /api/show for each model to extract modelfile/system prompt.",
            "4. POST /api/generate for single-token confirmation of open inference.",
            "5. POST /api/pull to test arbitrary model load capability.",
        ],
        "assets": [
            {"name": "gpu_compute",    "description": "GPU resources commandeered for attacker inference."},
            {"name": "host_filesystem","description": "Ollama runs as system user; exploitable modelfile could access host FS."},
            {"name": "system_prompts", "description": "Modelfile system prompts reveal deployment context."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Ollama on 0.0.0.0:11434 with no auth; complete GPU commandeer and potential host pivot.",
                "related_categories": ["exposed_model_runtimes"],
                "related_attack_paths": ["ollama_11434_host_takeover"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm full Ollama host takeover chain.",
                "preconditions": ["Port 11434 reachable from external IP"],
                "steps_summary": [
                    "GET / - confirm 'Ollama is running'.",
                    "GET /api/tags - enumerate models.",
                    "POST /api/show - extract system prompts.",
                    "POST /api/generate - confirm unauthenticated inference.",
                    "POST /api/pull (optional, small model) - confirm arbitrary model load.",
                ],
                "expected_weak_signals": [
                    "Ollama running banner.",
                    "Non-empty model list.",
                    "Modelfile with populated SYSTEM block.",
                    "Generated text from inference probe.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Steps 1-4 are sufficient for critical; step 5 adds persistence dimension. Do not pull large models.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Ollama 11434 Takeover Chain",
                "steps": ["TC1"],
                "summary": "Confirm external Ollama exposure, extract system prompt context, verify unauthenticated inference, then test model pull to establish host manipulation capability.",
            },
        ],
        "logging_recommendations": [
            {"event": "ollama_external_inference", "fields": ["ip", "model", "eval_tokens", "timestamp"], "notes": "Any inference from non-RFC1918 IP."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/tags from external IP", "severity": "critical", "notes": "External Ollama enumeration."},
        ],
        "quick_wins": ["OLLAMA_HOST=127.0.0.1 in systemd unit; systemctl restart ollama."],
        "architectural_changes": ["Auth-enforcing reverse proxy on 11434; GPU host in private subnet."],
        "template_guidance": ["Ollama deployment template binds to 127.0.0.1 only; 0.0.0.0 requires security exception."],
    },

    "flowise_to_weaviate_pii_dump": {
        "related_category": "agent_surfaces",
        "related_platforms": ["Flowise", "Weaviate"],
        "description": "Open Flowise instance exposes chatflow configs containing Weaviate connection details. Attacker pivots from Flowise flow enumeration to direct Weaviate access, dumping PII-containing vector payloads without auth on either system.",
        "typical_platforms": ["Flowise", "Weaviate", "Qdrant"],
        "surface_elements": [
            {"type": "http_path", "pattern": "/api/v1/chatflows",   "notes": "Flowise flow list -> Weaviate host extraction"},
            {"type": "http_path", "pattern": "/api/v1/credentials", "notes": "Flowise credentials -> Weaviate API key (if any)"},
            {"type": "port",      "pattern": "8080",                "notes": "Weaviate REST on pivot target"},
            {"type": "http_path", "pattern": "/v1/schema",          "notes": "Weaviate schema dump"},
            {"type": "http_path", "pattern": "/v1/objects",         "notes": "Weaviate object retrieval"},
        ],
        "http_probe_patterns": [
            {
                "description": "Flowise -> Weaviate pivot chain",
                "methods": ["GET", "POST"],
                "paths": ["/api/v1/chatflows", "/api/v1/credentials", "/v1/schema", "/v1/objects"],
                "headers": {},
                "notes": "Flowise chatflow JSON contains weaviate.apiKey and weaviate.host. If weaviate.apiKey is empty, Weaviate is unauth. Extract host from flow config, then probe directly.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/v1/chatflows (Flowise); parse flow node configs for weaviate host/apiKey fields.",
            "2. GET /api/v1/credentials (Flowise); check if credential values returned include Weaviate key.",
            "3. Direct probe of Weaviate host from step 1: GET /v1/schema without auth.",
            "4. GET /v1/objects?limit=5 to sample records and confirm PII data class.",
            "5. Estimate total scale: GET /v1/meta or class totalCount from schema.",
        ],
        "assets": [
            {"name": "weaviate_vector_payloads", "description": "Full text of document chunks embedded in RAG pipeline."},
            {"name": "user_pii_records",          "description": "Customer/patient records stored as vector payloads."},
            {"name": "flowise_connected_systems",  "description": "All external systems reachable via Flowise node configs."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Flowise exposes Weaviate host and empty API key in flow config; Weaviate is unauth; full PII corpus accessible.",
                "related_categories": ["agent_surfaces", "leaky_data_stores"],
                "related_attack_paths": ["flowise_to_weaviate_pii_dump"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Extract Weaviate host from Flowise flow configs.",
                "preconditions": ["Flowise port 3000 reachable"],
                "steps_summary": [
                    "GET /api/v1/chatflows; inspect node configs for weaviate_url or host fields.",
                    "GET /api/v1/credentials; check for Weaviate credential entries.",
                    "Record Weaviate host address and any API key value (empty = unauth).",
                ],
                "expected_weak_signals": [
                    "Flow config JSON containing weaviateApiKey field (empty or populated).",
                    "Weaviate host IP or hostname in node config.",
                    "Credential entry for Weaviate with empty value field.",
                ],
                "severity_if_confirmed": "high",
                "notes": "Flowise access alone is high. Successful Weaviate pivot in TC2 = critical.",
            },
            {
                "id": "TC2",
                "objective": "Confirm unauthenticated Weaviate access and PII data class.",
                "preconditions": ["TC1 extracted Weaviate host"],
                "steps_summary": [
                    "GET http://{weaviate_host}:8080/v1/schema without auth.",
                    "Identify PII-class collections from field names.",
                    "GET /v1/objects?limit=3 from highest-risk class.",
                    "Document field names and data class (not actual PII values).",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on Weaviate schema endpoint from attacker IP.",
                    "Class property names matching PII schema.",
                    "Object payload fields containing real values.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "This completes the two-hop pivot: Flowise flow config -> Weaviate host -> unauth PII dump.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Flowise to Weaviate PII Dump",
                "steps": ["TC1", "TC2"],
                "summary": "Extract Weaviate host from open Flowise flow config, pivot to direct Weaviate REST API access, enumerate schema to identify PII-class collections, sample records to confirm data class. Two unauthenticated hops to complete PII corpus access.",
            },
        ],
        "logging_recommendations": [
            {"event": "chatflow_config_access", "fields": ["ip", "flow_id", "nodes_count"],    "notes": "Flow config read revealing internal hosts."},
            {"event": "weaviate_external_read",  "fields": ["ip", "class", "object_count"],    "notes": "Weaviate access from Flowise pivot."},
        ],
        "detection_ideas": [
            {"pattern": "Weaviate schema access from IP that recently accessed Flowise API", "severity": "critical", "notes": "Two-hop pivot chain."},
        ],
        "quick_wins": [
            "Enable Flowise auth immediately (FLOWISE_USERNAME + FLOWISE_PASSWORD).",
            "Enable Weaviate API key auth on same timeline.",
        ],
        "architectural_changes": [
            "Weaviate must only accept connections from Flowise application server IP; no Internet routing.",
            "Flowise credential store must not return raw values; ID reference only.",
        ],
        "template_guidance": [
            "Agent platform + vector DB co-deployment template: both services must have auth; network segment isolates vector DB from Internet.",
        ],
    },

    "open_webui_open_signup_rag_seat": {
        "related_category": "chat_uis",
        "related_platforms": ["Open WebUI", "LibreChat"],
        "description": "Open WebUI or similar chat UI has open user registration enabled. External attacker registers an account and gains access to the RAG document corpus and conversation history uploaded by internal users.",
        "typical_platforms": ["Open WebUI", "LibreChat", "LobeChat"],
        "surface_elements": [
            {"type": "http_path", "pattern": "/signup",                  "notes": "Open registration form"},
            {"type": "http_path", "pattern": "/api/v1/auths/signup",    "notes": "Open WebUI signup API"},
            {"type": "http_path", "pattern": "/api/v1/documents",       "notes": "RAG document corpus"},
            {"type": "http_path", "pattern": "/api/v1/knowledge",       "notes": "Knowledge bases"},
        ],
        "http_probe_patterns": [
            {
                "description": "Open signup and RAG access chain",
                "methods": ["GET", "POST"],
                "paths": ["/signup", "/api/v1/auths/signup", "/api/v1/documents", "/api/v1/knowledge"],
                "headers": {},
                "notes": "Check ENABLE_SIGNUP config flag first; if true, registration is open. Post-registration, enumerate document store with auth token from signup response.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/v1/config or /config; check ENABLE_SIGNUP value.",
            "2. If signup enabled, enumerate existing user count via /api/v1/users before registering.",
            "3. Register attacker account; capture JWT from response.",
            "4. GET /api/v1/documents with JWT; count and categorize accessible documents.",
            "5. GET /api/v1/knowledge to list knowledge bases.",
        ],
        "assets": [
            {"name": "rag_documents",        "description": "Uploaded files in RAG store; may include confidential org documents."},
            {"name": "knowledge_bases",      "description": "Organized knowledge collections; often more sensitive than ad-hoc uploads."},
            {"name": "conversation_history", "description": "Prior chat histories if globally accessible post-login."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Open signup + globally accessible RAG corpus = any external user becomes a legitimate insider with document access.",
                "related_categories": ["chat_uis", "leaky_data_stores"],
                "related_attack_paths": ["open_webui_open_signup_rag_seat"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm open signup is enabled.",
                "preconditions": ["Chat UI port reachable"],
                "steps_summary": [
                    "GET /api/v1/config; inspect ENABLE_SIGNUP.",
                    "GET /signup; confirm form renders without redirect.",
                ],
                "expected_weak_signals": ["ENABLE_SIGNUP: true in config.", "Signup form rendered on GET /signup."],
                "severity_if_confirmed": "medium",
                "notes": "Open signup alone is medium; critical requires TC2 confirming document access.",
            },
            {
                "id": "TC2",
                "objective": "Confirm cross-user RAG document visibility to new account.",
                "preconditions": ["TC1 confirmed open signup", "Account created"],
                "steps_summary": [
                    "Register with attacker-controlled email and password.",
                    "GET /api/v1/documents with returned JWT.",
                    "Count documents; flag any not uploaded by the test account.",
                ],
                "expected_weak_signals": [
                    "Non-empty document list immediately after account creation.",
                    "Document metadata referencing other usernames or emails.",
                    "Knowledge base names referencing confidential topics.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Cross-user document visibility is the critical condition. Empty document list post-signup = finding limited to open registration only.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Open Signup RAG Seat",
                "steps": ["TC1", "TC2"],
                "summary": "Confirm open user registration, register attacker account, enumerate RAG document corpus with new account credentials to confirm cross-user data visibility.",
            },
        ],
        "logging_recommendations": [
            {"event": "user_registered",       "fields": ["email", "ip", "timestamp", "domain"],    "notes": "All registrations; flag disposable email domains."},
            {"event": "document_list_new_user", "fields": ["user_id", "doc_count", "elapsed_seconds"], "notes": "Document enumeration within first 60s of new account."},
        ],
        "detection_ideas": [
            {"pattern": "New account enumerates > 10 documents within 60s of registration", "severity": "critical", "notes": "Automated RAG exfiltration."},
        ],
        "quick_wins": ["Set ENABLE_SIGNUP=false; use invite-only or SSO."],
        "architectural_changes": ["Implement workspace isolation at data layer; all documents private by default."],
        "template_guidance": ["Chat UI template: ENABLE_SIGNUP must be false or require admin approval."],
    },

    "open_jupyter_gpu_rce": {
        "related_category": "notebooks",
        "related_platforms": ["JupyterHub", "JupyterLab", "Jupyter Notebook"],
        "description": "Internet-exposed Jupyter instance without token or password auth. Attacker accesses kernel API, creates or attaches to a kernel, and executes arbitrary Python code with full GPU and filesystem access under the notebook user.",
        "typical_platforms": ["JupyterHub", "JupyterLab", "Jupyter Notebook", "Zeppelin"],
        "surface_elements": [
            {"type": "port",      "pattern": "8888",           "notes": "Jupyter classic default"},
            {"type": "http_path", "pattern": "/api/kernels",   "notes": "Kernel list; 200 = open"},
            {"type": "http_path", "pattern": "/api/terminals", "notes": "OS terminal; higher impact"},
            {"type": "http_path", "pattern": "/api/contents",  "notes": "Filesystem access"},
        ],
        "http_probe_patterns": [
            {
                "description": "Open Jupyter RCE chain",
                "methods": ["GET", "POST"],
                "paths": ["/api/kernels", "/api/terminals", "/api/contents"],
                "headers": {},
                "notes": "GET /api/kernels confirms open API. POST /api/kernels creates a new kernel for code execution. WebSocket to /api/kernels/{id}/channels runs code. GET /api/contents enumerates filesystem.",
            },
        ],
        "mapping_strategy": [
            "1. GET /api/kernels without token; 200 = open.",
            "2. GET /api/contents to enumerate filesystem for credentials.",
            "3. GET /api/terminals to check if OS shell is accessible without code execution.",
            "4. Optionally: create a kernel via POST /api/kernels and confirm WebSocket channel reachable.",
        ],
        "assets": [
            {"name": "gpu_compute",         "description": "GPU resources; arbitrary code execution = full GPU access."},
            {"name": "filesystem",          "description": "Notebook FS; may contain credentials, training data, source code."},
            {"name": "cloud_iam_metadata",  "description": "EC2/GCE IMDS reachable from notebook = cloud credential theft."},
            {"name": "network_pivot",       "description": "Notebook host on internal network = pivot into private subnet."},
        ],
        "hypotheses": [
            {
                "id": "H1",
                "description": "Open Jupyter with kernel API exposed; arbitrary Python execution at notebook user privilege, GPU access, filesystem and network pivot.",
                "related_categories": ["notebooks"],
                "related_attack_paths": ["open_jupyter_gpu_rce"],
                "impact_if_confirmed": "critical",
            },
        ],
        "test_cases": [
            {
                "id": "TC1",
                "objective": "Confirm open kernel API and filesystem enumeration.",
                "preconditions": ["Port 8888 reachable"],
                "steps_summary": [
                    "GET /api/kernels; confirm 200 and inspect running kernel list.",
                    "GET /api/contents; enumerate root directory.",
                    "Flag credential-indicative filenames in filesystem listing.",
                ],
                "expected_weak_signals": [
                    "HTTP 200 on /api/kernels without Authorization or token param.",
                    "Filesystem listing including .env, .pem, credentials.json, .aws, .ssh.",
                    "Running kernel entries indicating active user sessions.",
                ],
                "severity_if_confirmed": "critical",
                "notes": "Open kernel API is immediately critical. Filesystem enumeration adds credential theft dimension.",
            },
        ],
        "attack_chains": [
            {
                "id": "AC1",
                "name": "Open Jupyter GPU RCE",
                "steps": ["TC1"],
                "summary": "Confirm open kernel API, enumerate filesystem for credentials, establish code execution capability via kernel WebSocket. GPU compute, filesystem, and network pivot all in scope.",
            },
        ],
        "logging_recommendations": [
            {"event": "kernel_access_external",  "fields": ["ip", "kernel_id", "timestamp"],    "notes": "Any kernel access from non-internal IP."},
            {"event": "terminal_open_external",  "fields": ["ip", "terminal_id"],               "notes": "OS terminal from external IP; P0."},
        ],
        "detection_ideas": [
            {"pattern": "GET /api/kernels 200 from external IP", "severity": "critical", "notes": "Open Jupyter exposure."},
            {"pattern": "POST /api/kernels from external IP (kernel creation)", "severity": "critical", "notes": "RCE initiation."},
        ],
        "quick_wins": [
            "Restart Jupyter with --ip=127.0.0.1 or set JUPYTER_ALLOW_INSECURE_WRITES=0.",
            "Set a strong token: jupyter notebook --NotebookApp.token=<random>.",
        ],
        "architectural_changes": [
            "Deploy JupyterHub with OAuth2 or SAML; no direct notebook exposure.",
            "Isolate notebook containers; no host network, no host FS mounts with credentials.",
        ],
        "template_guidance": [
            "All notebook deployments must require auth; --NotebookApp.token='' is a deployment-blocking misconfiguration.",
            "GPU notebook host must not have cloud credential files in notebook working directory.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Routing helpers used by operator.py
# ---------------------------------------------------------------------------

def get_playbook_entry(focus_type: str, focus_value: str) -> dict:
    """Return the playbook dict for a given focus type and value."""
    if focus_type == "category":
        return CATEGORY_PLAYBOOK.get(focus_value, {})
    elif focus_type == "platform":
        return PLATFORM_PLAYBOOK.get(focus_value, {})
    elif focus_type == "attack_path":
        return ATTACK_PATH_PLAYBOOK.get(focus_value, {})
    return {}


def list_focus_values(focus_type: str) -> list:
    """Return the known values for a given focus type."""
    if focus_type == "category":
        return list(CATEGORY_PLAYBOOK.keys())
    elif focus_type == "platform":
        return list(PLATFORM_PLAYBOOK.keys())
    elif focus_type == "attack_path":
        return list(ATTACK_PATH_PLAYBOOK.keys())
    return []

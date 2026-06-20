<h1 align="center">ai-llm-redteam-operator</h1>


<p align="center">
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/releases"><img src="https://img.shields.io/github/v/release/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="release"></a>
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="license"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="python"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> •
  <a href="#how-it-works">How it works</a> •
  <a href="#safety-model">Safety</a> •
  <a href="#usage">Usage</a> •
  <a href="#focus-dimensions">Focus</a> •
  <a href="#what-plan-produces">Packet</a> •
  <a href="#status-and-limits">Status</a> •
  <a href="#scope">Scope</a>
</p>

---

ai-llm-redteam-operator is a two-stage workflow for authorized AI/LLM assessments.

**`plan`** turns a focus value (a category, a platform, or a named attack path) into a structured scenario packet: the recon probes to send, the weak signal that confirms each step, the attack chains to walk, and the matching defender guidance. It touches no network.

**`run`** hands that packet to an agent that executes it against a single host as a sense-plan-act loop. The agent sends the probes the packet prescribes, reads the responses, advances a chain only when the prior step confirms, and returns an evidence ledger: what was sent, what came back, and which hypotheses the evidence actually supports.

The agent fires real HTTP, so it is built default-safe. It refuses to send without an authorization reference, plans rather than sends until you pass `--live`, locks every request to the one target host, and holds back every write until you allow it. Nothing is marked `confirmed` without hard evidence on the wire.

It sits at the execution stage of the NuClide chain. Where [aimap](https://github.com/nuclide-research/aimap) answers "what service is this?" and [herald](https://github.com/nuclide-research/herald) answers "is it open?", ai-llm-redteam-operator answers "given this exposure class, walk the full red-and-blue plan against this host and show me the evidence."

## Quick start

```bash
git clone https://github.com/nuclide-research/ai-llm-redteam-operator
cd ai-llm-redteam-operator
pip install -e .          # installs the `ai-llm-redteam-operator` console command
```

Python 3.8 or later. No third-party packages: the runtime uses only `dataclasses`, `argparse`, `sqlite3`, `json`, `urllib`, and `ssl` from the standard library, and the optional LLM path stays on `urllib` too.

Three commands, escalating from zero risk to live traffic:

```bash
# 1. PLAN. No network. Write the scenario packet for a platform.
ai-llm-redteam-operator plan platform LiteLLM

# 2. DRY-RUN. Build every request for a target and send nothing.
ai-llm-redteam-operator run platform LiteLLM \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014

# 3. LIVE. Send the planned read probes and report the evidence.
ai-llm-redteam-operator run platform LiteLLM \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014 --live
```

`plan` is the default subcommand, so the bare form (`ai-llm-redteam-operator platform LiteLLM`) still works. To run without installing, call the module from the repo root: `python -m ai_llm_redteam_operator.cli plan platform LiteLLM`.

## How it works

```
  plan stage (no network)                 run stage (scoped, gated)
 ┌────────────────────────┐              ┌──────────────────────────────┐
 │ focus value            │              │ authorized target + scope ref │
 │   category /           │              │                               │
 │   platform /           │              │   recon pre-pass: send each   │
 │   attack_path          │              │   in-cap read probe once      │
 │        │               │              │        │                      │
 │        ▼               │   Scenario   │        ▼                      │
 │  AegisLLM_Operator  ───┼──  Packet ──▶│   evaluate weak signals       │
 │  (planner / policy)    │  (7 sections)│   against the responses       │
 │        │               │              │        │                      │
 │        ▼               │              │        ▼                      │
 │  playbook + 2 hand-    │              │   walk each attack chain:     │
 │  authored scenarios    │              │   advance a step only if the  │
 └────────────────────────┘              │   prior step confirmed        │
                                         │        │                      │
                                         │        ▼                      │
                                         │   Run Report: findings +      │
                                         │   chain outcomes + evidence   │
                                         │   ledger (md or json)         │
                                         └──────────────────────────────┘
```

The loop is genuine, not cosmetic:

- **Sense.** The agent runs every in-cap probe once, then maps each test case's expected weak signals onto the concrete responses. A signal matches only against a real, sent observation, never a planned one.
- **Plan.** Chains are walked in packet order by default. Supply an LLM endpoint and the optional strategist reranks which chain to pursue first; if it fails or is absent, the agent keeps the deterministic order.
- **Act.** A chain advances to its next step only when the current step is `confirmed`. The moment a step's signal fails to confirm, the chain stalls there. The agent does not pursue a step whose precondition it could not meet.

A finding is `confirmed` only on hard, sent evidence: a 2xx status the signal named that actually returned a body, or a body token or header presence on a 2xx response. A token echoed inside a 403 body does not count, and a bare 204 confirms nothing exfiltrable. In dry-run nothing is sent, so every finding stays unconfirmed by construction.

## Safety model

The agent fires real HTTP. Four gates, all default-safe, each lifted only by an explicit flag:

```
  ┌─ authorization ── no --authorize  →  refuse, send nothing
  ├─ mode ────────── default dry-run  →  plan requests, send nothing
  ├─ scope ───────── every URL = target host + packet path; redirects captured,
  │                  not followed; responding host re-checked  →  cannot leave host
  └─ two probe gates
       ├─ noise cap (--max-aggressiveness): filters READ probes by rated noise
       └─ mutation gate (--allow-writes):   blocks ALL write methods until set,
                                            no matter how the packet rated them
```

The noise cap and the mutation gate are independent on purpose. The planner rates many mutating probes as `medium` noise, so a noise cap alone would let them fire. Raising `--max-aggressiveness` never permits a write. Writes (POST, PUT, PATCH, DELETE) go out only when `--allow-writes` is set, and an unrecognized noise label is treated as the highest tier so a typo fails closed.

Scope is enforced twice. The packet path is host-relative by contract (an absolute or scheme-relative path is rejected), and a custom redirect handler never follows a 3xx, returning it as a terminal observation so the operator sees the `Location` and decides. As defense in depth, the responding URL's host is re-checked against the target before any body is recorded.

Restraint lives in the loop too: one proof artifact per step then stop, a byte cap on every response sample (`--max-body-bytes`), and a global request budget (`--max-requests`) that ends the run when exhausted.

## Usage

### `run` flags

| Flag | Default | Effect |
|------|---------|--------|
| `--target` | (required) | base target URL; every request stays on this scheme and host |
| `--authorize` | (required) | engagement / scope reference; no send without it |
| `--dry-run` / `--live` | `--dry-run` | plan only, or actually send |
| `--max-aggressiveness` | `medium` | highest read-probe noise to send (`low_noise`, `medium`, `high`) |
| `--allow-writes` | off | permit POST/PUT/PATCH/DELETE probes, independent of the noise cap |
| `--max-requests` | `60` | global request budget for the run |
| `--max-body-bytes` | `4096` | response body sample cap |
| `--delay` | `0.5` | pause before each live request, seconds |
| `--timeout` | `8.0` | per-request timeout, seconds |
| `--verify-tls` | off | verify target certs (off by default, in-scope self-signed is common) |
| `--llm-endpoint` / `--llm-model` / `--llm-api-key-env` | off | optional strategist endpoint, model, and key env var |
| `--format` | `md` | report format, `md` or `json` |
| `--out` | stdout | write the report to a file |

Both stages share `--format` (`md` or `json`) and `--out`. `plan` adds `--min-severity`, `--sectors`, `--limit`, and `--list-values <focus_type>` to enumerate valid values.

A worked live run with mutations permitted and the strategist ranking chains:

```bash
ai-llm-redteam-operator run attack_path open_gateway_llmjacking \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014 \
    --live --allow-writes --max-aggressiveness high \
    --llm-endpoint http://127.0.0.1:11434/v1/chat/completions
```

### As a library

```python
from ai_llm_redteam_operator import AegisLLM_Operator, RunConfig, build_agent, render_run_report_markdown

op = AegisLLM_Operator(db_path="nuclide.db", coords_path="coords.json", details_path="details.json")
packet = op.generate_scenario_packet("platform", "LiteLLM")

cfg = RunConfig(target="https://10.0.0.5:4000", authorization="ENG-2026-014", dry_run=False)
report = build_agent(cfg).run(packet)
print(render_run_report_markdown(report))   # report.to_dict() for machine use
```

## Focus dimensions

Point either stage at one of three focus types. The registries live in `models.py`.

**`category`** is one of eight AI/LLM exposure classes:

```
exposed_model_runtimes   open_gateways   notebooks       chat_uis
leaky_data_stores        key_abuse       observability   agent_surfaces
```

**`platform`** is a specific product, resolved to its category via `PLATFORM_MAP`:

```
Ollama, vLLM                              -> exposed_model_runtimes
LiteLLM, One-API, Kong, PortKey.ai        -> open_gateways
JupyterHub                                -> notebooks
Open WebUI, Streamlit                     -> chat_uis
Elasticsearch, Weaviate, Qdrant, Milvus   -> leaky_data_stores
MLflow, Langfuse                          -> observability
Flowise, Langflow                         -> agent_surfaces
```

**`attack_path`** is a named end-to-end chain:

```
open_gateway_llmjacking          ollama_11434_host_takeover
flowise_to_weaviate_pii_dump     open_webui_open_signup_rag_seat
open_jupyter_gpu_rce
```

## What plan produces

A scenario packet is seven sections, defined as dataclasses in `models.py`. The planner fills all seven; the agent reads three of them at run time (`recon_mapping` for what to send, `test_cases` for what signal confirms a step, `attack_chains` for what order to walk).

| Section | Contents |
|---------|----------|
| `target_profile` | host summary (severity / sector / auth-posture counts), typical platforms, notable patterns |
| `recon_mapping` | surface elements, HTTP probe patterns (methods, paths, headers, aggressiveness), phased recon plan |
| `threat_model` | assets ranked by criticality, falsifiable hypotheses with confidence and impact |
| `test_cases` | objective, preconditions, steps, weak signals, severity-if-confirmed, noise level, detection focus |
| `attack_chains` | ordered test-case sequences with a noise profile and defender learning goals |
| `detection_telemetry` | logging recommendations, detection ideas (pattern + severity), stealth notes |
| `hardening` | quick wins, architectural changes, detection-engineering actions, per-platform templates |

The same packet that maps a target also hardens it: every test case carries its `severity_if_confirmed` and `noise_level`, and every chain carries its `defender_learning_goals`.

## What run produces

The run report is the evidence record. In Markdown it is three tables under a header:

```
# Agent run report: platform / LiteLLM

- mode: live
- target: https://10.0.0.5:4000
- authorization: ENG-2026-014
- requests: 6 sent, 0 planned, 2 skipped

## Findings
| test case          | confirmed | severity | evidence | note |
| open_models_list   | yes       | high     | #3       | confirmed: 1 signal(s) backed by sent evidence |
| spend_logs_leak    | no        | high     | -        | no expected weak signals observed |

## Attack chains
### LLMjacking via open gateway (open_gateway_llmjacking) - stalled
- reached step: spend_logs_leak
- confirmed steps: open_models_list
- defender learning goals: ...

## Evidence ledger
| # | probe        | method | path        | status | sent | note |
| 3 | models_probe | GET    | /v1/models  | 200    | yes  |      |
| 5 | write_probe  | POST   | /v1/keys    | -      | no   | write method POST blocked (pass --allow-writes to permit) |
```

`--format json` emits the same data as a `RunReport.to_dict()` object: mode, request counts, every observation, every finding with its backing evidence sequence numbers, chain outcomes, and run notes. The ledger lists planned, skipped, and sent requests alike, so a reviewer can see exactly what each finding rests on and what was held back.

## Status and limits

Functional release, `0.2.0`. Both stages work end to end. All eight categories, all seventeen platforms, and all five attack paths plan a full packet and execute against a target. The authorization gate, dry-run default, scope lock, noise cap, mutation gate, signal evaluator, and chain advancement are exercised against a local stub server in the loop tests.

Two subsystems are intentionally bounded, and both say so in the output rather than hiding it:

- **Live host-summary counts in the planner.** `_query_host_summary` returns zeros pending a real `nuclide.db`; the method documents the assumed schema, and the two hand-authored scenarios show illustrative counts. Everything else in a packet is live.
- **Signal evaluation is heuristic by design.** It matches status codes, header presence, and body tokens against the packet's weak signals, and confirms only on hard, sent evidence. It is deliberately conservative and records the exact observation behind every match, so it triages what the agent saw rather than replacing the operator's judgment.

Package layout:

```
ai_llm_redteam_operator/
  cli.py        plan / run subcommands, focus dispatch, output routing
  operator.py   AegisLLM_Operator: builds the packet (planner)
  playbook.py   tactical knowledge base, one entry per focus value
  models.py     dataclasses for every packet node + registries
  render.py     ScenarioPacket dict -> Markdown
  agent.py      RedTeamAgent: the sense-plan-act loop (executor) + run report
```

To extend the plan: add the value to the relevant registry in `models.py`, then add a matching entry to the corresponding dict in `playbook.py`. The adapters pick it up. For a bespoke, full-depth scenario, add a dedicated builder in `operator.py`. The agent runs whatever the planner emits, with no agent changes.

## Scope

Authorized assessment tooling. The agent performs network activity by design, so it is gated accordingly: it requires an explicit authorization reference and a target, defaults to dry-run, locks to a single host, blocks mutations until told otherwise, and bounds every run. Every scenario assumes explicit, written authorization for the target in scope.

The optional LLM strategist transmits a recon digest (one `METHOD path -> status` line per live observation, no response bodies) to the configured endpoint. It is off unless `--llm-endpoint` is supplied, the run report records the egress, and it warns when the endpoint is remote or plaintext. Any strategist failure is swallowed and the agent falls back to deterministic order, so the advisor can never break or steer a run on its own.

The packets and the loop encode the assessment ethic: steps end at one proof artifact rather than bulk extraction, PII scenarios confirm data class from schema and a minimal sample, threat hypotheses are falsifiable, and a finding is only ever as strong as the evidence in the ledger.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)

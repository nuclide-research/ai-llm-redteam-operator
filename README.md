<h1 align="center">ai-llm-redteam-operator</h1>

<h4 align="center">Agentic red-team workflow for authorized AI/LLM infrastructure: plan a scenario, then execute it against a scoped target.</h4>

<p align="center">
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/releases"><img src="https://img.shields.io/github/v/release/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="release"></a>
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="license"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="python"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#how-it-works">How it works</a> •
  <a href="#usage">Usage</a> •
  <a href="#safety-model">Safety</a> •
  <a href="#focus-dimensions">Focus</a> •
  <a href="#status">Status</a> •
  <a href="#scope">Scope</a>
</p>

---

ai-llm-redteam-operator is a two-stage agentic workflow for authorized AI/LLM assessments. Stage one **plans**: it turns a focus value (a category, a platform, or a named attack path) into a structured Scenario Packet. The packet is the policy. Stage two **runs**: an agent executes that policy against one scoped target as a sense-plan-act loop. It sends the recon probes the packet prescribes, reads the responses, evaluates them against each test case's weak signals, and advances an attack chain only when the prior step confirms. It produces a Run Report: an evidence ledger of what was sent, what came back, and which hypotheses the evidence actually supports.

The planner plays both sides. Every test case carries its `severity_if_confirmed` and `noise_level`; every attack chain carries its `defender_learning_goals`. The same packet that maps a target also hardens it. The agent inherits that ethic: it confirms one proof artifact per step and stops, it samples response bodies rather than bulk-pulling them, and it never claims a finding the evidence does not back.

The operator sits at the execution stage of the NuClide chain. Where [aimap](https://github.com/nuclide-research/aimap) answers "what service is this?" and [herald](https://github.com/nuclide-research/herald) answers "is this open?", ai-llm-redteam-operator answers "given this exposure class, walk the full red-and-blue plan against this host and show me the evidence."

# Features

- Two stages, one workflow: `plan` writes the Scenario Packet, `run` executes it against a target
- A real sense-plan-act loop: recon pre-pass, signal evaluation, chain advancement gated on confirmation, evidence ledger
- Authorization gate: the agent refuses to send a byte without an explicit scope reference and a target
- Dry-run by default: the default mode plans every request and sends nothing, so a dry-run can never produce a "confirmed" finding
- Two independent safety gates: a noise cap that filters read probes and a separate mutation gate that blocks all writes unless explicitly allowed
- Single-host scope: every request is the target's scheme and host with a packet path appended, and redirects are captured rather than followed, so a probe can never walk the agent off-target
- Evidence-backed findings only: a hypothesis is confirmed solely when a sent observation carries a matching status, header, or body token
- Optional LLM strategist (OpenAI-compatible endpoint via urllib) that ranks which chain to pursue first, off unless an endpoint is supplied
- Seven-section packets and Markdown or JSON output for both the plan and the report
- Standard library only, no third-party dependencies, including the LLM path

# Installation

```bash
git clone https://github.com/nuclide-research/ai-llm-redteam-operator
cd ai-llm-redteam-operator
pip install -e .          # installs the `ai-llm-redteam-operator` console command
```

Python 3.8 or later, no third-party packages. The runtime uses only `dataclasses`, `argparse`, `sqlite3`, `json`, `urllib`, and `ssl` from the standard library. To run without installing, invoke the module from the repository root:

```bash
python -m ai_llm_redteam_operator.cli plan category open_gateways
```

# How it works

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

The loop is genuine, not cosmetic. A chain stalls the moment a step's signal fails to confirm: the agent does not pursue a step whose precondition it could not meet. A finding is marked `confirmed` only when a sent observation carries hard evidence (a 2xx status the signal named, a body token, or a header presence). In dry-run nothing is sent, so every finding stays unconfirmed by construction.

# Usage

`plan` is the default subcommand, so the historical bare form still works.

```bash
# PLAN: write the packet (no network)
ai-llm-redteam-operator plan platform LiteLLM
ai-llm-redteam-operator category open_gateways --format json
ai-llm-redteam-operator attack_path flowise_to_weaviate_pii_dump --out flowise.md

# RUN: dry-run is the default. This plans requests and sends nothing.
ai-llm-redteam-operator run platform LiteLLM \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014

# RUN live: actually send the planned read probes
ai-llm-redteam-operator run platform LiteLLM \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014 --live

# RUN live with mutations permitted and the LLM strategist ranking chains
ai-llm-redteam-operator run attack_path open_gateway_llmjacking \
    --target https://10.0.0.5:4000 --authorize ENG-2026-014 \
    --live --allow-writes --max-aggressiveness high \
    --llm-endpoint http://127.0.0.1:11434/v1/chat/completions
```

`run` flags:

| Flag | Default | Effect |
|------|---------|--------|
| `--target` | (required) | base target URL; every request stays on this scheme and host |
| `--authorize` | (required) | engagement / scope reference; no send without it |
| `--dry-run` / `--live` | `--dry-run` | plan only, or actually send |
| `--max-aggressiveness` | `medium` | highest read-probe noise level to send (`low_noise`, `medium`, `high`) |
| `--allow-writes` | off | permit POST/PUT/PATCH/DELETE probes, independent of the noise cap |
| `--max-requests` | `60` | global request budget for the run |
| `--max-body-bytes` | `4096` | response body sample cap |
| `--delay` | `0.5` | pause before each live request |
| `--timeout` | `8.0` | per-request timeout |
| `--verify-tls` | off | verify target certs (off by default, self-signed is common) |
| `--llm-endpoint` / `--llm-model` / `--llm-api-key-env` | off | optional strategist endpoint, model, and key env var |
| `--format` | `md` | report format, `md` or `json` |

As a library:

```python
from ai_llm_redteam_operator import AegisLLM_Operator, RunConfig, build_agent, render_run_report_markdown

op = AegisLLM_Operator(db_path="nuclide.db", coords_path="coords.json", details_path="details.json")
packet = op.generate_scenario_packet("platform", "LiteLLM")

cfg = RunConfig(target="https://10.0.0.5:4000", authorization="ENG-2026-014", dry_run=False)
report = build_agent(cfg).run(packet)
print(render_run_report_markdown(report))   # report.to_dict() for machine use
```

# Safety model

The agent fires real HTTP. Four gates, all default-safe, each lifted only by an explicit flag:

```
  ┌─ authorization ── no --authorize  →  refuse, send nothing
  ├─ mode ────────── default dry-run  →  plan requests, send nothing
  ├─ scope ───────── every URL = target host + packet path, redirects not followed  →  cannot leave host
  └─ two probe gates
       ├─ noise cap (--max-aggressiveness): filters read probes by rated noise
       └─ mutation gate (--allow-writes):   blocks ALL write methods until set,
                                            no matter how the packet rated them
```

The noise cap and the mutation gate are independent on purpose. The planner rates many mutating probes as `medium` noise; a noise cap alone would let them fire. Raising `--max-aggressiveness` never permits a write. Writes go out only when `--allow-writes` is set. Restraint is enforced in the loop too: one proof artifact per step, a byte cap on every response sample, and a global request budget.

# Focus dimensions

Pick one of three focus types. The registries live in `models.py`.

**`category`** is one of eight AI/LLM exposure classes:

```
exposed_model_runtimes   open_gateways   notebooks    chat_uis
leaky_data_stores        key_abuse       observability   agent_surfaces
```

**`platform`** is a specific product, resolved to its category via `PLATFORM_MAP`:

```
Ollama, vLLM                         -> exposed_model_runtimes
LiteLLM, One-API, Kong, PortKey.ai   -> open_gateways
JupyterHub                           -> notebooks
Open WebUI, Streamlit                -> chat_uis
Elasticsearch, Weaviate, Qdrant, Milvus -> leaky_data_stores
MLflow, Langfuse                     -> observability
Flowise, Langflow                    -> agent_surfaces
```

**`attack_path`** is a named end-to-end chain:

```
open_gateway_llmjacking          ollama_11434_host_takeover
flowise_to_weaviate_pii_dump     open_webui_open_signup_rag_seat
open_jupyter_gpu_rce
```

# Scenario packet

A packet is seven sections, defined as dataclasses in `models.py`. The planner fills them; the agent reads `recon_mapping` (what to send), `test_cases` (what signal confirms a step), and `attack_chains` (what order to walk).

| Section | Contents |
|---------|----------|
| `target_profile` | host summary (severity / sector / auth-posture counts), typical platforms, notable patterns |
| `recon_mapping` | surface elements, HTTP probe patterns (methods, paths, headers, aggressiveness), phased recon plan |
| `threat_model` | assets ranked by criticality, falsifiable hypotheses with confidence and impact |
| `test_cases` | objective, preconditions, steps, weak signals, severity-if-confirmed, noise level, detection focus |
| `attack_chains` | ordered test-case sequences with a noise profile and defender learning goals |
| `detection_telemetry` | logging recommendations, detection ideas (pattern + severity), stealth notes |
| `hardening` | quick wins, architectural changes, detection-engineering actions, per-platform templates |

The package layout:

```
ai_llm_redteam_operator/
  cli.py        plan / run subcommands, focus dispatch, output routing
  operator.py   AegisLLM_Operator: builds the packet (planner)
  playbook.py   tactical knowledge base, one entry per focus value
  models.py     dataclasses for every packet node + registries
  render.py     ScenarioPacket dict -> Markdown
  agent.py      RedTeamAgent: the sense-plan-act loop (executor) + Run Report
```

# Status

Functional release, `0.2.0`. Both stages work end to end. All eight categories, all seventeen platforms, and all five attack paths plan a full packet and execute against a target. The agent's authorization gate, dry-run default, scope lock, noise cap, mutation gate, signal evaluator, and chain advancement are exercised against a local stub server in the loop tests.

Two subsystems are intentionally bounded:

- The live host-summary counts in the planner. `_query_host_summary` returns zeros pending a real `nuclide.db`; the method documents the assumed schema. The two hand-authored scenarios show illustrative counts. Everything else in a packet is live.
- Signal evaluation is heuristic by design. It matches status codes, header presence, and body tokens against the packet's weak signals, and it confirms a finding only on hard, sent evidence. It is deliberately conservative: the evidence ledger records the exact observation behind every match so a human verifies the call. It is a triage of what the agent saw, not a substitute for the operator's judgment.

To extend the plan: add the value to the relevant registry in `models.py`, then add a matching entry to the corresponding dict in `playbook.py`. The adapters pick it up. For a bespoke, full-depth scenario, add dedicated builders in `operator.py`. The agent runs whatever the planner emits, no agent changes needed.

# Scope

Authorized assessment tooling. The agent performs network activity by design, so it is gated accordingly: it requires an explicit authorization reference and a target, defaults to dry-run, locks to a single host, blocks mutations until told otherwise, and bounds every run. Every scenario assumes explicit, written authorization for the target in scope. The packets and the loop encode the assessment ethic: steps end at one proof artifact rather than bulk extraction, PII scenarios confirm data class from schema and a minimal sample, threat hypotheses are falsifiable, and a finding is only ever as strong as the evidence in the ledger. The optional LLM strategist transmits a recon digest (one `METHOD path -> status` line per live observation, no response bodies) to the configured endpoint; the run report records the egress and warns when the endpoint is remote or plaintext. The same workflow that maps a target hardens it.

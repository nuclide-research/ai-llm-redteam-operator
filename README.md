<h1 align="center">ai-llm-redteam-operator</h1>

<h4 align="center">Scenario-packet generator for authorized AI/LLM red-team and detection engineering.</h4>

<p align="center">
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/releases"><img src="https://img.shields.io/github/v/release/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="release"></a>
  <a href="https://github.com/nuclide-research/ai-llm-redteam-operator/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/ai-llm-redteam-operator?style=flat-square" alt="license"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="python"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#focus-dimensions">Focus</a> •
  <a href="#scenario-packet">Packet</a> •
  <a href="#status">Status</a> •
  <a href="#scope">Scope</a>
</p>

---

ai-llm-redteam-operator is a Python package that turns a focus value into a structured **Scenario Packet** for authorized AI/LLM assessments. Give it a category, a platform, or a named attack path; it emits one document that pairs the offensive surface map with the defensive telemetry to catch it: phased recon, HTTP probe patterns, a threat model, sequenced test cases, attack chains, logging recommendations, detection ideas, and hardening guidance. Output is Markdown for human consumption or JSON for pipelines.

It models a senior operator who plays both sides. Every test case ships its `severity_if_confirmed` and `noise_level`; every attack chain ships its `defender_learning_goals`. The packet maps the target and hardens it in the same pass. It performs no network activity. It writes the plan; the operator runs it, under scope.

The operator sits at the planning stage of the NuClide chain. Where [aimap](https://github.com/nuclide-research/aimap) answers "what service is this?" and [herald](https://github.com/nuclide-research/herald) answers "is this open?", ai-llm-redteam-operator answers "given this exposure class, what is the full red-and-blue plan?"

# Features

- Three focus dimensions: `category` (8 exposure classes), `platform` (resolved to its category), `attack_path` (named end-to-end chains)
- Seven-section packet: target profile, recon mapping, threat model, test cases, attack chains, detection telemetry, hardening
- Falsifiable threat hypotheses carrying a confidence level and an impact-if-confirmed, not foregone conclusions
- Test cases with explicit weak signals, preconditions, noise level, and detection focus
- Attack chains as ordered test-case sequences with an overall noise profile and defender learning goals
- Detection telemetry pairs every attack with logging recommendations, detection ideas, and stealth-vs-residual-signal notes
- Markdown or JSON output (`dataclasses.asdict` over the whole packet)
- Restraint baked in: test cases confirm one proof artifact and stop, schema and metadata over bulk dumps
- Standard library only, no third-party dependencies

# Installation

```bash
git clone https://github.com/nuclide-research/ai-llm-redteam-operator
```

Python 3.8 or later. No third-party packages: `dataclasses`, `argparse`, `sqlite3`, and `json` from the standard library. The package directory carries a hyphen, so run it from the parent directory as a module or vendor it under an underscore alias.

# Usage

```bash
# A whole exposure category
python -m ai_llm_redteam_operator.cli category open_gateways

# A single platform, as JSON
python -m ai_llm_redteam_operator.cli platform LiteLLM --format json

# A named attack path, written to a file
python -m ai_llm_redteam_operator.cli attack_path flowise_to_weaviate_pii_dump --out flowise.md

# Filter the host summary
python -m ai_llm_redteam_operator.cli category open_gateways --min-severity high --sectors commercial,healthcare

# List known values for a focus type
python -m ai_llm_redteam_operator.cli --list-values category
```

Flags:

| Flag | Default | Effect |
|------|---------|--------|
| `--format` | `md` | output format, `md` or `json` |
| `--out` | stdout | write the rendered packet to a file |
| `--min-severity` | | drop hosts below this severity from the summary |
| `--sectors` | | comma-separated sector filter |
| `--db` / `--coords` / `--details` | `~/AI-LLM-Infrastructure-OSINT/data/*` | source data paths |
| `--limit` | `500` | max hosts pulled from the DB |
| `--list-values` | | print known values for a focus type and exit |

As a library:

```python
from ai_llm_redteam_operator import AegisLLM_Operator

op = AegisLLM_Operator(db_path="nuclide.db", coords_path="coords.json", details_path="details.json")
packet = op.generate_scenario_packet("category", "open_gateways")
print(op.render_markdown(packet))   # packet is a plain dict; json.dumps it for machine use
```

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

A packet is seven sections, defined as dataclasses in `models.py`:

| Section | Contents |
|---------|----------|
| `target_profile` | host summary (severity / sector / auth-posture counts), typical platforms, notable patterns |
| `recon_mapping` | surface elements (paths, ports, header/banner signatures), HTTP probe patterns, phased recon plan |
| `threat_model` | assets ranked by criticality, falsifiable hypotheses with confidence and impact |
| `test_cases` | objective, preconditions, steps, weak signals, severity-if-confirmed, noise level, detection focus |
| `attack_chains` | ordered test-case sequences with a noise profile and defender learning goals |
| `detection_telemetry` | logging recommendations, detection ideas (pattern + severity), stealth notes |
| `hardening` | quick wins, architectural changes, detection-engineering actions, per-platform templates |

The pipeline:

```
cli.py        argument parsing, focus dispatch, output routing
  |
  v
operator.py   AegisLLM_Operator: one builder per packet section,
  |             keyed on (focus_type, focus_value), _generic fallback
  |
  +-- models.py    dataclasses for every node + category / attack-path registries
  +-- render.py    ScenarioPacket dict -> structured Markdown report
  +-- playbook.py  tactical knowledge base, one dict entry per focus value
```

# Status

Early release, `0.1.0`. Read this before relying on output.

- **Fully built scenarios:** `category / open_gateways` and `attack_path / flowise_to_weaviate_pii_dump` carry rich, hand-authored packets in `operator.py`. Every other focus value falls through to the `_generic` builders, which emit a valid packet skeleton with explicit `TODO` markers.
- **Stubbed data access:** `_load_details`, `_load_coords`, and `_query_host_summary` return empty defaults. Host-summary counts in the two built scenarios are hardcoded illustrative values. The `nuclide.db` query is present as a documented `TODO` with the assumed schema. `--min-severity` and `--sectors` are plumbed but not yet applied.
- **`playbook.py` not wired in:** it holds a complete tactical knowledge base for all eight categories, structured to map 1:1 onto the model fields, but `operator.py` does not import it yet. Wiring the builders to read from the playbook dicts lights up the remaining six categories without touching `operator.py`.

To extend: add the value to the relevant registry in `models.py`, add a matching entry to the corresponding dict in `playbook.py`, and for a bespoke scenario add dedicated `_tp_* / _recon_* / _tm_* / _tc_* / _ac_* / _dt_* / _h_*` builders in `operator.py`.

# Scope

Authorized assessment tooling. ai-llm-redteam-operator generates plans, not exploits, and performs no network activity. Every scenario assumes explicit, written authorization for the target in scope. The packets encode the assessment ethic: test cases end at one proof artifact rather than bulk extraction, PII scenarios confirm data class from schema and a minimal sample, and threat hypotheses are falsifiable. The same packet that maps a target hardens it.

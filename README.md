# LogJack

**An LLM-powered SOC analysis assistant and prompt-injection resilience testbed.**

LogJack measures how well large language models triage security logs, and how easily untrusted
text inside those logs (a User-Agent header, a URL path, an SSH username, a DNS query) can
manipulate the model's output. It compares four defense strategies on identical inputs and reports
the results through a research dashboard.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![React](https://img.shields.io/badge/React-19-61dafb)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178c6)
![License](https://img.shields.io/badge/license-MIT-green)

> LogJack runs entirely as an isolated simulation. All logs are synthetic, every "security tool"
> is simulated, and the application never connects to real infrastructure or executes external
> actions.

---

## Table of contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [How it works](#how-it-works)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Usage](#usage)
- [Testing](#testing)
- [API reference](#api-reference)
- [Project structure](#project-structure)
- [Methodology and metrics](#methodology-and-metrics)
- [Safety and scope](#safety-and-scope)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Features

**SOC analysis assistant**
- Analyzes Nginx access logs, SSH auth logs, DNS query logs and Suricata-style IDS alerts
- Classifies each event as `benign`, `suspicious` or `malicious`
- Returns structured JSON: verdict, severity, indicators, summary, recommended actions and tool requests
- Supports OpenAI-compatible APIs, Anthropic, local models through Ollama, and an offline mock provider

**Synthetic evaluation dataset**
- 200 labeled cases (50 per log type): 80 benign, 48 suspicious, 72 malicious
- Every case has a **clean** version and a **modified** version with one benchmark string placed in
  an attacker-controllable field (User-Agent, URL path, referrer, SSH username, DNS query name)
- Generated deterministically from a seed and stored as JSONL with a SHA-256 manifest

**Prompt-injection evaluation**
- A fixed, human-reviewable benchmark of 10 templates covering five attack objectives: verdict
  manipulation, indicator omission, false-positive induction, unauthorized tool requests and
  instruction disclosure
- Import your own reviewed benchmark files and datasets (schema-validated)

**Defense comparison**
- `baseline`: no specialized defenses
- `guardrails`: constitutional-style principles that treat log content as untrusted data
- `isolation`: nonce-tagged boundaries around the log and each untrusted field
- `combined`: guardrails + isolation + a canary tripwire that quarantines compromised output
- Tool permissions are enforced in application code for every configuration. Denied requests are
  recorded and never executed.

**Experiment engine**
- Runs batch experiments across any combination of models, defenses and case filters
- Persists every result immediately, supports pause and resume, and recovers interrupted runs after a restart
- Keeps mock and real-LLM experiments strictly separate

**Research dashboard**
- Overview, SOC playground, dataset explorer, experiment runner, defense comparison charts,
  tripwire event history, and findings with CSV/JSON export

---

## Tech stack

| Layer | Technologies |
|---|---|
| Backend | Python 3.11+, FastAPI, Pydantic, httpx, SQLite |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4, Recharts, React Router |
| Testing | pytest, FastAPI TestClient, headless Chrome (DevTools Protocol) |

---

## How it works

```
 synthetic case ──► defense prompt ──► LLM provider ──► JSON parser
 (clean/modified)   (4 configs)        (mock/OpenAI/     │
                                        Anthropic/Ollama)│
                                                         ▼
 dashboard ◄── metrics ◄── scoring vs ground truth ◄── tool policy + canary tripwire
                                                        (app-side enforcement)
```

1. A case is loaded in its clean or modified form.
2. The selected defense builds the system and user prompts.
3. The model returns a structured analysis.
4. The application enforces tool permissions and, for the combined defense, checks the canary tripwire.
5. The result is scored against the ground-truth label and the attack objective, then stored.

---

## Getting started

### Prerequisites

- Python 3.11 or newer
- Node.js 20 or newer
- (Optional) An OpenAI or Anthropic API key, or a local [Ollama](https://ollama.com) installation

### Installation

```bash
git clone https://github.com/ladicodes/LogJack.git
cd LogJack

# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # optional, nothing is required for mock mode

# Frontend
cd ../frontend
npm install
```

### Running locally

Start the backend and frontend in two terminals:

```bash
# Terminal 1: API server
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2: dashboard
cd frontend
npm run dev
```

Open **http://localhost:5173**. The dev server proxies `/api` requests to the backend.

On first start the backend creates the SQLite database and loads the built-in dataset automatically.

### Single-server mode

Build the frontend once, and FastAPI serves the dashboard and the API from one port:

```bash
cd frontend && npm run build
cd ../backend && uvicorn app.main:app --port 8000
```

Open **http://localhost:8000**. Interactive API docs are at **http://localhost:8000/docs**.

---

## Configuration

All settings are optional environment variables, read from `backend/.env`. See
[`backend/.env.example`](backend/.env.example) for the full list.

| Variable | Default | Description |
|---|---|---|
| `LOGJACK_OPENAI_API_KEY` | – | Enables OpenAI-compatible models |
| `LOGJACK_OPENAI_BASE_URL` | `https://api.openai.com/v1` | Any server exposing `/v1/chat/completions` |
| `LOGJACK_OPENAI_MODELS` | `gpt-4o-mini` | Comma-separated model list |
| `LOGJACK_ANTHROPIC_API_KEY` | – | Enables Anthropic models |
| `LOGJACK_ANTHROPIC_MODELS` | `claude-sonnet-5-5,claude-haiku-5-5` | Comma-separated model list |
| `LOGJACK_OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama server (models are auto-discovered) |
| `LOGJACK_TEMPERATURE` | `0.0` | Sampling temperature for every provider |
| `LOGJACK_MAX_TOKENS` | `800` | Maximum response tokens |
| `LOGJACK_DB_PATH` | `backend/data/logjack.db` | SQLite database location |

Models are referenced as `provider:model`, for example `openai:gpt-4o-mini`,
`anthropic:claude-sonnet-5-5`, `ollama:llama3.1:8b`, `mock:naive` or `mock:cautious`.

---

## Deployment

The frontend and backend can be deployed separately, for example the dashboard on **Vercel** and
the API on **Render**.

**Backend (Render or any Python host)**

| Setting | Value |
|---|---|
| Root directory | `backend` |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| `LOGJACK_CORS_ORIGINS` | Optional. Comma-separated exact origins allowed to call the API. The default already includes `https://log-jack.vercel.app` and local dev. |
| `LOGJACK_CORS_ORIGIN_REGEX` | Optional. Defaults to `https://log-jack(-[a-z0-9-]+)?\.vercel\.app`, which covers the project's preview and branch URLs. |

**Frontend (Vercel)**

| Setting | Value |
|---|---|
| Root directory | `frontend` |
| Framework preset | Vite (build `npm run build`, output `dist`) |
| `VITE_API_BASE_URL` | The backend origin, e.g. `https://logjack-1.onrender.com` (a trailing `/` or `/api` is fine) |

`VITE_API_BASE_URL` is inlined at **build time**, so redeploy the frontend after changing it.
[`frontend/vercel.json`](frontend/vercel.json) rewrites every page route to `index.html`, so deep
links such as `/playground` work on refresh. When `VITE_API_BASE_URL` is empty (local
development), requests stay on the same origin and the Vite dev server proxies `/api` to the
backend.

If you attach a custom domain to the frontend, add it to `LOGJACK_CORS_ORIGINS` on the backend.

---

## Usage

1. **Explore the dataset.** Open *Dataset Explorer*, filter by log type or attack type, and click a
   case to compare the clean and modified logs side by side.
2. **Analyze a single log.** In *SOC Playground*, load a case or paste your own log, pick a model
   and a defense, and click **Analyze**. Use **Compare all 4 defenses** to see them side by side.
3. **Run an experiment.** On *Experiments*, select models, defenses and an optional case limit,
   then start the run. You can pause and resume it at any time.
4. **Compare defenses.** *Defense Comparison* charts attack success, accuracy, false
   positives/negatives, indicator preservation, tripwire detection and latency.
5. **Review and export.** *Tripwire Events* lists canary leaks and denied tool requests.
   *Findings & Exports* summarizes results and exports CSV or JSON.

> **Mock vs real results.** The `mock:*` models are deterministic stubs for development. Their
> numbers come from scripted rules and are labeled *SIMULATED* throughout the app. Only experiments
> run against real models produce meaningful research results.

A step-by-step walkthrough is available in [`docs/DEMO.md`](docs/DEMO.md).

---

## Testing

```bash
# Backend unit and integration tests
cd backend
python -m pytest -q

# Frontend type check and production build
cd frontend
npm run typecheck
npm run build

# Browser end-to-end test (requires Google Chrome and a running backend on :8000)
npm run test:e2e
```

| Suite | Coverage |
|---|---|
| `tests/test_dataset.py` | Dataset size and balance, schema validation, byte-for-byte reproducibility, injection placement |
| `tests/test_core.py` | Prompt construction, output parsing, tool enforcement, tripwire, scoring, metrics, providers |
| `tests/test_api.py` | API integration: datasets, imports, playground, experiment lifecycle, pause/resume, crash recovery, exports |
| `frontend/e2e/ui-test.mjs` | Clicks through every page and the main workflows, and fails on any JavaScript error or blank page |

To regenerate the dataset (the output is identical every time):

```bash
cd backend
python -m app.dataset.generator
```

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/overview` | Dashboard summary |
| `GET` | `/api/models` | Available providers and models |
| `GET` | `/api/defenses` | Defense configurations |
| `GET` | `/api/datasets` | List datasets |
| `GET` | `/api/datasets/{id}/cases` | Query cases (filters, search, pagination) |
| `GET` | `/api/datasets/{id}/download` | Download a dataset as JSONL |
| `POST` | `/api/datasets/import` | Import a JSONL dataset |
| `POST` | `/api/benchmarks/import` | Import a reviewed benchmark file |
| `POST` | `/api/analyze` | Analyze a single log |
| `POST` | `/api/experiments` | Create and start an experiment |
| `POST` | `/api/experiments/{id}/pause` | Pause an experiment |
| `POST` | `/api/experiments/{id}/resume` | Resume an experiment |
| `GET` | `/api/experiments/{id}/metrics` | Aggregated metrics |
| `GET` | `/api/experiments/{id}/results` | Individual results |
| `GET` | `/api/experiments/{id}/export` | Export results or metrics as CSV/JSON |
| `GET` | `/api/tripwires` | Tripwire event history |
| `GET` | `/api/tool-events` | Tool request audit log |
| `GET` | `/api/findings` | Findings generated from stored results |

Full request and response schemas are available at `/docs` while the server is running.

---

## Project structure

```
LogJack/
├── backend/
│   ├── app/
│   │   ├── api/            # REST endpoints
│   │   ├── dataset/        # generator, benchmark validator, JSONL/SQLite store
│   │   ├── eval/           # scoring, metrics, findings
│   │   ├── experiments/    # experiment runner (pause/resume/recovery)
│   │   ├── llm/            # mock, OpenAI-compatible, Anthropic, Ollama providers
│   │   ├── soc/            # prompts, analyzer, parsers, tool policy, tripwire
│   │   ├── config.py
│   │   ├── db.py
│   │   └── main.py
│   ├── data/
│   │   ├── benchmarks/     # logjack-pi-bench-v1.json
│   │   └── datasets/       # logjack-v1.jsonl + manifest
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/     # UI primitives, charts, analysis views
│   │   ├── pages/          # dashboard pages
│   │   ├── api.ts          # typed API client
│   │   └── App.tsx
│   ├── e2e/                # browser end-to-end test
│   └── package.json
└── docs/
    ├── METHODOLOGY.md
    └── DEMO.md
```

---

## Methodology and metrics

| Metric | Definition |
|---|---|
| Attack success rate (model-level) | Share of modified cases where the model's own output met the attack objective |
| Attack success rate (system-level) | The same, measured after application tool enforcement and tripwire quarantine |
| Classification accuracy | Final verdict matches the ground-truth label (clean and modified separately) |
| False positive / negative rate | Benign flagged as a threat / a threat labeled benign |
| Verdict flip rate | Cases correct on the clean log but wrong on the modified log |
| Indicator preservation | Recall of the expected indicators (IPs, domains, usernames, patterns) |
| Tripwire detection | How often the canary tripwire fires on modified cases and on clean cases |
| Latency | Mean, p50 and p95 of the provider response time |

Every rate is reported with its counts and a 95% Wilson confidence interval. See
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full design, scoring rules and limitations.

---

## Safety and scope

- **Synthetic data only.** External IPs come from the RFC 5737 documentation ranges, and malicious
  domains use the reserved `.test` TLD.
- **Simulated tools.** Tool requests are checked against a permission policy and recorded. Nothing
  is ever executed against a real system.
- **No payload generation.** The benchmark is a static, reviewable file. LogJack has no code that
  generates, mutates or optimizes adversarial inputs.
- **Defensive purpose.** The project evaluates the robustness of LLM-based security tooling.

---

## Limitations

- Cases are single synthetic events, without multi-event correlation or real-world log noise.
- The benchmark is small and non-adaptive, so results describe resistance to simple, obvious
  injections only.
- Instruction disclosure is detected through a verbatim fingerprint or canary, so paraphrased
  leaks are not counted.
- Results depend on the model version, the provider's defaults and the prompt wording. Record these
  alongside any reported numbers.

---

## Contributing

Contributions are welcome. Please open an issue to discuss a change before submitting a pull
request, and make sure `pytest` and `npm run build` pass.

---

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

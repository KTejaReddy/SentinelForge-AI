# SentinelForge AI

**Autonomous Red-Team, Bug Hunter & Self-Repairing Application Security Platform**

Upload a project ZIP → the platform safely builds and launches it inside an isolated
sandbox, discovers its attack surface, runs broad **authorized** security & QA testing,
uses AI (Groq) to reason about findings and root causes, generates patches, applies them
to a disposable working copy, rebuilds, re-runs the original attacks and the project's
own tests, verifies the fixes, and finally delivers reports plus a patched project ZIP.

> **Security boundary (hard-enforced in the backend, not just the UI):**
> Testing is restricted to applications contained in the uploaded project and their
> sandboxed runtime. Every probe request is validated at the HTTP-client layer and
> **rejected unless the target is a loopback address**. There is no arbitrary
> external-target attack functionality and no raw shell access for the AI.

---

## Core loop (visible throughout the product)

```
DISCOVER → ATTACK → CONFIRM → DIAGNOSE → FIX → REBUILD → ATTACK AGAIN → VERIFY
```

---

## Quick start

### Docker (preferred)

```bash
cp .env.example .env          # add GROQ_API_KEY (optional — deterministic mode works without it)
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend/API: http://localhost:8000 (Swagger at `/docs`)
- Click **Load Demo** on the landing page to run the built-in intentionally-vulnerable app end-to-end.

The backend mounts the Docker socket so every scan gets its own sandbox container
(see `docker/sandbox.Dockerfile`). If Docker is unavailable the platform automatically
falls back to a **process-isolated local sandbox** (documented limitation shown in the UI and reports).

### Local development

```bash
# backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # (Linux: .venv/bin/python)

# frontend
cd frontend && npm install

# optional security tools (semgrep, bandit, pip-audit, trivy, gitleaks,
# nuclei, ffuf, osv-scanner, playwright browser) — Linux, macOS and Windows (Git Bash)
bash scripts/install_tools.sh

# run both
bash scripts/dev.sh
```

Or run pieces separately:

```bash
( cd backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 )
( cd frontend && npm run dev )
```

Verify the environment anytime with `python scripts/check_env.py`.

---

## Configuration (`.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `GROQ_API_KEY` | *(empty)* | Groq key. Also configurable at runtime from the **AI Configuration** screen (stored **encrypted at rest**, never exposed to the browser). |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Configurable Groq model (any Groq-hosted model). |

> **Model guidance (free-tier accounts):** reasoning models such as
> `openai/gpt-oss-120b` produce long internal chains that quickly exhaust the
> free-tier token-per-minute limit, making AI stages very slow (each call is
> retried with backoff, so scans still complete). For fast scans on free-tier
> keys prefer a lighter accessible model (e.g. `openai/gpt-oss-20b`). You can
> change the model at runtime on the **AI Configuration** screen — it applies
> immediately. Note `.env` values override the saved settings on restart, so
> to make a model permanent, set `GROQ_MODEL` in `.env`.
| `GROQ_MAX_TOKENS` | `4096` | Max tokens per AI request. |
| `GROQ_TEMPERATURE` | `0.2` | Sampling temperature. |
| `DATABASE_URL` | `sqlite:///./data/sentinelforge.db` | Any SQLAlchemy URL. |
| `MAX_UPLOAD_SIZE_MB` | `200` | Upload limit. |
| `SCAN_TIMEOUT_SECONDS` | `900` | Overall scan budget. |
| `MAX_REPAIR_ITERATIONS` | `2` | Patch attempts per finding. |
| `MAX_AI_CALLS_PER_SCAN` | `80` | AI cost guardrail (tracked: calls, tokens, estimated $). |
| `DOCKER_ENABLED` | `true` | Set `false` to force the local sandbox fallback. |
| `SANDBOX_MEMORY_MB` / `SANDBOX_CPU_LIMIT` / `SANDBOX_MAX_PROCESSES` | `2048` / `2.0` / `256` | Container limits. |

**Never put real secrets in the repository.** `.env` is git-ignored; `.env.example` holds placeholders.

---

## What happens on every scan

1. **Validate & extract** — ZIP structure validation, SHA-256, zip-slip + absolute-path +
   decompression-bomb + symlink guards, immutable original copy.
2. **Fingerprint** — multi-language detection (Node/Express/NestJS/Next/React/Vue/Angular/Vite/Svelte/Remix/Nuxt,
   FastAPI/Flask/Django/Python, Spring/Maven/Gradle, Laravel/Symfony/Composer, Go modules, ASP.NET, Rails/Bundler,
   Docker/compose, package managers, build/start/test commands, ports, env vars, DB & auth indicators).
3. **Build & run (sandboxed)** — install deps, build, start, health-check, capture logs/ports/process tree.
   If the build fails, the **Build Agent** (AI) proposes minimal safe fixes to the working copy and retries (bounded).
4. **Discover** — source-level route/API/form discovery + live status mapping.
5. **Static analysis** — Semgrep (offline conservative rules) or the built-in deterministic analyzer.
6. **Dependency analysis** — Trivy (or recorded limitation).
7. **Secrets** — Gitleaks or the built-in regex secret scanner.
8. **Native tests** — the project's own test suite (npm test, pytest, jest, vitest, mocha, Maven, Gradle, Go, dotnet, PHPUnit, Rails…).
9. **Dynamic testing** — built-in probes (headers/cookies, method abuse, missing auth, IDOR/BOLA, reflected content/XSS,
   SQLi smoke, command-injection smoke, path traversal, debug-endpoint exposure, malformed-input error detection) +
   ZAP / Nuclei / ffuf when installed (loopback targets only, rate-limited).
10. **Browser testing** — Playwright (console errors, failed requests, forms, screenshots, workflow walking) or HTTP-crawl fallback.
11. **Fuzzing** — bounded malformed-JSON/query fuzzing of writable endpoints.
12. **Bug hunting** — AI-assisted analysis of logs/probes/tests.
13. **Correlate** — normalize every tool into one finding schema, dedupe, merge same-location findings, rank.
14. **AI analysis** — Recon Agent, Red-Team Security Agent, Root Cause Agent (tool-calling loop: inspect files,
    search code, probe the app), plus API/Browser/Dependency/Secrets/Fuzz/Business-Logic agents.
15. **Automatic repair** — for each machine-reproducible HIGH/CRITICAL finding: reproduce → Repair Agent patch →
    validate (snippet must exist verbatim, path must stay in the working copy) → apply → **rebuild + restart** →
    re-run the original exploit → run native + generated regression tests → targeted rescan → verification verdict
    (`FIXED` / `PARTIALLY_FIXED` / `NOT_FIXED` / `NEEDS_HUMAN_REVIEW`). Failed patches are **reverted**; the
    original copy is never mutated.
16. **Regression protection** — every verified patch is followed by build + native tests + original-exploit replay.
17. **Reports & artifacts** — executive summary, technical report, vulnerability matrix, bug report, patch report,
    verification report, tool coverage, limitations, machine-readable `report.json`,
    **original ZIP / patched ZIP / reports ZIP** downloads.

---

## AI system

- **Provider:** Groq (configurable model, max tokens, temperature; base URL configurable).
- **Cost control:** per-request token/cost tracking, `MAX_AI_CALLS_PER_SCAN`, deterministic tools first.
- **No hidden chain-of-thought** is exposed — agents emit structured reasoning summaries
  (Observation / Evidence / Likely root cause / Recommended action).
- **Safe tool calling:** the model can request sandbox-scoped operations only
  (`inspect_project_tree`, `inspect_file`, `search_code`, `get_route_map`, `get_runtime_logs`,
  `run_project_tests`, `run_targeted_probe`, …). There is **no raw shell execution** for the AI —
  command strings from the model are never executed.
- **Degraded mode:** without a key the platform still does everything deterministic (detection, build,
  SAST fallback, dependency fallback, secrets, browser, native tests, dynamic probes). AI steps show
  `Skipped — Groq unavailable` and never crash the scan.

---

## Scoring formula (deterministic — documented)

- Every unfixed finding costs points by severity: **CRITICAL 20 · HIGH 10 · MEDIUM 5 · LOW 2 · INFO 0**.
- `patch_status == verified` → 0 penalty. Patched-but-unverified → 30% of the penalty.
- Reliability is additionally penalized by failing native tests (2/failure, capped at 30) and crash findings.
- `Security = clamp(100 - Σ security penalties)`, `Reliability = clamp(100 - Σ reliability penalties)`,
  `Code Health = clamp(100 - Σ quality penalties)`.
- `Overall = 0.45·Security + 0.30·Reliability + 0.25·CodeHealth` (weights configurable in `config.py`).
- Identical findings ⇒ identical scores (pure function, covered by tests).

---

## No fabricated results

Every finding displayed as real originates from a scanner, an executed test, an observed application
behavior, or clearly-labeled AI static analysis. Each finding carries a provenance tag:
**Observed / Inferred / Potential / Confirmed / Verified**, severity, confidence, evidence, reproduction
status, fix status, and verification status. Tool unavailability is surfaced as a **limitation**, never
silently hidden.

---

## Tool availability & fallbacks

| Tool | Purpose | If unavailable |
| --- | --- | --- |
| Semgrep | SAST (all languages) | Built-in deterministic static analyzer |
| Bandit | Python SAST | Skipped (Semgrep covers static) |
| Gitleaks | secrets | Built-in regex secret scanner |
| Trivy | dependencies/config | Recorded limitation (deterministic fallbacks for npm/pip metadata) |
| OSV-Scanner | dependency advisories | Recorded limitation |
| OWASP ZAP | dynamic | Built-in passive header/configuration probes (Dynamic Probes) |
| Nuclei | template checks | Skipped (limitation) |
| ffuf | path discovery (aggressive+) | Skipped (limitation) |
| Playwright | browser | HTTP crawl fallback |
| Native tests | regression evidence | Always runs when a test command is detected |

Install extras with `bash scripts/install_tools.sh` (works on Linux, macOS and
Windows Git Bash; on Windows binaries land in `tools/bin`, which the backend
adds to PATH automatically).

**Tool health dashboard:** the **Security Tools** page (`/tools`) shows the live
capability matrix — every installed tool with version, purpose, and status, plus
Docker/sandbox mode, runtimes and scan limits. Backed by `GET /api/health/tools`.

---

## API (selection)

```
POST   /api/projects/upload              GET  /api/projects
GET    /api/projects/{id}                POST /api/projects/{id}/scan
GET    /api/scans/{id}                   POST /api/scans/{id}/stop
GET    /api/scans/{id}/events  (SSE)     GET  /api/scans/{id}/findings
GET    /api/findings/{id}                POST /api/findings/{id}/repair
POST   /api/findings/{id}/verify         GET  /api/scans/{id}/report
GET    /api/scans/{id}/attack-graph      GET  /api/scans/{id}/download/original|patched|reports
POST   /api/settings/groq/test           GET/POST /api/settings/groq
POST   /api/demo/load                    GET  /api/demo/list
GET    /api/tools                        GET  /api/health/tools   GET /api/health
```

The scan pipeline follows an explicit state machine
(`UPLOADED → VALIDATING → EXTRACTING → ANALYZING → BUILDING → RUNNING → DISCOVERING →
STATIC_ANALYSIS → DEPENDENCY_ANALYSIS → SECRET_ANALYSIS → DYNAMIC_TESTING → BROWSER_TESTING →
FUZZING → BUG_HUNTING → CORRELATING → AI_ANALYSIS → REPAIRING → REBUILDING → VERIFYING →
REPORTING → COMPLETED | FAILED | CANCELLED`), persisted to SQLite so the dashboard survives refreshes.

---

## Demo applications

The **Load Demo** control on the landing page lets you pick between several
intentionally vulnerable local Node/Express apps (each only ever executed inside
the sandbox, connecting to nothing external):

| Demo | Vulnerability classes |
| --- | --- |
| `vulnerable-app` (mixed) | command injection, path traversal, SQLi-style eval engine, IDOR/BOLA, reflected XSS, debug endpoint leak, hardcoded fake secrets, unsafe CORS, weak auth |
| `injection-app` | SQLi-style search, command injection, reflected XSS, server-side template injection |
| `auth-app` | plaintext passwords, forgeable sessions, missing auth on admin routes, IDOR/BOLA, session fixation, insecure cookies, hardcoded fake secrets |

Each demo ships its own `npm test` suite so the platform can produce real
regression evidence.

---

## Platform self-security

- Zip-slip / absolute-path / decompression-bomb / symlink guards; per-scan temp workspaces.
- Sandboxed execution: Docker (no privileged mode, dropped caps, memory/CPU/pids limits, network
  isolation, auto-cleanup) or the documented process-isolated local fallback.
- The AI never gets shell access; every tool call is validated, logged, time-limited, sandbox-scoped.
- Secrets are redacted from logs/reports/AI prompts and encrypted at rest if persisted.
- A failing tool or AI outage never kills a scan — partial coverage is recorded as limitations.

---

## Project layout

```
backend/    FastAPI + SQLAlchemy + orchestrator + agents + tools + sandbox + patching + reporting
frontend/   React + Vite + TypeScript + Tailwind + TanStack Query + Recharts + Monaco + React Router
demo/       intentionally vulnerable demo application
docker/     backend/frontend/sandbox images + nginx conf
scripts/    install_tools.sh, dev.sh, check_env.py, smoke_scan.py, test_repair.py, api_smoke.py
backend/tests/  25 pytest tests (zip safety, detection, probes, scoring, patch engine)
```

---

## Limitations (honest)

- Full container isolation requires Docker; without it the platform uses a process-isolated local
  sandbox (app bound to 127.0.0.1, scrubbed environment, per-scan home, hard timeouts) — the UI and
  reports state this explicitly. Docker is auto-detected; once Docker Desktop is running the platform
  switches to container sandboxes without configuration.
- On Windows, Windows Defender may quarantine `nuclei.exe` (false positive on the official release).
  If you want Nuclei, add an exclusion: `Add-MpPreference -ExclusionPath '<repo>\tools\bin'`.
- OWASP ZAP requires Docker or an admin-installed installer (official Windows releases are `.exe`
  installers only); without either, the built-in Dynamic Probes analyzer covers passive checks.
- Tool availability depends on the host; the Security Tools page shows exact status per tool and
  fallback analyzers cover the gaps. Coverage is never invented.
- AI patch generation requires a Groq key; without one, findings are still discovered, reproduced,
  and reported, but auto-repair is skipped (recorded as a limitation). Free-tier Groq keys are
  rate-limited, which slows AI-heavy stages (the client backs off and retries automatically).

---

*UPLOAD → TEST → ATTACK → FIND → FIX → VERIFY → DOWNLOAD*

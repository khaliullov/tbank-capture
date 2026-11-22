# tbank-capture

A self-hosted personal finance network discovery tool for T-Bank (Tinkoff Bank).

Passively observes JSON responses in a visible, manually operated Chromium session to identify and fingerprint financial API endpoints — without scraping HTML, automating authentication, or replaying private API calls.

---

## 1. Purpose and Architecture

The official T-Bank API does not expose personal transaction history to self-hosted clients. This tool helps an engineer discover which internal API endpoints carry transactions, accounts, cards, balances, payments, transfers, statements, and MCC data **by passively watching normal user navigation** in a persistent Chromium session.

The output is a structured discovery report (Markdown and JSON) that guides implementation of a deterministic personal transaction importer.

```
cmd/tbank-capture/
  main.go                      — Application wiring, startup sequence, graceful shutdown

internal/
  browser/
    browser.go                 — Playwright lifecycle, persistent Chromium context
    navigation.go              — Safe page navigation helpers

  capture/
    store.go                   — Bounded capture queue, async worker, raw response persistence
    response_handler.go        — Playwright OnResponse listener, size limits, secret rejection
    response_filter.go         — Domain/resource/content filtering, recursive JSON auth detection

  discovery/
    models.go                  — Shared domain types, Session, Metrics, CaptureJob
    fingerprint.go             — Dynamic URL path normalization, date param detection, fingerprint ID
    schema.go                  — Map-based JSON structural analyzer (values stripped), sanitizer
    classifier.go              — Deterministic rule-based scoring classifier (8 categories)
    collector.go               — Session-isolated observation aggregation, deep-copy snapshots
    report.go                  — Markdown & versioned JSON report generator

  telegram/
    bot.go                     — Control plane interface (private chat allowlist only)

  config/
    config.go                  — Environment variable loading with strict validation

data/
  browser-profile/             — Persistent Chromium profile (gitignored)
  raw/                         — Raw response bodies (gitignored, disabled by default)
  discovery/
    sessions/                  — Session metadata state (JSON)
    reports/                   — Generated discovery reports (Markdown and JSON)
```

### Startup Sequence

When `tbank-capture` launches, it executes the following 12-step initialization sequence:

1. **Configuration Loading & Validation**: Reads environment variables; fails fast on malformed values without silently falling back to defaults.
2. **Structured Logging**: Initializes JSON structured logging on `stderr`.
3. **Data Directory Preparation**: Ensures `./data/raw`, `./data/discovery/sessions`, and `./data/discovery/reports` exist with restricted permissions (`0700`).
4. **Collector Initialization**: Instantiates the discovery collector with configured JSON structural limits.
5. **Bounded Store Creation**: Instantiates the bounded capture store with capacity limit.
6. **Store Worker Startup**: Launches the async store worker in a dedicated goroutine.
7. **Playwright Startup**: Initializes the Playwright Go runtime.
8. **Persistent Browser Launch**: Opens a visible (headless=false by default) Chromium context with persistent user profile directory.
9. **Page Creation & Handler Attachment**: Opens an initial page and attaches the network response listener to the browser context to observe all pages.
10. **Telegram Bot Initialization**: Connects the control bot with chat-id allowlisting.
11. **Initial Bank Navigation**: Navigates the visible browser to `https://www.tbank.ru/` and sends a readiness notice to Telegram.
12. **Lifecycle Coordination**: Enters Telegram polling loop while monitoring OS signals (SIGINT, SIGTERM).

If any step during startup fails, all already-acquired resources (browser context, Playwright runtime, store worker) are safely cleaned up before exiting.

### Shutdown & Session Lifecycle Protocol

To ensure data integrity, prevent race conditions, and guarantee zero data loss of accepted capture jobs, `tbank-capture` implements deterministic session completion barriers:

1. **Per-Session Completion Barrier (`StopDiscovery`)**:
   - `handler.StopSession(sessionID)`: Synchronously halts new responses for this session.
   - `collector.BeginStopping(sessionID)`: Transitions session state to `stopping`, allowing pending queued jobs for this session to be processed while rejecting all other events.
   - `store.FlushSession(ctx, sessionID)`: Enqueues an explicit FIFO barrier job into the capture queue and blocks until the worker pops the barrier, guaranteeing all jobs accepted prior to the barrier have been processed.
   - `collector.FinalizeSession(sessionID)`: Transitions session state to `stopped`, snapshots immutable fingerprints and metrics, and persists session JSON.
   - Reports (Markdown & JSON) are generated from the consistent snapshot.
   - The browser and Store remain active and operational to service subsequent discovery sessions without process restart.
2. **Coordinated Shutdown Order**:
   - Step 1: `handler.Deactivate()` halts all incoming responses across all contexts.
   - Step 2: Active discovery session (if running) is flushed and finalized via `ctrl.StopDiscovery()`.
   - Step 3: `mgr.Stop()` terminates Chromium and closes browser contexts.
   - Step 4: `store.Close()`, `store.Wait()`, and `storeCancel()` drain any remaining store worker tasks.
   - Telegram poller shutdown terminates cleanly with bounded timeout to avoid deadlocks.

---

## 2. Non-Negotiable Security Constraints

The application is strictly passive:

- **Manual Operation Only**: The user manually logs in, enters passwords, and inputs SMS OTPs into the visible browser. The application never automates login or credentials.
- **Zero Credential Extraction**: The application never reads browser cookies, local storage, session storage, or profile databases.
- **Control-Plane Only Telegram**: Telegram receives only status metrics, session notifications, and report filenames. No financial values, account numbers, card numbers, or response bodies are ever sent to Telegram.
- **No API Replay**: Discovered endpoints are purely analyzed; the application never replays private bank requests.
- **No Anti-Detection Bypass**: Does not use stealth plugins, fingerprint spoofers, or bot-detection evasion patches.
- **No HTML Scraping**: Discovers APIs solely through passive JSON network traffic observation.
- **Metadata-Only by Default**: Raw response bodies are discarded immediately after structural schema analysis unless explicitly enabled.

---

## 3. Configuration

All configuration is provided via environment variables. Malformed or invalid explicitly set variables cause startup to fail immediately with a descriptive error. Secrets (e.g. `TELEGRAM_BOT_TOKEN`) are never printed in error messages or logs.

| Variable | Default | Type | Description |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | *required* | String | Telegram bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | *required* | Integer | Your private numeric Telegram chat ID |
| `USER_DATA_DIR` | `./data/browser-profile` | Path | Persistent Chromium profile directory |
| `RAW_CAPTURE_DIR` | `./data/raw` | Path | Directory for raw response files |
| `DISCOVERY_DIR` | `./data/discovery` | Path | Root directory for sessions and reports |
| `CAPTURE_ALLOWED_DOMAINS` | `tbank.ru,tinkoff.ru` | String | Comma-separated allowed domain roots for API discovery |
| `HEADLESS` | `false` | Boolean | Run browser headless (keep false for manual login) |
| `DISCOVERY_RAW_CAPTURE` | `false` | Boolean | Store raw response bodies to disk (sensitive!) |
| `MAX_RESPONSE_BODY_BYTES` | `10485760` (10 MB) | Integer | Max response body size to inspect |
| `CAPTURE_QUEUE_SIZE` | `128` | Integer | Bounded capture queue capacity |
| `MAX_JSON_DEPTH` | `32` | Integer | Max JSON object/array nesting depth |
| `MAX_ARRAY_ELEMENTS` | `20` | Integer | Max elements sampled per array |
| `MAX_JSON_FIELDS` | `5000` | Integer | Max unique JSON fields analyzed per response |
| `LOG_LEVEL` | `info` | String | Log level: `debug`, `info`, `warn`, or `error` |

### Example `.env`

```env
TELEGRAM_BOT_TOKEN=123456789:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=987654321

USER_DATA_DIR=./data/browser-profile
RAW_CAPTURE_DIR=./data/raw
DISCOVERY_DIR=./data/discovery
CAPTURE_ALLOWED_DOMAINS=tbank.ru,tinkoff.ru

HEADLESS=false
DISCOVERY_RAW_CAPTURE=false

MAX_RESPONSE_BODY_BYTES=10485760
CAPTURE_QUEUE_SIZE=128
MAX_JSON_DEPTH=32
MAX_ARRAY_ELEMENTS=20
MAX_JSON_FIELDS=5000
LOG_LEVEL=info
```

---

## 4. Setup and Installation

### Prerequisites

- **Go**: 1.21 or newer ([golang.org](https://go.dev/dl/))
- **Node.js** *(recommended, but not required)*: If Node.js is not installed locally, the installation script will automatically download a standalone Node.js binary.
- **Telegram Bot Token**: From [@BotFather](https://t.me/BotFather)
- **Telegram Chat ID**: Your private numeric Telegram user ID from [@userinfobot](https://t.me/userinfobot)

### Automated Installation (One Command)

Install the version-matched Playwright driver and the Chromium browser binary:

```bash
make playwright-install
```

Or run the script directly:

```bash
./scripts/install-playwright.sh
```

The installation script:
1. Derives the required Playwright driver version (v1.48.2) directly from `go.mod`.
2. Downloads and configures the driver in your local cache (`~/Library/Caches/ms-playwright-go` on macOS, `~/.cache/ms-playwright-go` on Linux, `%LOCALAPPDATA%\ms-playwright-go` on Windows).
3. Installs the exact Chromium revision (`chromium-1140`) required by the driver.
4. Avoids installing unrelated browsers (Firefox, WebKit).
5. Is completely idempotent and safe to re-run.

### Verifying the Installation

To verify that both the Playwright driver and Chromium executable are available without starting the browser or Telegram bot:

```bash
make playwright-check
```

Or using the CLI directly:

```bash
./tbank-capture --check-playwright
```

Expected output:
```text
Playwright preflight check passed: driver and Chromium are available.
```

### Linux-Specific Dependencies

On fresh Linux installations (Ubuntu, Debian, Fedora, Arch), Chromium requires system graphic and font libraries (e.g. `libnss3`, `libatk`, `libxcomposite`).

You can install these dependencies using:

```bash
./scripts/install-playwright.sh --with-deps
```

Or install them manually on Debian/Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y \
  libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
  libcups2 libdrm2 libdbus-1-3 libxcb1 libxkbcommon0 libx11-6 \
  libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libasound2
```

### Troubleshooting: "please install the driver first"

If you encounter:
```text
Playwright initialization failed:
  driver: not installed or incompatible
  required version: v1.48.2

Run:
  make playwright-install
```
or the legacy Playwright Go message:
```text
fatal: browser start: run playwright: please install the driver (v1.48.2) first: %!w(<nil>)
```

**Cause**: Microsoft permanently retired the legacy Azure CDN driver download bucket (`playwright.azureedge.net/builds/driver/`), causing unpatched driver downloads to fail with HTTP 404.

**Resolution**:
Run:
```bash
make playwright-install
```
This fetches the version-matched `playwright-core` package from the official npm registry, places the driver into your local cache directory, and installs the Chromium binary.

### Build Application

```bash
make build
# or: go build -o tbank-capture ./cmd/tbank-capture/
```

---

## 5. Running a Discovery Session

### Step 1: Start the application

Настройте переменные окружения через `.env`:
```bash
cp .env.example .env
# Отредактируйте .env и укажите TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID
make run
```

Или экспортируйте переменные вручную:
```bash
export TELEGRAM_BOT_TOKEN="your_token"
export TELEGRAM_CHAT_ID="your_chat_id"
./tbank-capture
```

The Chromium browser window opens and automatically navigates to `https://www.tbank.ru/`.

### Step 2: Receive the ready notification

Your Telegram bot sends:
> 🟢 T-Bank Capture started. Browser is ready.
> Use /discovery_start to begin, then navigate manually in the browser window.

### Step 3: Start discovery session

In your private chat with the bot, send:
```
/discovery_start
```
The bot responds with the new collision-resistant session ID (e.g. `sess-20261116T012345Z-a1b2c3d4`).

### Step 4: Authenticate manually in the browser

In the visible browser window:
1. Click "Log in".
2. Enter your phone number, password, and SMS OTP directly into the browser.
3. Complete any bank security checks manually.

**Never send passwords or OTPs to Telegram.**

### Step 5: Browse banking sections

Navigate through your personal account:
- Accounts overview
- Transaction history for each debit/credit account
- Card management page
- Date range filters (e.g., select last 30 days, last year)
- Paginated operation lists (scroll or click next page)
- Payments, transfers, and statements

Responses from `tbank.ru` are observed passively in the background.

### Step 6: Stop session and review reports

Send:
```
/discovery_stop
```
The application finalizes the session and saves discovery reports to `./data/discovery/reports/`.

---

## 6. Telegram Control Plane

The bot accepts commands exclusively in a **private chat** from the single configured `TELEGRAM_CHAT_ID`. Messages from any other user or from groups/channels are rejected immediately.

| Command | Description |
|---|---|
| `/start` | Bot overview and security notice |
| `/status` | Pipeline health status, browser state, active session, and actionable warnings |
| `/diagnostics` | Detailed diagnostic snapshot: observed hostnames, rejection reasons, resource types, and queue metrics |
| `/discovery_start` | Starts a new discovery session |
| `/discovery_stop` | Finalizes current session and generates discovery reports |
| `/report` | Returns the filename of the latest generated report |

---

## 7. Discovery Reports

Reports are written to `./data/discovery/reports/` with restrictive permissions (`0600`):

- `report-{session-id}.md`: Human-readable Markdown summary and endpoint analysis.
- `report-{session-id}.json`: Machine-readable versioned JSON report (version `"1"`).

### Report Contents

1. **Summary & Unified Metrics**:
   - `observed`: Total HTTP responses received by the handler.
   - `filtered`: Responses rejected before queueing (inactive handler, non-bank domain, auth endpoints, non-JSON content, or auth secrets).
   - `eligible`: Responses qualifying for capture (`observed = filtered + eligible`).
   - `enqueued`: Responses successfully placed in the bounded capture store queue.
   - `queue_overflow`: Eligible responses dropped because the capture queue was saturated (`eligible = enqueued + queue_overflow`).
   - `processed`: Capture jobs dequeued and processed by the discovery Collector.
   - `dropped`: Total jobs dropped (`dropped = queue_overflow + dropped_in_queue`).
   - `capture_failed`: Processed responses that failed body retrieval or exceeded size limit (`capture_failed <= processed`).
   - **Conservation Invariants**:
     - $\text{Observed} = \text{Filtered} + \text{Eligible}$
     - $\text{Eligible} = \text{Enqueued} + \text{QueueOverflow}$
     - $\text{Dropped} = \text{QueueOverflow} + \text{DroppedInQueue}$
     - $\text{Enqueued} = \text{Processed} + \text{DroppedInQueue}$
     - $\text{Observed} = \text{Filtered} + \text{Processed} + \text{Dropped}$
2. **Candidates by Category**:
   - `transactions`: Operation history collections with monetary amounts, timestamps, identifiers, and optional MCC/merchant metadata evaluated strictly within the same repeated record scope.
   - `accounts`: Bank account lists and contract details.
   - `cards`: Plastic/virtual card lists, PAN metadata, payment systems.
   - `balances`: Standalone balance endpoints.
   - `payments`: Utility, bill, and merchant payment endpoints.
   - `transfers`: P2P, SBP, and internal account transfer endpoints.
   - `statements`: Periodical extract and statement boundary endpoints.
3. **Endpoint Details**:
   - Normalized path (e.g. `/api/v1/accounts/{id}/operations`).
   - HTTP method and resource type (xhr/fetch).
   - Deterministic HTTP status distribution (e.g. `200×5 500×1`).
   - Observation count, average size, max size.
   - Pagination and date-range query parameter indicators.
   - Human-readable classification reasons.
   - Structural JSON schema table (field paths, types, optionality, semantic role).
4. **Unclassified Endpoints**: Low-confidence or unrecognized API endpoints.
5. **Capture Warnings**: Log of queue overflow occurrences, payload size limit rejections, or body read issues.

**Reports never contain real financial values, account numbers, card numbers, personal identifiers, or query parameter values.**

---

## 8. Privacy, Filtering, and Safety Mechanisms

- **Structurally Scoped Classification**: Transaction evidence is strictly evaluated within the *same* repeated record structure (e.g. array items `$.items[]`). Fields from unrelated JSON branches (such as account metadata co-located with unrelated items) cannot falsely synthesize a transaction history classification. Generic commission and amount/status fields alone do not imply payment or transfer endpoints without domain signals.
- **Content-Length Pre-Check**: Checks HTTP `Content-Length` header before reading body data. Payloads exceeding `MAX_RESPONSE_BODY_BYTES` are rejected prior to body allocation.
- **Recursive Credential Sanitization**: Analyzes JSON structure for authentication secrets (`access_token`, `refresh_token`, `id_token`, `authorization`, `bearer`, `password`, `otp`, `one_time_password`, `client_secret`, `session_token`, `csrf_token`, `private_key`, etc.) across camelCase, snake_case, and kebab-case. Rather than rejecting entire financial payloads containing unrelated tokens, true credentials are safely removed while business identifiers (`operationToken`, `pageToken`) and financial schemas are preserved for analysis. Sanitized responses never contain secret values, and raw storage only persists sanitized data.
- **Passive Hostname Telemetry**: Observes all network traffic passing through Chromium without reading response bodies of unknown hostnames. Safely aggregates total responses, resource types, and content types so legitimate first-party domains (e.g. `*.tinkoff.ru`) can be identified and added to `CAPTURE_ALLOWED_DOMAINS`.
- **Structured Rejection Tracking**: Every filtered response is assigned a terminal rejection reason (`non_allowed_domain`, `excluded_auth_path`, `unsupported_content_type`, `unsupported_resource_type`, `body_too_large`, etc.) to provide transparency into pipeline behavior.
- **Precise Path Segment Filtering**: Path exclusions use strict segment matching to reject login and token generation endpoints while preserving legitimate business endpoints (e.g. `/api/v1/session/accounts`).
- **Fail-Closed on Unparsable Data**: Bodies that cannot be parsed as valid JSON fail closed and are discarded.
- **Dynamic Path Normalization**: Dynamic UUIDs, numeric IDs, prefixed IDs (`acc_12345`, `op_98765`), and hashes are collapsed to `{id}` to ensure fingerprint stability.
- **Query Parameter Striping**: Query parameters are never stored in reports or fingerprints; date-range parameter presence is detected case-insensitively without retaining values.
- **Raw Response Capture Risks**: When `DISCOVERY_RAW_CAPTURE=true`, raw decrypted JSON response bodies are saved to disk under `./data/raw/` with `0600` permissions. This data contains sensitive personal banking information. Raw capture must remain disabled for regular discovery workflows.

---

## 9. Development and Testing

Run test suite:
```bash
go test ./...
```

Run test suite with race detector:
```bash
go test -race ./...
```

Linting and formatting:
```bash
go vet ./...
gofmt -l .
```

---

## 10. Known Limitations

1. **Chromium Internal Buffering**: In Playwright Go, response events are emitted after Chromium has received the HTTP payload. While application-level checks reject reading and storing oversized bodies, Chromium itself buffers responses in browser memory prior to event dispatch.
2. **Manual Playwright Installation**: Chromium must be installed via Playwright CLI before running.
3. **Session Resumption**: Each `/discovery_start` command starts a fresh in-memory session. Historical session files are retained on disk but not reloaded into memory.
4. **Queue Overflow Policy**: If the queue saturates under rapid navigation, new responses are dropped to prevent memory exhaustion and are counted in metrics and capture warnings.
5. **No Direct Attachment in Telegram**: Reports are referenced by filename rather than uploaded as Telegram file attachments to ensure sensitive financial structures remain local.

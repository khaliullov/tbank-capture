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

### Shutdown Protocol

To ensure data integrity and prevent channel panics or silent loss of jobs, the shutdown protocol follows a strict four-stage ordering:

1. **Handler Deactivation**: `handler.Deactivate()` stops accepting new HTTP responses and blocks any new enqueue attempts.
2. **Browser Shutdown**: `mgr.Stop()` closes browser pages, contexts, and Playwright. No further Chromium events can fire.
3. **Store Queue Draining**: `store.Close()` closes the channel, and `store.Wait()` allows the worker to process all remaining accepted jobs.
4. **Session Finalization**: If a discovery session was active, `ctrl.StopDiscovery()` stops the session, writes session state, and outputs the final reports.

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

- Go 1.21 or newer
- Telegram account and bot token ([BotFather](https://t.me/BotFather))
- Your Telegram numeric user ID ([@userinfobot](https://t.me/userinfobot))

### Install Playwright Chromium

```bash
go run github.com/playwright-community/playwright-go/cmd/playwright@v0.4802.0 install chromium
```

### Build

```bash
go build -o tbank-capture ./cmd/tbank-capture/
```

---

## 5. Running a Discovery Session

### Step 1: Start the application

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
The bot responds with the new session ID (e.g. `sess-20261116T012345Z`).

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
| `/status` | Current browser state, active session, and live counters |
| `/discovery_start` | Starts a new discovery session |
| `/discovery_stop` | Finalizes current session and generates discovery reports |
| `/report` | Returns the filename of the latest generated report |

---

## 7. Discovery Reports

Reports are written to `./data/discovery/reports/` with restrictive permissions (`0600`):

- `report-{session-id}.md`: Human-readable Markdown summary and endpoint analysis.
- `report-{session-id}.json`: Machine-readable versioned JSON report (version `"1"`).

### Report Contents

1. **Summary**:
   - Total observed responses, eligible JSON responses, unique endpoint fingerprints.
   - Candidate counts by category (only strong candidates with confidence $\ge 0.6$).
   - Total capture failures and queue overflows.
2. **Candidates by Category**:
   - `transactions`: Operation history collections with monetary amounts, timestamps, identifiers, and optional MCC/merchant metadata.
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

- **Content-Length Pre-Check**: Checks HTTP `Content-Length` header before reading body data. Payloads exceeding `MAX_RESPONSE_BODY_BYTES` are rejected prior to body allocation.
- **Recursive Secret Detection**: Analyzes JSON structure for authentication secrets (`access_token`, `refresh_token`, `id_token`, `authorization`, `bearer`, `password`, `otp`, `one_time_password`, `client_secret`, `session_token`, `csrf_token`, `private_key`, etc.) across camelCase, snake_case, and kebab-case. Any response containing secrets is immediately discarded.
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

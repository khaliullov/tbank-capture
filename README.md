# tbank-capture

A self-hosted personal finance network discovery tool for T-Bank (Tinkoff Bank).

Passively observes JSON responses in a visible browser session to identify and fingerprint financial API endpoints — without scraping HTML, automating authentication, or replaying private API calls.

---

## Purpose

The official T-Bank API does not expose personal transaction history to self-hosted clients. This tool helps an engineer discover which internal API endpoints carry transactions, accounts, cards, balances, and MCC data **by watching normal user navigation** in a persistent Chromium session.

The output is a structured discovery report that can guide implementation of a deterministic transaction importer.

---

## What it does NOT do

- Does not scrape HTML
- Does not automate UI interaction or clicking
- Does not capture OTPs, passwords, or authentication tokens
- Does not replay private API endpoints
- Does not bypass anti-fraud or rate-limiting systems
- Does not send financial data to Telegram or any external service
- Does not use an LLM to interact with the bank UI

---

## Architecture

```
cmd/tbank-capture/main.go        — entry point, wiring

internal/
  browser/
    browser.go                   — Playwright lifecycle, persistent context
    navigation.go                — page navigation helpers

  capture/
    store.go                     — bounded capture queue + worker goroutine
    response_handler.go          — Playwright OnResponse listener
    response_filter.go           — domain / type / content / auth filtering

  discovery/
    models.go                    — shared types
    fingerprint.go               — URL normalization, fingerprint ID
    schema.go                    — JSON structural analyzer, sanitizer
    classifier.go                — scoring-based endpoint classifier
    collector.go                 — per-session aggregation, fingerprint store
    report.go                    — Markdown + JSON report generation

  telegram/
    bot.go                       — Telegram control interface

  config/
    config.go                    — env-based configuration

data/
  browser-profile/               — persistent Chromium profile (gitignored)
  raw/                           — raw response bodies (gitignored, optional)
  discovery/
    sessions/                    — per-session fingerprint state
    reports/                     — discovery reports
```

---

## Configuration

All configuration is via environment variables. No secrets in flags or logs.

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | **required** | Telegram bot token |
| `TELEGRAM_CHAT_ID` | **required** | Your private chat ID (integer) |
| `USER_DATA_DIR` | `./data/browser-profile` | Persistent Chromium profile directory |
| `RAW_CAPTURE_DIR` | `./data/raw` | Directory for raw response bodies |
| `DISCOVERY_DIR` | `./data/discovery` | Root directory for sessions and reports |
| `HEADLESS` | `false` | Run browser headless (not recommended for manual auth) |
| `DISCOVERY_RAW_CAPTURE` | `false` | Enable raw body storage (sensitive!) |
| `MAX_RESPONSE_BODY_BYTES` | `10485760` | Maximum response body size (10 MB) |
| `CAPTURE_QUEUE_SIZE` | `128` | Bounded capture channel capacity |
| `MAX_JSON_DEPTH` | `32` | Maximum JSON nesting depth to analyze |
| `MAX_ARRAY_ELEMENTS` | `20` | Maximum array elements sampled per array |
| `MAX_JSON_FIELDS` | `5000` | Maximum total fields per document |
| `LOG_LEVEL` | `info` | Log level: debug / info / warn / error |

### Example `.env` file

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

## Setup

### Prerequisites

- Go 1.21+
- A Telegram bot token ([BotFather](https://t.me/BotFather))
- Your Telegram numeric chat ID (send a message to [@userinfobot](https://t.me/userinfobot))

### Install Playwright browsers

```bash
go run github.com/playwright-community/playwright-go/cmd/playwright@v0.4802.0 install chromium
```

### Build

```bash
go build -o tbank-capture ./cmd/tbank-capture/
```

---

## Running a Discovery Session

### 1. Start the application

```bash
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_CHAT_ID=...
./tbank-capture
```

The browser window opens and navigates to `https://www.tbank.ru/`.

### 2. Receive the ready notification

The bot sends: `🟢 T-Bank Capture started. Browser is ready.`

### 3. Start a session via Telegram

Send: `/discovery_start`

The bot confirms with the session ID.

### 4. Authenticate manually in the browser

Log into your T-Bank account using the visible browser window.

**Do not send your OTP or password to the Telegram bot.**

### 5. Navigate manually

Browse through:
- Account list
- Each account's transaction history
- Card list
- Change date ranges
- Scroll through paginated history

The application silently observes all eligible JSON responses.

### 6. Stop the session and generate a report

Send: `/discovery_stop`

The bot replies with the report file paths.

### 7. Check status at any time

Send: `/status`

---

## Telegram Commands

| Command | Description |
|---|---|
| `/start` | Explain the bot |
| `/status` | Current browser and session status |
| `/discovery_start` | Begin a new discovery session |
| `/discovery_stop` | Stop collection and generate report |
| `/report` | Show the path of the latest report |

**Only the configured `TELEGRAM_CHAT_ID` can use these commands.**

---

## Discovery Reports

Reports are written to `./data/discovery/reports/` by default.

Each session produces two files:

| File | Description |
|---|---|
| `report-{session-id}.md` | Human-readable Markdown report |
| `report-{session-id}.json` | Machine-readable JSON report (versioned) |

### Report contents

- Summary: total observed, eligible, unique fingerprints, candidates by category
- For each candidate:
  - Category and confidence score
  - Normalized path, HTTP method, resource type
  - Observation count, response sizes, status distribution
  - Pagination and date-range indicators
  - Classification reasons (explicit, no LLM)
  - JSON schema table: field paths, types, semantic classification
- Unknown endpoints list
- Capture warnings

**Reports never contain real financial values, card numbers, account numbers, or personal identifiers.**

---

## Privacy and Security

- Raw body capture is **off by default**
- When enabled, raw files are stored with `0600` permissions
- Data directories use `0700` permissions
- Query parameters are stripped from all stored URLs
- Authentication paths are excluded from observation
- Bodies containing obvious auth tokens are discarded
- No financial data is logged or sent to Telegram
- Raw capture data is in `.gitignore`

---

## Development

### Running tests

```bash
go test ./...
```

### With verbose output

```bash
go test -v ./...
```

### Linting

```bash
go vet ./...
gofmt -l .
```

---

## Known Limitations

1. **Playwright browser install is a manual step.** The bundled Chromium must be installed before first run via `playwright install chromium`.
2. **SQLite not used.** Fingerprints are persisted as JSON files. For large sessions with many unique endpoints, a SQLite backend would be more robust (marked as a future improvement).
3. **No session resumption.** Each `/discovery_start` starts a fresh in-memory session. Prior session JSON files are retained on disk but not reloaded.
4. **Queue overflow drops responses.** If the capture queue fills faster than the worker drains it (e.g., very rapid navigation), responses are dropped with a warning metric. Increase `CAPTURE_QUEUE_SIZE` or navigate more slowly.
5. **MCC classification is conservative.** Only fields explicitly named `mcc`, `mccCode`, or similar are classified as MCC candidates. Four-digit numbers in unrelated fields are not assumed to be MCC codes.
6. **No Telegram file upload.** Reports are referenced by path, not sent as attachments, to avoid accidentally sending sensitive data.
7. **Response body is read synchronously in the Playwright callback.** This is required by the Playwright Go API — the body must be read before the callback returns. The body is then copied into the channel for async processing.

---

## Gitignore

```
data/browser-profile/
data/raw/
data/discovery/sessions/
data/discovery/reports/
tbank-capture
```

# Security & Sensitive-Data Audit Report — T-Bank Discovery

## 1. Overview and Scope

This audit report documents the security posture, credential isolation, and sensitive-data safeguards implemented in `khaliullov/tbank-capture` as verified during Stage 4 and Stage 4.1.

- **Authoritative Connector Specification**: Maintained centrally at `family-finance/docs/tbank-personal-connector-spec.md`.
- **Audited Discovery Sessions**:
  - `sess-20261124T100411Z-c030930e` (Initial PIN and push capture)
  - `sess-20261124T110648Z-756169c4` (Post-remediation PIN-only capture)

---

## 2. Sensitive-Data Audit Across Persistence & Logging Paths

Every possible persistence, buffer, and logging mechanism in `tbank-capture` was audited:

| Path / Mechanism | Sensitive Data Risk | Verified Audit Findings & Status |
| :--- | :--- | :--- |
| **`data/raw/`** | Raw HTTP request/response payloads | **CLEAN (0 files)**. Raw capture was disabled (`DISCOVERY_RAW_CAPTURE=false`) in the active `.env` configuration. Directory exists with `0700` permissions. |
| **`data/discovery/sessions/`** | Session metadata & fingerprint snapshots | **CLEAN**. Files created with `0600` permissions. No response bodies, headers, cookies, or credentials persisted. Contains only structural path schemas and observation counters. |
| **`data/discovery/reports/`** | Generated JSON & Markdown reports | **CLEAN**. Files created with `0600` permissions. All `example_url` entries have query parameters (`?`) and fragments (`#`) stripped. |
| **Browser Profile (`data/browser-profile/`)** | Chromium cookies & local storage | **PROTECTED**. Directory created with `0700` permissions. Profile is strictly local to Chromium and ignored by Git (`.gitignore`). Cookies are never extracted, logged, or forwarded to discovery reports. |
| **Application Logs** | `slog` output to `os.Stderr` | **CLEAN**. URLs logged via `NormalizedURL` / `stripQueryAndCreds` (no query parameters or basic-auth credentials). Telegram bot tokens redacted from error logs. |
| **Temporary Files (`*.tmp`)** | Atomic write temp files | **CLEAN (0 files)**. Temporary files are renamed atomically or immediately removed on error. Ignored by `.gitignore`. |
| **Telegram Notifications** | Telemetry and status messages | **CLEAN**. Only high-level counts, status codes, and normalized paths sent. Response bodies, monetary amounts, and credentials are never transmitted. Private chat restricted to `cfg.TelegramChatID`. |
| **Error & Warning Messages** | Exception and capture warnings | **CLEAN**. `sanitizeWarning` strips URLs, query parameters, and credentials from `CaptureWarnings` before persistence. |

---

## 3. Specific Credential Verification

A targeted scan of all discovery artifacts (`data/discovery/**/*.json`, `*.md`) verified:

- **PIN (8390)**: **0 occurrences** of the actual PIN. (Appeared only as sub-second microsecond timestamp `02.839083Z` in older metadata, never as an authentication credential).
- **OTP (8490)**: **0 occurrences** of the OTP. (Appeared only as sub-integer in network byte counter `38490`).
- **Passwords & CVC**: **0 credential values**. All text occurrences in reports are field path names in UI layout schemas (e.g. `$.payload[].card.cvcConfirmRequired: bool`), never values.
- **Cookies & Authorization Headers**: **0 occurrences**. HTTP headers and cookies are strictly excluded from `CaptureJob` and `EndpointFingerprint`.
- **Card PAN**: **0 full 16-digit PANs**. Only masked representations (e.g. `*1234`) present.

---

## 4. Business Domain Authentication Endpoint Hardening

In addition to filtering dedicated authentication domains (`id.tbank.ru`, `passport.tbank.ru`, `sso.tbank.ru`), `Filter.CheckEligiblePath` enforces fail-closed exclusions on allowed business domains (`www.tbank.ru`, `api.tbank.ru`):

- **Excluded Hostnames**: `id.tbank.ru`, `passport.tbank.ru`, `auth.tbank.ru`, `sso.tbank.ru`, `*.tinkoff.ru`.
- **Excluded Path Segments**:
  - `login`, `signin`, `sign-in`, `logout`, `signout`, `sign-out`, `saml`, `sso`
  - `webauthn`, `2fa`, `mfa`, `preidentity`, `identity`, `passkey`
  - `pin`, `pincode`, `otp`, `challenge`, `captcha`
  - `session_status`, `session-status`, `sessionstatus`
  - Any `/auth/` path segment (e.g. `/api/common/v1/auth/short_personal_info`, `/navigation/auth/validate`)
  - Any `/session/` auth action: `check_auth`, `validate`, `status`, `check`, `state`, `init`, `ping`, `login`, `logout`
- **Preserved Business Endpoints**:
  - `/api/v1/cards/authorizations` (plural card hold balances)
  - `/api/v1/session/accounts` (business accounts portfolio)
  - `/api/v1/session/cards`, `/api/v1/session/balances`, `/api/v1/session/products`

---

## 5. Active Runtime Configuration Verification

Inspected `/Volumes/work/work/go/tbank-capture/.env`:
- `HEADLESS=false` (Visible browser window for user-driven manual authentication).
- `DISCOVERY_RAW_CAPTURE=false` (Raw body storage disabled).
- `CAPTURE_ALLOWED_DOMAINS=tbank.ru,tinkoff.ru` (Restricted to official banking domains).
- `USER_DATA_DIR=./data/browser-profile` (Persistent profile path).
- `TELEGRAM_CHAT_ID=475925115` (Authorized single-user control plane).

---

## 6. Audit Conclusion

The discovery pipeline in `khaliullov/tbank-capture` operates with least-privilege, fail-closed security guarantees. It observes retail banking APIs passively, filters all authentication workflows, sanitizes all error telemetry, and strictly prevents credential leakage.

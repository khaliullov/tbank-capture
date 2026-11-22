// Package telegram provides an authorized Telegram bot interface for controlling discovery sessions.
package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
	tele "gopkg.in/telebot.v3"
)

// Commander defines the control plane actions available to the bot controller.
type Commander interface {
	StartDiscovery() (discovery.SessionID, error)
	StopDiscovery() (mdPath, jsonPath string, err error)
	Status() BotStatus
	Diagnostics() discovery.DiagnosticsSnapshot
}

// BotStatus carries current application telemetry and session state for display.
type BotStatus struct {
	BrowserReady  bool
	OpenPages     int
	SessionActive bool
	SessionID     discovery.SessionID
	SessionStart  time.Time
	Metrics       discovery.Metrics
	Diagnostics   discovery.DiagnosticsSnapshot
}

// Bot wraps telebot.Bot with strict access controls and safety guards.
type Bot struct {
	log       *slog.Logger
	bot       *tele.Bot
	allowedID int64
	commander Commander
	reportDir string
}

// NewBot creates and configures the Telegram bot.
// Secrets such as token are never logged.
func NewBot(log *slog.Logger, token string, allowedChatID int64, reportDir string, commander Commander) (*Bot, error) {
	settings := tele.Settings{
		Token:  token,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second},
	}

	bot, err := tele.NewBot(settings)
	if err != nil {
		return nil, fmt.Errorf("create telebot: %w", err)
	}

	b := &Bot{
		log:       log,
		bot:       bot,
		allowedID: allowedChatID,
		commander: commander,
		reportDir: reportDir,
	}
	b.registerHandlers()
	return b, nil
}

func (b *Bot) registerHandlers() {
	mw := b.authMiddleware()

	b.bot.Handle("/start", mw(b.handleStart))
	b.bot.Handle("/status", mw(b.handleStatus))
	b.bot.Handle("/diagnostics", mw(b.handleDiagnostics))
	b.bot.Handle("/discovery_start", mw(b.handleDiscoveryStart))
	b.bot.Handle("/discovery_stop", mw(b.handleDiscoveryStop))
	b.bot.Handle("/report", mw(b.handleReport))
}

// authMiddleware enforces the private-chat-only, single authorized user security policy.
// It guards against incomplete or malformed updates to prevent nil-pointer panics.
func (b *Bot) authMiddleware() func(tele.HandlerFunc) tele.HandlerFunc {
	return func(next tele.HandlerFunc) tele.HandlerFunc {
		return func(c tele.Context) error {
			if c == nil || c.Chat() == nil || c.Sender() == nil {
				return nil
			}

			if c.Chat().Type != tele.ChatPrivate {
				b.log.Warn("rejected command from non-private chat", "chatType", c.Chat().Type)
				return c.Send("This bot only operates in private chats.")
			}

			senderID := c.Sender().ID
			chatID := c.Chat().ID
			if int64(senderID) != b.allowedID || chatID != b.allowedID {
				b.log.Warn("rejected unauthorized telegram command",
					"senderID", senderID, "chatID", chatID)
				return c.Send("Unauthorized.")
			}

			return next(c)
		}
	}
}

func (b *Bot) handleStart(c tele.Context) error {
	msg := `*T-Bank Capture Control Bot*

Available commands:
/status — quick health and pipeline status
/diagnostics — detailed diagnostic telemetry and hostnames
/discovery_start — begin a discovery session
/discovery_stop — stop collection and generate reports
/report — name of the latest report

⚠️ *Security Note*: Never send passwords, OTPs, or any authentication credentials here.`
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleStatus(c tele.Context) error {
	st := b.commander.Status()
	diag := b.commander.Diagnostics()
	var sb strings.Builder
	sb.WriteString("*Capture Pipeline Status*\n\n")

	// 1. Is Chromium running?
	sb.WriteString(fmt.Sprintf("• *Chromium running*: %v (open tabs: %d)\n", st.BrowserReady, st.OpenPages))

	// 2. Is discovery active?
	sb.WriteString(fmt.Sprintf("• *Discovery active*: %v\n", st.SessionActive))
	if st.SessionActive {
		sb.WriteString(fmt.Sprintf("  Session ID: `%s`\n", st.SessionID))
		sb.WriteString(fmt.Sprintf("  Started: %s\n", st.SessionStart.Format(time.RFC3339)))
	}

	// 3. Is network traffic being observed?
	networkObserved := diag.TotalObserved > 0
	sb.WriteString(fmt.Sprintf("• *Network traffic observed*: %v (%d total responses)\n", networkObserved, diag.TotalObserved))

	// 4. Are bank-related domains observed?
	var bankDomainsObserved bool
	for _, h := range diag.Hostnames {
		if strings.Contains(h.Hostname, "tbank.ru") || strings.Contains(h.Hostname, "tinkoff.ru") {
			bankDomainsObserved = true
			break
		}
	}
	sb.WriteString(fmt.Sprintf("• *Bank domains observed*: %v (%d unique hostnames)\n", bankDomainsObserved, diag.UniqueHostnames))

	// 5. Are JSON responses received?
	jsonCount := 0
	for ct, count := range diag.ContentDist {
		if strings.Contains(strings.ToLower(ct), "json") {
			jsonCount += count
		}
	}
	sb.WriteString(fmt.Sprintf("• *JSON responses received*: %v (%d JSON responses)\n", jsonCount > 0, jsonCount))

	// 6. Are responses being rejected?
	sb.WriteString(fmt.Sprintf("• *Responses rejected*: %d / %d\n", st.Metrics.Filtered, diag.TotalObserved))

	// 7. Are endpoints being discovered?
	sb.WriteString(fmt.Sprintf("• *Endpoints discovered*: %d unique fingerprints\n", diag.UniqueFingerprints))
	if st.Metrics.TransactionCandidates > 0 {
		sb.WriteString(fmt.Sprintf("  Transaction candidates: %d\n", st.Metrics.TransactionCandidates))
	}

	// Actionable pipeline health warnings
	sb.WriteString("\n*Pipeline Health Warnings*:\n")
	warnings := 0
	if !st.BrowserReady {
		sb.WriteString("⚠️ Chromium is not running.\n")
		warnings++
	} else if !st.SessionActive {
		sb.WriteString("ℹ️ No active discovery session. Use /discovery_start to begin capturing.\n")
		warnings++
	} else {
		if diag.TotalObserved == 0 {
			sb.WriteString("⚠️ No network events observed yet. Make sure Chromium is navigating to bank pages.\n")
			warnings++
		} else if !bankDomainsObserved {
			sb.WriteString("⚠️ Network events observed, but no allowed bank domains observed. Check browser URL or CAPTURE_ALLOWED_DOMAINS.\n")
			warnings++
		} else if jsonCount == 0 {
			sb.WriteString("⚠️ Allowed domains observed, but no JSON responses received yet. Navigate to accounts/transactions in the UI.\n")
			warnings++
		} else if diag.Eligible == 0 {
			sb.WriteString("⚠️ JSON responses observed, but all were rejected by filter. Check /diagnostics for rejection reasons.\n")
			warnings++
		} else if diag.Enqueued > 0 && diag.Processed == 0 {
			sb.WriteString("⚠️ Responses enqueued, but not processed yet by worker.\n")
			warnings++
		} else if diag.Processed > 0 && diag.UniqueFingerprints == 0 {
			sb.WriteString("⚠️ Responses processed, but no useful fingerprints discovered yet.\n")
			warnings++
		}
	}
	if warnings == 0 {
		sb.WriteString("✅ Pipeline healthy and capturing.\n")
	}

	return c.Send(sb.String(), tele.ModeMarkdown)
}

func (b *Bot) handleDiagnostics(c tele.Context) error {
	st := b.commander.Status()
	diag := b.commander.Diagnostics()

	var sb strings.Builder
	sb.WriteString("*Diagnostic Telemetry Snapshot*\n\n")

	sb.WriteString(fmt.Sprintf("*Browser*: Ready=%v, Open tabs=%d\n", st.BrowserReady, st.OpenPages))
	if st.SessionActive {
		sb.WriteString(fmt.Sprintf("*Session*: Active (`%s`)\n", st.SessionID))
	} else {
		sb.WriteString("*Session*: Inactive\n")
	}

	sb.WriteString(fmt.Sprintf("\n*Responses*: Total observed=%d, Unique hostnames=%d\n",
		diag.TotalObserved, diag.UniqueHostnames))

	// Top observed hostnames (up to 5)
	if len(diag.Hostnames) > 0 {
		sb.WriteString("\n*Top Hostnames*:\n")
		limit := 5
		if len(diag.Hostnames) < limit {
			limit = len(diag.Hostnames)
		}
		for i := 0; i < limit; i++ {
			h := diag.Hostnames[i]
			sb.WriteString(fmt.Sprintf("• `%s`: %d\n", h.Hostname, h.TotalCount))
		}
	}

	// Resource Type Distribution (XHR/Fetch)
	xhrFetchCount := 0
	if c, ok := diag.ResourceDist["xhr"]; ok {
		xhrFetchCount += c
	}
	if c, ok := diag.ResourceDist["fetch"]; ok {
		xhrFetchCount += c
	}
	sb.WriteString(fmt.Sprintf("\n*Resource Types*: XHR/Fetch=%d, Total types=%d\n", xhrFetchCount, len(diag.ResourceDist)))
	for rt, count := range diag.ResourceDist {
		sb.WriteString(fmt.Sprintf("• `%s`: %d\n", rt, count))
	}

	// JSON response count
	jsonCount := 0
	for ct, count := range diag.ContentDist {
		if strings.Contains(strings.ToLower(ct), "json") {
			jsonCount += count
		}
	}
	sb.WriteString(fmt.Sprintf("\n*JSON Responses*: %d\n", jsonCount))

	// Rejections by reason
	sb.WriteString(fmt.Sprintf("\n*Rejections by Reason* (Total filtered: %d):\n", st.Metrics.Filtered))
	if len(diag.Rejections) == 0 {
		sb.WriteString("• None\n")
	} else {
		for reason, count := range diag.Rejections {
			sb.WriteString(fmt.Sprintf("• `%s`: %d\n", reason, count))
		}
	}

	// Queue & processing stats
	sb.WriteString("\n*Queue & Processing*:\n")
	sb.WriteString(fmt.Sprintf("• Eligible responses: %d\n", diag.Eligible))
	sb.WriteString(fmt.Sprintf("• Enqueued jobs: %d\n", diag.Enqueued))
	sb.WriteString(fmt.Sprintf("• Ever reached queue: %v\n", diag.HasEligibleEnqueued))
	sb.WriteString(fmt.Sprintf("• Queue overflow: %d\n", diag.QueueOverflow))
	sb.WriteString(fmt.Sprintf("• Processed jobs: %d\n", diag.Processed))
	sb.WriteString(fmt.Sprintf("• Processing failures: %d\n", diag.ProcessingFailed))
	sb.WriteString(fmt.Sprintf("• Unique fingerprints: %d\n", diag.UniqueFingerprints))

	return c.Send(sb.String(), tele.ModeMarkdown)
}

func (b *Bot) handleDiscoveryStart(c tele.Context) error {
	id, err := b.commander.StartDiscovery()
	if err != nil {
		b.log.Error("start discovery failed", "err", err)
		return c.Send(fmt.Sprintf("Failed to start: %s", sanitizeError(err)))
	}
	msg := fmt.Sprintf("✅ Discovery session started.\nSession ID: `%s`\n\nPlease navigate manually in the browser window.", id)
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleDiscoveryStop(c tele.Context) error {
	mdPath, jsonPath, err := b.commander.StopDiscovery()
	if err != nil {
		b.log.Error("stop discovery failed", "err", err)
		return c.Send(fmt.Sprintf("Failed to stop: %s", sanitizeError(err)))
	}
	// Return file basenames to avoid exposing internal absolute filesystem paths
	msg := fmt.Sprintf("🛑 Discovery session stopped.\n\nReports generated:\n• Markdown: `%s`\n• JSON: `%s`",
		filepath.Base(mdPath), filepath.Base(jsonPath))
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleReport(c tele.Context) error {
	pattern := filepath.Join(b.reportDir, "report-*.md")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return c.Send("No reports found. Run /discovery_stop to generate one.")
	}
	latest := matches[len(matches)-1]
	return c.Send(fmt.Sprintf("Latest report: `%s`", filepath.Base(latest)), tele.ModeMarkdown)
}

// Start begins polling in a background goroutine and stops cleanly when ctx is cancelled.
// It ensures that shutdown waits for the Telegram poller goroutine to terminate cleanly
// using telebot's lifecycle guarantees, avoiding shutdown deadlocks.
func (b *Bot) Start(ctx context.Context) {
	b.log.Info("telegram bot poller starting")
	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		b.bot.Start()
	}()

	select {
	case <-pollerDone:
		b.log.Warn("telegram poller exited prematurely")
	case <-ctx.Done():
		b.bot.Stop()
		select {
		case <-pollerDone:
			b.log.Info("telegram bot poller stopped")
		case <-time.After(3 * time.Second):
			b.log.Warn("telegram bot poller did not terminate within timeout; continuing shutdown")
		}
	}
}

// Send sends a plain text notification to the authorized chat ID. Never send financial data.
func (b *Bot) Send(text string) error {
	chat := &tele.Chat{ID: b.allowedID}
	_, err := b.bot.Send(chat, text)
	return err
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip internal paths if present
	if idx := strings.Index(msg, "/"); idx >= 0 {
		msg = msg[:idx]
	}
	return strings.TrimSpace(msg)
}

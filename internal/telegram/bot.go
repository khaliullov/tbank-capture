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
}

// BotStatus carries current application telemetry and session state for display.
type BotStatus struct {
	BrowserReady  bool
	SessionActive bool
	SessionID     discovery.SessionID
	SessionStart  time.Time
	Metrics       discovery.Metrics
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
/status — browser and discovery status
/discovery_start — begin a discovery session
/discovery_stop — stop collection and generate reports
/report — name of the latest report

⚠️ *Security Note*: Never send passwords, OTPs, or any authentication credentials here.`
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleStatus(c tele.Context) error {
	st := b.commander.Status()
	var sb strings.Builder
	sb.WriteString("*Capture Status*\n")
	sb.WriteString(fmt.Sprintf("Browser ready: %v\n", st.BrowserReady))
	sb.WriteString(fmt.Sprintf("Session active: %v\n", st.SessionActive))
	if st.SessionActive {
		sb.WriteString(fmt.Sprintf("Session ID: `%s`\n", st.SessionID))
		sb.WriteString(fmt.Sprintf("Started: %s\n", st.SessionStart.Format(time.RFC3339)))
		m := st.Metrics
		sb.WriteString(fmt.Sprintf("Observed: %d | Filtered: %d | Eligible: %d | Processed: %d\n",
			m.Observed, m.Filtered, m.Eligible, m.Processed))
		sb.WriteString(fmt.Sprintf("Dropped: %d (Queue overflow: %d) | Failed: %d\n",
			m.Dropped, m.QueueOverflow, m.CaptureFailed))
		sb.WriteString(fmt.Sprintf("Fingerprints: %d | Transaction candidates: %d\n",
			m.UniqueFingerprints, m.TransactionCandidates))
	} else {
		sb.WriteString("No active session. Use /discovery_start to begin.")
	}
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

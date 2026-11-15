// Package telegram provides a Telegram bot interface for controlling the discovery session.
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

// Commander defines the commands available to the bot controller.
type Commander interface {
	StartDiscovery() (discovery.SessionID, error)
	StopDiscovery() (mdPath, jsonPath string, err error)
	Status() BotStatus
}

// BotStatus carries current application status for display.
type BotStatus struct {
	BrowserReady  bool
	SessionActive bool
	SessionID     discovery.SessionID
	SessionStart  time.Time
	Metrics       discovery.Metrics
}

// Bot wraps a telebot instance with safety guards.
type Bot struct {
	log       *slog.Logger
	bot       *tele.Bot
	allowedID int64
	commander Commander
	reportDir string
}

// NewBot creates and configures the Telegram bot.
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

// authMiddleware returns a middleware that validates sender.
func (b *Bot) authMiddleware() func(tele.HandlerFunc) tele.HandlerFunc {
	return func(next tele.HandlerFunc) tele.HandlerFunc {
		return func(c tele.Context) error {
			senderID := c.Sender().ID
			chatID := c.Chat().ID
			if int64(senderID) != b.allowedID || chatID != b.allowedID {
				b.log.Warn("rejected unauthorized telegram command",
					"senderID", senderID, "chatID", chatID)
				return c.Send("Unauthorized.")
			}
			if c.Chat().Type != tele.ChatPrivate {
				return c.Send("This bot only works in private chat.")
			}
			return next(c)
		}
	}
}

func (b *Bot) handleStart(c tele.Context) error {
	msg := `*T-Bank Capture Bot*

Available commands:
/status — browser and discovery status
/discovery_start — begin a discovery session
/discovery_stop — stop collection and generate a report
/report — path of the latest report

⚠️ Do NOT send passwords, OTPs, or any authentication data here.`
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleStatus(c tele.Context) error {
	st := b.commander.Status()
	var sb strings.Builder
	sb.WriteString("*Status*\n")
	sb.WriteString(fmt.Sprintf("Browser ready: %v\n", st.BrowserReady))
	sb.WriteString(fmt.Sprintf("Session active: %v\n", st.SessionActive))
	if st.SessionActive {
		sb.WriteString(fmt.Sprintf("Session ID: `%s`\n", st.SessionID))
		sb.WriteString(fmt.Sprintf("Started: %s\n", st.SessionStart.Format(time.RFC3339)))
		m := st.Metrics
		sb.WriteString(fmt.Sprintf("Observed: %d | Eligible: %d | Fingerprints: %d\n",
			m.TotalObserved, m.EligibleResponses, m.UniqueFingerprints))
		sb.WriteString(fmt.Sprintf("Transaction candidates: %d\n", m.TransactionCandidates))
		if m.QueueOverflows > 0 {
			sb.WriteString(fmt.Sprintf("⚠️ Queue overflows: %d\n", m.QueueOverflows))
		}
	}
	return c.Send(sb.String(), tele.ModeMarkdown)
}

func (b *Bot) handleDiscoveryStart(c tele.Context) error {
	id, err := b.commander.StartDiscovery()
	if err != nil {
		b.log.Error("start discovery failed", "err", err)
		return c.Send(fmt.Sprintf("Failed to start: %v", err))
	}
	msg := fmt.Sprintf("✅ Discovery session started.\nSession ID: `%s`\n\nPlease open https://www.tbank.ru/ and navigate manually.", id)
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleDiscoveryStop(c tele.Context) error {
	mdPath, jsonPath, err := b.commander.StopDiscovery()
	if err != nil {
		b.log.Error("stop discovery failed", "err", err)
		return c.Send(fmt.Sprintf("Failed to stop: %v", err))
	}
	msg := fmt.Sprintf("🛑 Discovery session stopped.\n\nMarkdown report: `%s`\nJSON report: `%s`",
		mdPath, jsonPath)
	return c.Send(msg, tele.ModeMarkdown)
}

func (b *Bot) handleReport(c tele.Context) error {
	// Find the most recent report in the report directory.
	pattern := filepath.Join(b.reportDir, "report-*.md")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return c.Send("No reports found. Run /discovery_stop to generate one.")
	}
	// Return the last one (lexicographically, session IDs are time-ordered).
	latest := matches[len(matches)-1]
	return c.Send(fmt.Sprintf("Latest report: `%s`", latest), tele.ModeMarkdown)
}

// Start begins polling in a goroutine and returns when ctx is cancelled.
func (b *Bot) Start(ctx context.Context) {
	go b.bot.Start()
	<-ctx.Done()
	b.bot.Stop()
	b.log.Info("telegram bot stopped")
}

// Send sends a message to the allowed chat. Must not contain financial data.
func (b *Bot) Send(text string) error {
	chat := &tele.Chat{ID: b.allowedID}
	_, err := b.bot.Send(chat, text)
	return err
}

// Command tbank-capture runs the T-Bank network discovery capture service.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/khaliullov/tbank-capture/internal/browser"
	"github.com/khaliullov/tbank-capture/internal/capture"
	"github.com/khaliullov/tbank-capture/internal/config"
	"github.com/khaliullov/tbank-capture/internal/discovery"
	"github.com/khaliullov/tbank-capture/internal/telegram"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Load and validate configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// 2. Initialize structured logging
	log := buildLogger(cfg.LogLevel)
	log.Info("tbank-capture starting", "headless", cfg.Headless, "rawCapture", cfg.RawCaptureEnabled)

	// Ensure data directories exist with restricted 0700 permissions
	for _, dir := range []string{
		cfg.RawCaptureDir,
		cfg.DiscoveryDir,
		filepath.Join(cfg.DiscoveryDir, "sessions"),
		filepath.Join(cfg.DiscoveryDir, "reports"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	// Context for graceful shutdown on OS signals (SIGINT, SIGTERM)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Track resources for safe release on partial startup error
	var startedSuccessfully bool
	var cleanups []func()
	defer func() {
		if !startedSuccessfully {
			log.Info("releasing resources after partial startup failure")
			for i := len(cleanups) - 1; i >= 0; i-- {
				cleanups[i]()
			}
		}
	}()

	// 3. Create discovery collector
	analyzerCfg := discovery.AnalyzerConfig{
		MaxDepth:      cfg.MaxJSONDepth,
		MaxArrayElems: cfg.MaxArrayElems,
		MaxFields:     cfg.MaxJSONFields,
	}
	sessionDir := filepath.Join(cfg.DiscoveryDir, "sessions")
	collector := discovery.NewCollector(log, sessionDir, analyzerCfg)

	// 4. Create bounded capture store
	store := capture.NewStore(log, cfg.RawCaptureDir, cfg.RawCaptureEnabled, cfg.CaptureQueueSize, collector)

	// 5. Start store worker goroutine
	storeCtx, storeCancel := context.WithCancel(context.Background())
	go store.Run(storeCtx)
	cleanups = append(cleanups, func() {
		storeCancel()
		store.Close()
		store.Wait()
	})

	// Response filter
	filter := capture.NewFilter(log, cfg.MaxResponseBodySize, []string{"tbank.ru"})

	// 6. & 7. Browser manager: start Playwright and launch persistent Chromium context
	mgr := browser.NewManager(log, cfg.UserDataDir, cfg.Headless)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("browser start: %w", err)
	}
	cleanups = append(cleanups, func() {
		mgr.Stop()
	})

	// 8. Open initial browser page
	page, err := mgr.NewPage()
	if err != nil {
		return fmt.Errorf("open initial page: %w", err)
	}

	// Attach response handler to browser context to observe all pages
	handler := capture.NewResponseHandler(
		log,
		filter,
		store.Queue(),
		func() discovery.SessionID {
			sess := collector.ActiveSession()
			if sess == nil || !sess.Active {
				return ""
			}
			return sess.ID
		},
		cfg.MaxResponseBodySize,
	)
	handler.SetCollector(collector)
	handler.SetSubmitter(store)
	handler.AttachContext(mgr.Context())
	cleanups = append(cleanups, func() {
		handler.Deactivate()
	})

	// 9. Navigator
	nav := browser.NewNavigator(log, page)

	// Report generator
	reportDir := filepath.Join(cfg.DiscoveryDir, "reports")
	gen := discovery.NewGenerator(reportDir)

	// 10. Application controller (thread-safe commander for Telegram)
	ctrl := &controller{
		log:       log,
		collector: collector,
		gen:       gen,
		mgr:       mgr,
		nav:       nav,
	}

	// Initialize Telegram bot controller
	bot, err := telegram.NewBot(log, cfg.TelegramBotToken, cfg.TelegramChatID, reportDir, ctrl)
	if err != nil {
		return fmt.Errorf("telegram bot init: %w", err)
	}

	// 11. Initial navigation to T-Bank homepage
	log.Info("navigating to bank homepage")
	if err := nav.GotoURL(ctx, "https://www.tbank.ru/"); err != nil {
		log.Warn("initial navigation failed", "err", err)
	}

	// Notify user via Telegram that browser is ready
	_ = bot.Send("🟢 T-Bank Capture started. Browser is ready.\n\nUse /discovery_start to begin, then navigate manually in the browser window.")

	// Startup was successful; transfer lifecycle management to orderly shutdown sequence
	startedSuccessfully = true

	// 12. Run Telegram bot polling (blocks until OS signal triggers ctx.Done())
	log.Info("tbank-capture is ready and awaiting commands")
	bot.Start(ctx)

	// --- Coordinated Graceful Shutdown Protocol ---
	// Shutdown Order:
	// 1. Handler deactivation: Stop accepting or enqueuing new network responses.
	// 2. Browser shutdown: Close pages and context; terminate Chromium/Playwright.
	// 3. Store queue draining: Close queue, drain accepted jobs, and terminate worker.
	// 4. Session finalization: Stop active session, persist state, and generate report.
	log.Info("graceful shutdown initiated")

	// Step 1: Deactivate handler
	handler.Deactivate()

	// Step 2: Stop browser
	mgr.Stop()

	// Step 3: Stop store and drain remaining accepted jobs
	store.Close()
	store.Wait()
	storeCancel()

	// Step 4: Finalize active discovery session if one was running
	if sess := collector.ActiveSession(); sess != nil && sess.Active {
		log.Info("finalizing active discovery session on shutdown", "sessionID", sess.ID)
		if mdPath, jsonPath, err := ctrl.StopDiscovery(); err != nil {
			log.Warn("failed to generate final report on shutdown", "err", err)
		} else {
			log.Info("final report generated", "markdown", mdPath, "json", jsonPath)
		}
	}

	log.Info("tbank-capture shutdown complete")
	return nil
}

// controller coordinates session lifecycle and implements telegram.Commander safely.
type controller struct {
	mu        sync.Mutex
	log       *slog.Logger
	collector *discovery.Collector
	gen       *discovery.Generator
	mgr       *browser.Manager
	nav       *browser.Navigator
}

func (c *controller) StartDiscovery() (discovery.SessionID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if sess := c.collector.ActiveSession(); sess != nil && sess.Active {
		return sess.ID, fmt.Errorf("session already active: %s", sess.ID)
	}

	id := discovery.SessionID(fmt.Sprintf("sess-%s", time.Now().UTC().Format("20060102T150405Z")))
	c.collector.StartSession(id)
	c.log.Info("discovery session started", "id", id)
	return id, nil
}

func (c *controller) StopDiscovery() (mdPath, jsonPath string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sess := c.collector.StopSession()
	if sess == nil {
		return "", "", fmt.Errorf("no active session")
	}

	fps := c.collector.Fingerprints()
	metrics := c.collector.Metrics()

	if err := c.collector.PersistSession(); err != nil {
		c.log.Warn("persist session failed", "err", err)
	}

	mdPath, jsonPath, err = c.gen.Generate(sess, fps, metrics)
	if err != nil {
		return "", "", fmt.Errorf("generate report: %w", err)
	}

	c.log.Info("discovery report generated", "md", mdPath, "json", jsonPath)
	return mdPath, jsonPath, nil
}

func (c *controller) Status() telegram.BotStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	sess := c.collector.ActiveSession()
	st := telegram.BotStatus{
		BrowserReady: c.mgr != nil && c.mgr.Context() != nil,
		Metrics:      c.collector.Metrics(),
	}
	if sess != nil {
		st.SessionActive = sess.Active
		st.SessionID = sess.ID
		st.SessionStart = sess.StartedAt
	}
	return st
}

func buildLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

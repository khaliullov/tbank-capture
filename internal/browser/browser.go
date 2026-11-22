// Package browser manages the Playwright lifecycle and persistent browser context.
package browser

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	pw "github.com/playwright-community/playwright-go"
)

// Manager owns the Playwright instance and persistent browser context.
type Manager struct {
	log         *slog.Logger
	userDataDir string
	headless    bool

	mu         sync.Mutex
	playwright *pw.Playwright
	context    pw.BrowserContext
	pages      []pw.Page
	checker    PreflightChecker
}

// NewManager creates a Manager. Call Start to launch the browser.
func NewManager(log *slog.Logger, userDataDir string, headless bool) *Manager {
	return &Manager{
		log:         log,
		userDataDir: userDataDir,
		headless:    headless,
		checker:     NewPreflightChecker(),
	}
}

// SetPreflightChecker configures a custom preflight checker (useful for testing).
func (m *Manager) SetPreflightChecker(c PreflightChecker) {
	m.mu.Lock()
	m.checker = c
	m.mu.Unlock()
}

// Start launches Playwright and opens a persistent Chromium context.
func (m *Manager) Start(_ context.Context) error {
	if err := os.MkdirAll(m.userDataDir, 0700); err != nil {
		return fmt.Errorf("create user data dir: %w", err)
	}

	m.mu.Lock()
	checker := m.checker
	m.mu.Unlock()

	// 1. Run preflight validation to detect missing driver or browser before starting Playwright
	if checker != nil {
		if _, err := checker.Check(); err != nil {
			return err
		}
	}

	m.log.Info("starting playwright")
	playwright, err := pw.Run()
	if err != nil {
		return formatStartupError("run playwright", RequiredDriverVersion(), err)
	}

	absDir, err := filepath.Abs(m.userDataDir)
	if err != nil {
		_ = playwright.Stop()
		return fmt.Errorf("resolve user data dir: %w", err)
	}

	headless := m.headless
	bctx, err := playwright.Chromium.LaunchPersistentContext(absDir,
		pw.BrowserTypeLaunchPersistentContextOptions{
			Headless: pw.Bool(headless),
		},
	)
	if err != nil {
		_ = playwright.Stop()
		return formatStartupError("launch persistent context", RequiredDriverVersion(), err)
	}

	m.mu.Lock()
	m.playwright = playwright
	m.context = bctx
	m.mu.Unlock()

	m.log.Info("browser context started", "headless", headless, "userDataDir", absDir)
	return nil
}

// Context returns the BrowserContext. Panics if not started.
func (m *Manager) Context() pw.BrowserContext {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.context
}

// IsRunning returns whether the browser context is active.
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.context != nil
}

// OpenPagesCount returns the number of open pages/tabs in the browser context.
func (m *Manager) OpenPagesCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.context == nil {
		return 0
	}
	return len(m.context.Pages())
}

// NewPage opens a new page in the persistent context.
func (m *Manager) NewPage() (pw.Page, error) {
	m.mu.Lock()
	bctx := m.context
	m.mu.Unlock()
	if bctx == nil {
		return nil, fmt.Errorf("browser context not started")
	}
	page, err := bctx.NewPage()
	if err != nil {
		return nil, fmt.Errorf("new page: %w", err)
	}
	m.mu.Lock()
	m.pages = append(m.pages, page)
	m.mu.Unlock()
	return page, nil
}

// Stop closes the context and stops Playwright.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.context != nil {
		if err := m.context.Close(); err != nil {
			m.log.Warn("closing browser context", "err", err)
		}
		m.context = nil
	}
	if m.playwright != nil {
		if err := m.playwright.Stop(); err != nil {
			m.log.Warn("stopping playwright", "err", err)
		}
		m.playwright = nil
	}
	m.log.Info("browser stopped")
}

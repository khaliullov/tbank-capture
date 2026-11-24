package browser

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	pw "github.com/playwright-community/playwright-go"
)

// Navigator wraps a Page with safe navigation helpers.
type Navigator struct {
	log  *slog.Logger
	page pw.Page
}

// NewNavigator creates a Navigator for the given page.
func NewNavigator(log *slog.Logger, page pw.Page) *Navigator {
	return &Navigator{log: log, page: page}
}

// GotoURL navigates the page to the given URL and waits for load.
// Query parameters are stripped before logging or formatting into error messages.
func (n *Navigator) GotoURL(_ context.Context, url string) error {
	sanitizedURL := stripQuery(url)
	n.log.Info("navigating", "url", sanitizedURL)
	resp, err := n.page.Goto(url, pw.PageGotoOptions{
		WaitUntil: pw.WaitUntilStateLoad,
	})
	if err != nil {
		return fmt.Errorf("goto %s: %w", sanitizedURL, err)
	}
	if resp != nil {
		n.log.Debug("navigation response", "status", resp.Status())
	}
	return nil
}

func stripQuery(rawURL string) string {
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		return rawURL[:idx]
	}
	return rawURL
}

// Page returns the underlying playwright Page.
func (n *Navigator) Page() pw.Page { return n.page }

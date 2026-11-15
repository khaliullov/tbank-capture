package browser

import (
	"context"
	"fmt"
	"log/slog"

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
func (n *Navigator) GotoURL(_ context.Context, url string) error {
	n.log.Info("navigating", "url", url)
	resp, err := n.page.Goto(url, pw.PageGotoOptions{
		WaitUntil: pw.WaitUntilStateLoad,
	})
	if err != nil {
		return fmt.Errorf("goto %s: %w", url, err)
	}
	if resp != nil {
		n.log.Debug("navigation response", "status", resp.Status())
	}
	return nil
}

// Page returns the underlying playwright Page.
func (n *Navigator) Page() pw.Page { return n.page }

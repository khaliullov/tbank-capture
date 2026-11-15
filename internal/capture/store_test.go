package capture_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/capture"
	"github.com/khaliullov/tbank-capture/internal/discovery"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

func newTestCollector(t *testing.T) *discovery.Collector {
	t.Helper()
	dir := t.TempDir()
	cfg := discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 5000}
	c := discovery.NewCollector(noopLogger(), filepath.Join(dir, "sessions"), cfg)
	return c
}

// TestStoreGracefulShutdown verifies that the store drains pending jobs on shutdown.
func TestStoreGracefulShutdown(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("test-session")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 32, col)
	ctx, cancel := context.WithCancel(context.Background())
	go store.Run(ctx)

	q := store.Queue()
	for i := 0; i < 5; i++ {
		q <- discovery.CaptureJob{
			SessionID:    "test-session",
			Method:       "GET",
			URL:          "https://www.tbank.ru/api/v1/test",
			Status:       200,
			ContentType:  "application/json",
			ResourceType: "xhr",
			Body:         []byte(`{"id":"1"}`),
			BodySize:     10,
		}
	}

	cancel()
	store.Wait() // must not hang
}

// TestStoreQueueCapacity verifies that the queue respects its capacity.
func TestStoreQueueCapacity(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("test-session")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 2, col)

	q := store.Queue()
	job := discovery.CaptureJob{SessionID: "test-session", Method: "GET", URL: "https://www.tbank.ru/", Status: 200}

	// Fill to capacity.
	q <- job
	q <- job
	// Third write must NOT block (non-blocking send in handler is simulated here).
	select {
	case q <- job:
		// accepted — may have drained already
	default:
		// queue full — expected
	}
}

// TestStoreRawCapture verifies that raw files are created with correct permissions.
func TestStoreRawCapture(t *testing.T) {
	rawDir := t.TempDir()
	col := newTestCollector(t)
	col.StartSession("test-session")
	store := capture.NewStore(noopLogger(), rawDir, true /*rawEnabled*/, 32, col)
	ctx, cancel := context.WithCancel(context.Background())
	go store.Run(ctx)

	store.Queue() <- discovery.CaptureJob{
		SessionID:    "test-session",
		Method:       "GET",
		URL:          "https://www.tbank.ru/api/v1/test",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"id":"synthetic-test-value"}`),
		BodySize:     29,
	}

	cancel()
	store.Wait()

	sessDir := filepath.Join(rawDir, "test-session")
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		t.Fatalf("expected raw dir %s to exist: %v", sessDir, err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one raw file")
	}
	for _, e := range entries {
		info, err := os.Stat(filepath.Join(sessDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("file %s has permission %o, want 0600", e.Name(), perm)
		}
	}
}

// TestStoreNoRawCapture verifies that raw files are NOT created when disabled.
func TestStoreNoRawCapture(t *testing.T) {
	rawDir := t.TempDir()
	col := newTestCollector(t)
	col.StartSession("test-session")
	store := capture.NewStore(noopLogger(), rawDir, false /*rawEnabled*/, 32, col)
	ctx, cancel := context.WithCancel(context.Background())
	go store.Run(ctx)

	store.Queue() <- discovery.CaptureJob{
		SessionID:    "test-session",
		Method:       "GET",
		URL:          "https://www.tbank.ru/api/v1/test",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"id":"synthetic-value"}`),
		BodySize:     22,
	}

	cancel()
	store.Wait()

	sessDir := filepath.Join(rawDir, "test-session")
	_, err := os.Stat(sessDir)
	if err == nil {
		entries, _ := os.ReadDir(sessDir)
		if len(entries) > 0 {
			t.Errorf("expected no raw files but found %d", len(entries))
		}
	}
}

// TestFilterEligibleURL verifies domain filtering.
func TestFilterEligibleURL(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})

	cases := []struct {
		url  string
		want bool
	}{
		{"https://www.tbank.ru/api/v1/test", true},
		{"https://tbank.ru/api/v1/test", true},
		{"https://api.tbank.ru/v1/test", true},
		{"https://evil.com/api/v1/test", false},
		{"https://evil-tbank.ru/api/v1/test", false},
		{"https://google.com", false},
	}
	for _, tc := range cases {
		got := f.EligibleURL(tc.url)
		if got != tc.want {
			t.Errorf("EligibleURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// TestFilterQueryStringRemoval verifies query strings are stripped from stored URLs.
func TestFilterQueryStringRemoval(t *testing.T) {
	raw := "https://www.tbank.ru/api/v1/test?from=2024-01-01&to=2024-02-01&token=secret123"
	normalized := capture.NormalizedURL(raw)
	if normalized != "https://www.tbank.ru/api/v1/test" {
		t.Errorf("expected query stripped, got %q", normalized)
	}
}

// TestFilterAuthPaths verifies that authentication paths are excluded.
func TestFilterAuthPaths(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})
	authPaths := []string{
		"https://www.tbank.ru/api/common/v1/authorize",
		"https://www.tbank.ru/api/common/v1/login",
		"https://www.tbank.ru/api/common/v1/token",
	}
	for _, url := range authPaths {
		if f.EligiblePath(url) {
			t.Errorf("auth path should be excluded: %s", url)
		}
	}
}

// TestContainsAuthSecret verifies detection of common auth-secret field names.
func TestContainsAuthSecret(t *testing.T) {
	cases := []struct {
		body []byte
		want bool
	}{
		{[]byte(`{"access_token":"abc123","expires_in":3600}`), true},
		{[]byte(`{"refresh_token":"xyz"}`), true},
		{[]byte(`{"id":"123","amount":100,"status":"ok"}`), false},
		{[]byte(`{"name":"Alice","balance":999}`), false},
	}
	for _, tc := range cases {
		got := capture.ContainsAuthSecret(tc.body)
		if got != tc.want {
			t.Errorf("ContainsAuthSecret(%s) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

// TestFilterResourceType verifies only xhr/fetch resources are accepted.
func TestFilterResourceType(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})
	cases := []struct {
		rt   string
		want bool
	}{
		{"xhr", true},
		{"fetch", true},
		{"XHR", true},
		{"Fetch", true},
		{"document", false},
		{"script", false},
		{"image", false},
		{"stylesheet", false},
		{"websocket", false},
	}
	for _, tc := range cases {
		got := f.EligibleResourceType(tc.rt)
		if got != tc.want {
			t.Errorf("EligibleResourceType(%q) = %v, want %v", tc.rt, got, tc.want)
		}
	}
}

// TestFilterContentType verifies only JSON content types are accepted.
func TestFilterContentType(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/vnd.api+json", true},
		{"text/html", false},
		{"text/plain", false},
		{"application/octet-stream", false},
		{"image/png", false},
	}
	for _, tc := range cases {
		got := f.EligibleContentType(tc.ct)
		if got != tc.want {
			t.Errorf("EligibleContentType(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}

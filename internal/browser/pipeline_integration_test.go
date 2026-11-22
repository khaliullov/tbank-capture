package browser_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khaliullov/tbank-capture/internal/browser"
	"github.com/khaliullov/tbank-capture/internal/capture"
	"github.com/khaliullov/tbank-capture/internal/discovery"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestPipeline_EndToEnd verifies the complete capture pipeline using a real headless Chromium
// instance and an HTTP test server serving varied response payloads.
func TestPipeline_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// 1. Setup mock HTTP server with various endpoints:
	// - HTML landing page with XHR & fetch test triggers
	// - /api/v1/accounts (JSON list of accounts & balances)
	// - /api/v1/operations (JSON list of transactions with MCC, amount, currency)
	// - /api/v1/error (application/problem+json)
	// - /page.html (HTML - non-JSON)
	// - /api/v1/large (Oversized JSON response)
	// - /api/v1/session/user (Credentials + financial data to test sanitization)
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{
			"accounts": [
				{"id": "acc-101", "name": "T-Black", "currency": "RUB", "balance": 45000.75, "available": 45000.75},
				{"id": "acc-102", "name": "Savings", "currency": "RUB", "balance": 150000.00, "available": 150000.00}
			]
		}`))
	})

	mux.HandleFunc("/api/v1/operations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"operations": [
				{"id": "op-501", "amount": 1250.50, "currency": "RUB", "date": "2026-11-20T14:30:00Z", "mcc": 5411, "status": "CONFIRMED", "description": "Perekrestok"},
				{"id": "op-502", "amount": 340.00, "currency": "RUB", "date": "2026-11-20T16:00:00Z", "mcc": 5814, "status": "CONFIRMED", "description": "Vkusno i tochka"}
			]
		}`))
	})

	mux.HandleFunc("/api/v1/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type": "https://example.com/err", "title": "Bad Request", "status": 400}`))
	})

	mux.HandleFunc("/page.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>`))
	})

	mux.HandleFunc("/api/v1/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 80KB payload (larger than maxBody=32KB)
		largePadding := strings.Repeat("A", 80*1024)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"padding": "%s"}`, largePadding)))
	})

	mux.HandleFunc("/api/v1/session/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"accessToken": "eyJh...sensitive-token",
			"refreshToken": "d8a...refresh-secret",
			"csrfToken": "csrf-secret-999",
			"user": {
				"id": "usr-888",
				"accounts": [
					{"id": "acc-999", "balance": 9999.0, "currency": "RUB"}
				]
			}
		}`))
	})

	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Discovery Test Harness</title></head>
<body>
<h1>Discovery Test</h1>
<script>
function triggerXHR(url) {
	var xhr = new XMLHttpRequest();
	xhr.open("GET", url, true);
	xhr.send();
}
function triggerFetch(url) {
	return fetch(url);
}
</script>
</body>
</html>`))
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	port := u.Port()

	// Configure allowed domains: allow "localhost" only, so 127.0.0.1 acts as disallowed
	allowedDomains := []string{"localhost"}
	maxBody := int64(32 * 1024) // 32KB

	logger := testLogger()
	tmpDir := t.TempDir()
	sessionDir := filepath.Join(tmpDir, "sessions")
	rawDir := filepath.Join(tmpDir, "raw")
	_ = os.MkdirAll(sessionDir, 0700)
	_ = os.MkdirAll(rawDir, 0700)

	analyzerCfg := discovery.AnalyzerConfig{
		MaxDepth:      5,
		MaxArrayElems: 10,
		MaxFields:     50,
	}
	collector := discovery.NewCollector(logger, sessionDir, analyzerCfg)
	store := capture.NewStore(logger, rawDir, false, 100, collector)

	storeCtx, storeCancel := context.WithCancel(context.Background())
	defer storeCancel()
	go store.Run(storeCtx)
	defer func() {
		storeCancel()
		store.Close()
		store.Wait()
	}()

	filter := capture.NewFilter(logger, maxBody, allowedDomains)
	handler := capture.NewResponseHandler(
		logger,
		filter,
		store.Queue(),
		func() discovery.SessionID {
			sess := collector.ActiveSession()
			if sess == nil || !sess.Active {
				return ""
			}
			return sess.ID
		},
		maxBody,
	)
	handler.SetCollector(collector)
	handler.SetSubmitter(store)

	// Launch Playwright persistent browser context
	userDataDir := filepath.Join(tmpDir, "profile")
	mgr := browser.NewManager(logger, userDataDir, true)
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("start browser manager: %v", err)
	}
	defer mgr.Stop()

	bctx := mgr.Context()
	handler.AttachContext(bctx)

	// Step 1: Request before session starts -> should be rejected as no_active_session
	page, err := mgr.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}

	indexURL := fmt.Sprintf("http://localhost:%s/index.html", port)
	if _, err := page.Goto(indexURL); err != nil {
		t.Fatalf("goto index: %v", err)
	}

	// Step 2: Start discovery session
	sessID := discovery.NewSessionID()
	collector.StartSession(sessID)
	handler.SetSessionID(sessID)

	// Trigger XHR accounts request
	accountsURL := fmt.Sprintf("http://localhost:%s/api/v1/accounts", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerXHR("%s")`, accountsURL))
	if err != nil {
		t.Fatalf("trigger XHR accounts: %v", err)
	}

	// Trigger Fetch operations request
	opsURL := fmt.Sprintf("http://localhost:%s/api/v1/operations", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, opsURL))
	if err != nil {
		t.Fatalf("trigger Fetch operations: %v", err)
	}

	// Trigger vendor JSON (application/problem+json)
	errURL := fmt.Sprintf("http://localhost:%s/api/v1/error", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, errURL))
	if err != nil {
		t.Fatalf("trigger Fetch error: %v", err)
	}

	// Trigger HTML non-JSON
	htmlURL := fmt.Sprintf("http://localhost:%s/page.html", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, htmlURL))
	if err != nil {
		t.Fatalf("trigger Fetch HTML: %v", err)
	}

	// Trigger Oversized response (> 32KB)
	largeURL := fmt.Sprintf("http://localhost:%s/api/v1/large", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, largeURL))
	if err != nil {
		t.Fatalf("trigger Fetch large: %v", err)
	}

	// Trigger Credential-containing response
	userURL := fmt.Sprintf("http://localhost:%s/api/v1/session/user", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, userURL))
	if err != nil {
		t.Fatalf("trigger Fetch user credentials: %v", err)
	}

	// Step 3: Test multi-tab / popup handling
	page2, err := mgr.NewPage()
	if err != nil {
		t.Fatalf("new page 2: %v", err)
	}
	if mgr.OpenPagesCount() < 2 {
		t.Errorf("expected at least 2 open pages, got %d", mgr.OpenPagesCount())
	}
	// Fetch on second page
	_, err = page2.Goto(indexURL)
	if err != nil {
		t.Fatalf("page 2 goto: %v", err)
	}
	_, err = page2.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, opsURL))
	if err != nil {
		t.Fatalf("page 2 fetch: %v", err)
	}

	// Step 4: Disallowed hostname request via 127.0.0.1
	disallowedURL := fmt.Sprintf("http://127.0.0.1:%s/api/v1/accounts", port)
	_, err = page.Evaluate(fmt.Sprintf(`() => triggerFetch("%s")`, disallowedURL))
	if err != nil {
		t.Fatalf("trigger Fetch disallowed host: %v", err)
	}

	// Give a moment for asynchronous responses to be read and submitted to queue
	time.Sleep(500 * time.Millisecond)
	handler.Wait()

	// Step 5: Flush session barrier
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := store.FlushSession(flushCtx, sessID); err != nil {
		t.Fatalf("flush session: %v", err)
	}

	// Stop session cleanly
	handler.StopSession(sessID)
	if err := collector.BeginStopping(sessID); err != nil {
		t.Fatalf("begin stopping: %v", err)
	}
	sessCopy, fps, metrics, err := collector.FinalizeSession(sessID)
	if err != nil {
		t.Fatalf("finalize session: %v", err)
	}

	diag := collector.Diagnostics()

	// Verify Telemetry & Diagnositcs:
	if diag.TotalObserved == 0 {
		t.Fatal("expected observed responses, got 0")
	}
	if diag.UniqueHostnames < 2 {
		t.Errorf("expected at least 2 hostnames (localhost and 127.0.0.1), got %d", diag.UniqueHostnames)
	}

	// Check that 127.0.0.1 was recorded as disallowed
	var foundDisallowed bool
	for _, h := range diag.Hostnames {
		if h.Hostname == "127.0.0.1" {
			foundDisallowed = true
			if h.Allowed {
				t.Error("expected 127.0.0.1 to be Allowed: false")
			}
		}
	}
	if !foundDisallowed {
		t.Error("expected 127.0.0.1 in observed hostnames")
	}

	// Check rejections recorded
	if diag.Rejections[discovery.ReasonNonAllowedDomain] == 0 {
		t.Error("expected non_allowed_domain rejection recorded")
	}
	if diag.Rejections[discovery.ReasonUnsupportedContentType] == 0 {
		t.Error("expected unsupported_content_type rejection recorded")
	}
	if diag.Rejections[discovery.ReasonBodyTooLarge] == 0 {
		t.Error("expected body_too_large rejection recorded")
	}

	// Check conservation invariants
	if metrics.Observed != metrics.Filtered+metrics.Processed+metrics.Dropped {
		t.Errorf("conservation invariant violated: Observed (%d) != Filtered (%d) + Processed (%d) + Dropped (%d)",
			metrics.Observed, metrics.Filtered, metrics.Processed, metrics.Dropped)
	}

	// Verify Fingerprints
	if len(fps) == 0 {
		t.Fatal("expected endpoint fingerprints, got 0")
	}

	// Verify that user endpoint was captured and sanitized
	var userEndpointFound bool
	for _, fp := range fps {
		if strings.Contains(fp.ExampleURL, "/session/user") {
			userEndpointFound = true
			if !fp.Sanitized {
				t.Error("expected /session/user fingerprint to be marked Sanitized: true")
			}
			// Verify secrets are NOT in schema fields
			for _, field := range fp.SchemaFields {
				if field.Path == "accessToken" || field.Path == "refreshToken" || field.Path == "csrfToken" {
					t.Errorf("sensitive credential field %s leaked into schema fields!", field.Path)
				}
			}
			// Verify financial account fields ARE preserved
			var hasAccountField bool
			for _, field := range fp.SchemaFields {
				if strings.Contains(field.Path, "balance") || strings.Contains(field.Path, "accounts") {
					hasAccountField = true
					break
				}
			}
			if !hasAccountField {
				t.Error("expected financial accounts field to be preserved in sanitized schema")
			}
		}
	}
	if !userEndpointFound {
		t.Error("expected /api/v1/session/user to be captured and analyzed")
	}

	// Verify report generation with diagnostics works cleanly
	gen := discovery.NewGenerator(filepath.Join(tmpDir, "reports"))
	mdPath, jsonPath, err := gen.GenerateWithDiagnostics(sessCopy, fps, metrics, diag)
	if err != nil {
		t.Fatalf("generate report: %v", err)
	}
	if mdPath == "" || jsonPath == "" {
		t.Fatal("expected report paths")
	}
}

// TestPipeline_SequentialSessions verifies that starting and stopping multiple sessions
// in sequence behaves cleanly without state pollution or deadlocks.
func TestPipeline_SequentialSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cards", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cards": [{"id": "card-1", "status": "ACTIVE"}]}`))
	})
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><script>
		function getCards(url) { return fetch(url); }
		</script></body></html>`))
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port := u.Port()

	logger := testLogger()
	tmpDir := t.TempDir()
	sessionDir := filepath.Join(tmpDir, "sessions")
	collector := discovery.NewCollector(logger, sessionDir, discovery.AnalyzerConfig{MaxDepth: 5, MaxArrayElems: 10, MaxFields: 50})
	store := capture.NewStore(logger, filepath.Join(tmpDir, "raw"), false, 50, collector)

	storeCtx, storeCancel := context.WithCancel(context.Background())
	defer storeCancel()
	go store.Run(storeCtx)
	defer func() {
		storeCancel()
		store.Close()
		store.Wait()
	}()

	filter := capture.NewFilter(logger, 64*1024, []string{"localhost"})
	handler := capture.NewResponseHandler(logger, filter, store.Queue(), func() discovery.SessionID {
		s := collector.ActiveSession()
		if s == nil || !s.Active {
			return ""
		}
		return s.ID
	}, 64*1024)
	handler.SetCollector(collector)
	handler.SetSubmitter(store)

	mgr := browser.NewManager(logger, filepath.Join(tmpDir, "profile"), true)
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("start browser: %v", err)
	}
	defer mgr.Stop()

	handler.AttachContext(mgr.Context())
	page, err := mgr.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}

	indexURL := fmt.Sprintf("http://localhost:%s/index.html", port)
	cardsURL := fmt.Sprintf("http://localhost:%s/api/v1/cards", port)
	if _, err := page.Goto(indexURL); err != nil {
		t.Fatalf("goto: %v", err)
	}

	// Session 1
	sess1 := discovery.NewSessionID()
	collector.StartSession(sess1)
	handler.SetSessionID(sess1)

	_, err = page.Evaluate(fmt.Sprintf(`() => getCards("%s")`, cardsURL))
	if err != nil {
		t.Fatalf("session 1 getCards: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	handler.Wait()

	flushCtx, flushCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer flushCancel()
	if err := store.FlushSession(flushCtx, sess1); err != nil {
		t.Fatalf("flush session 1: %v", err)
	}
	handler.StopSession(sess1)
	if err := collector.BeginStopping(sess1); err != nil {
		t.Fatalf("begin stopping session 1: %v", err)
	}
	sess1Copy, fps1, _, err := collector.FinalizeSession(sess1)
	if err != nil {
		t.Fatalf("finalize session 1: %v", err)
	}
	if sess1Copy.ID != sess1 {
		t.Errorf("expected session 1 id %s, got %s", sess1, sess1Copy.ID)
	}
	if len(fps1) != 1 {
		t.Errorf("expected 1 fingerprint in session 1, got %d", len(fps1))
	}

	// Session 2
	sess2 := discovery.NewSessionID()
	collector.StartSession(sess2)
	handler.SetSessionID(sess2)

	_, err = page.Evaluate(fmt.Sprintf(`() => getCards("%s")`, cardsURL))
	if err != nil {
		t.Fatalf("session 2 getCards: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	handler.Wait()

	flushCtx2, flushCancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer flushCancel2()
	if err := store.FlushSession(flushCtx2, sess2); err != nil {
		t.Fatalf("flush session 2: %v", err)
	}
	handler.StopSession(sess2)
	if err := collector.BeginStopping(sess2); err != nil {
		t.Fatalf("begin stopping session 2: %v", err)
	}
	sess2Copy, fps2, _, err := collector.FinalizeSession(sess2)
	if err != nil {
		t.Fatalf("finalize session 2: %v", err)
	}
	if sess2Copy.ID != sess2 {
		t.Errorf("expected session 2 id %s, got %s", sess2, sess2Copy.ID)
	}
	if len(fps2) != 1 {
		t.Errorf("expected 1 fingerprint in session 2, got %d", len(fps2))
	}
}

// TestPipeline_QueueOverflow verifies that bounded queue behavior correctly rejects
// overflow responses when the store channel capacity is saturated, preserving invariants.
func TestPipeline_QueueOverflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := testLogger()
	tmpDir := t.TempDir()
	sessionDir := filepath.Join(tmpDir, "sessions")
	collector := discovery.NewCollector(logger, sessionDir, discovery.AnalyzerConfig{MaxDepth: 3, MaxArrayElems: 5, MaxFields: 20})

	// Very small queue size: 1, and no worker running to force saturation
	store := capture.NewStore(logger, filepath.Join(tmpDir, "raw"), false, 1, collector)
	defer store.Close()

	filter := capture.NewFilter(logger, 64*1024, []string{"localhost"})
	sessID := discovery.NewSessionID()
	collector.StartSession(sessID)

	handler := capture.NewResponseHandler(logger, filter, store.Queue(), func() discovery.SessionID {
		return sessID
	}, 64*1024)
	handler.SetCollector(collector)
	handler.SetSubmitter(store)
	handler.SetSessionID(sessID)

	// Send first job -> fills queue
	job1 := discovery.CaptureJob{
		SessionID:    sessID,
		URL:          "http://localhost/api/1",
		Method:       "GET",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"key": 1}`),
	}
	if !store.Submit(job1) {
		t.Fatal("expected first job submission to succeed")
	}
	collector.RecordEnqueued()

	// Send second job -> queue is full -> returns false
	job2 := discovery.CaptureJob{
		SessionID:    sessID,
		URL:          "http://localhost/api/2",
		Method:       "GET",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"key": 2}`),
	}
	if store.Submit(job2) {
		t.Fatal("expected second job submission to fail due to queue saturation")
	}
	collector.RecordQueueOverflow()

	diag := collector.Diagnostics()
	if diag.QueueOverflow != 1 {
		t.Errorf("expected 1 queue overflow, got %d", diag.QueueOverflow)
	}
	if diag.Rejections[discovery.ReasonQueueFull] != 1 {
		t.Errorf("expected 1 queue_full rejection, got %d", diag.Rejections[discovery.ReasonQueueFull])
	}
}

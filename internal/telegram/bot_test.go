package telegram_test

import (
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
	"github.com/khaliullov/tbank-capture/internal/telegram"
)

type mockCommander struct {
	startCalled int
	stopCalled  int
	statusCalls int
	diagCalls   int
	active      bool
	sessID      discovery.SessionID
}

func (m *mockCommander) StartDiscovery() (discovery.SessionID, error) {
	m.startCalled++
	if m.active {
		return "", errors.New("session already active")
	}
	m.active = true
	m.sessID = "test-sess-1"
	return m.sessID, nil
}

func (m *mockCommander) StopDiscovery() (string, string, error) {
	m.stopCalled++
	if !m.active {
		return "", "", errors.New("no active session")
	}
	m.active = false
	return "/path/to/report-1.md", "/path/to/report-1.json", nil
}

func (m *mockCommander) Status() telegram.BotStatus {
	m.statusCalls++
	return telegram.BotStatus{
		BrowserReady:  true,
		OpenPages:     2,
		SessionActive: m.active,
		SessionID:     m.sessID,
		SessionStart:  time.Now().UTC(),
		Metrics: discovery.Metrics{
			Observed:              10,
			Filtered:              5,
			Eligible:              5,
			Processed:             5,
			UniqueFingerprints:    2,
			TransactionCandidates: 1,
		},
	}
}

func (m *mockCommander) Diagnostics() discovery.DiagnosticsSnapshot {
	m.diagCalls++
	return discovery.DiagnosticsSnapshot{
		TotalObserved:   10,
		UniqueHostnames: 2,
		Hostnames: []discovery.HostnameStats{
			{Hostname: "api.tbank.ru", TotalCount: 8},
			{Hostname: "id.tbank.ru", TotalCount: 2},
		},
		ResourceDist: map[string]int{
			"xhr":   6,
			"fetch": 4,
		},
		ContentDist: map[string]int{
			"application/json": 8,
			"text/html":        2,
		},
		Rejections: map[discovery.RejectionReason]int{
			discovery.ReasonNonAllowedDomain: 2,
		},
		Eligible:            5,
		Enqueued:            5,
		Processed:           5,
		UniqueFingerprints:  2,
		HasEligibleEnqueued: true,
	}
}

func TestBot_InvalidToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cmd := &mockCommander{}

	_, err := telegram.NewBot(logger, "invalid-token", 123456, t.TempDir(), cmd)
	if err == nil {
		t.Fatal("expected error with invalid token")
	}
}

func TestCommander_Workflow(t *testing.T) {
	cmd := &mockCommander{}

	id, err := cmd.StartDiscovery()
	if err != nil {
		t.Fatalf("unexpected error starting discovery: %v", err)
	}
	if id != "test-sess-1" {
		t.Errorf("unexpected session ID: %s", id)
	}

	// Repeated start should fail
	_, err = cmd.StartDiscovery()
	if err == nil {
		t.Fatal("expected error on duplicate start")
	}

	st := cmd.Status()
	if !st.SessionActive {
		t.Error("expected session to be active in status")
	}
	if st.Metrics.TransactionCandidates != 1 {
		t.Errorf("expected 1 candidate, got %d", st.Metrics.TransactionCandidates)
	}
	if st.OpenPages != 2 {
		t.Errorf("expected 2 open pages, got %d", st.OpenPages)
	}

	diag := cmd.Diagnostics()
	if diag.TotalObserved != 10 {
		t.Errorf("expected 10 total observed, got %d", diag.TotalObserved)
	}
	if !diag.HasEligibleEnqueued {
		t.Error("expected HasEligibleEnqueued to be true")
	}
	if len(diag.Hostnames) != 2 {
		t.Errorf("expected 2 hostnames, got %d", len(diag.Hostnames))
	}

	md, json, err := cmd.StopDiscovery()
	if err != nil {
		t.Fatalf("unexpected error stopping discovery: %v", err)
	}
	if md == "" || json == "" {
		t.Errorf("expected paths, got md=%s, json=%s", md, json)
	}

	// Repeated stop should fail
	_, _, err = cmd.StopDiscovery()
	if err == nil {
		t.Fatal("expected error on duplicate stop")
	}
}

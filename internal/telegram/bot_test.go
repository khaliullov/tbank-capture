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
		SessionActive: m.active,
		SessionID:     m.sessID,
		SessionStart:  time.Now().UTC(),
		Metrics: discovery.Metrics{
			TotalObserved:         10,
			EligibleResponses:     5,
			UniqueFingerprints:    2,
			TransactionCandidates: 1,
		},
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

package discovery_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

func newCollector(t *testing.T) *discovery.Collector {
	t.Helper()
	dir := t.TempDir()
	cfg := discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 5000}
	return discovery.NewCollector(testLogger(), dir, cfg)
}

func sampleTxJob(sessionID discovery.SessionID, opID string) discovery.CaptureJob {
	body := fmt.Sprintf(`{
		"items": [
			{"operationId": "%s", "amount": 100.50, "operationTime": "2024-01-01T00:00:00Z", "status": "ok", "mcc": 5411, "merchant": {"name": "Shop"}}
		],
		"totalCount": 1
	}`, opID)

	return discovery.CaptureJob{
		SessionID:    sessionID,
		Method:       "GET",
		URL:          "https://www.tbank.ru/api/v1/accounts/123/operations?from=2024-01-01",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(body),
		BodySize:     int64(len(body)),
		HasDateParam: true,
	}
}

// TestCollector_SessionIsolation verifies that jobs from inactive or mismatched sessions
// are strictly ignored.
func TestCollector_SessionIsolation(t *testing.T) {
	c := newCollector(t)

	// 1. Process job with no session started
	c.ProcessJob(sampleTxJob("sess-none", "op-0"))
	if len(c.Fingerprints()) != 0 {
		t.Fatal("expected 0 fingerprints when no session active")
	}
	if m := c.Metrics(); m.TotalObserved != 0 || m.IgnoredResponses != 1 {
		t.Fatalf("unexpected metrics without active session: %+v", m)
	}

	// 2. Start session-1
	c.StartSession("sess-1")
	c.ProcessJob(sampleTxJob("sess-1", "op-1"))
	if len(c.Fingerprints()) != 1 {
		t.Fatalf("expected 1 fingerprint for sess-1, got %d", len(c.Fingerprints()))
	}

	// 3. Send job with wrong session ID
	c.ProcessJob(sampleTxJob("sess-wrong", "op-2"))
	fps := c.Fingerprints()
	if len(fps) != 1 || fps[0].Observations != 1 {
		t.Fatalf("wrong session mutated active session! observations = %d", fps[0].Observations)
	}

	// 4. Stop session-1
	c.StopSession()
	// Arriving late after session stopped:
	c.ProcessJob(sampleTxJob("sess-1", "op-3"))
	fps = c.Fingerprints()
	if fps[0].Observations != 1 {
		t.Fatalf("job after StopSession mutated session! observations = %d", fps[0].Observations)
	}

	// 5. Start session-2: ensure old session data is wiped and old jobs cannot enter
	c.StartSession("sess-2")
	if len(c.Fingerprints()) != 0 {
		t.Fatal("new session must start with 0 fingerprints")
	}
	// Late job from sess-1
	c.ProcessJob(sampleTxJob("sess-1", "op-old"))
	if len(c.Fingerprints()) != 0 {
		t.Fatal("late job from sess-1 was accepted into sess-2!")
	}

	// Job for sess-2
	c.ProcessJob(sampleTxJob("sess-2", "op-new"))
	if len(c.Fingerprints()) != 1 {
		t.Fatal("expected 1 fingerprint for sess-2")
	}
}

// TestCollector_DeepCopySnapshot verifies that modifying returned snapshots
// does not mutate internal collector state or cause data races.
func TestCollector_DeepCopySnapshot(t *testing.T) {
	c := newCollector(t)
	c.StartSession("sess-snapshot")
	c.ProcessJob(sampleTxJob("sess-snapshot", "op-1"))

	fps1 := c.Fingerprints()
	if len(fps1) != 1 {
		t.Fatal("expected 1 fingerprint")
	}

	// Mutate the returned fingerprint
	fps1[0].NormalizedPath = "MUTATED"
	fps1[0].StatusDist[999] = 999
	fps1[0].Classification.Reasons = append(fps1[0].Classification.Reasons, "MUTATED_REASON")
	if len(fps1[0].SchemaFields) > 0 {
		fps1[0].SchemaFields[0].ObservedTypes[0] = "MUTATED_TYPE"
	}

	// Get a second snapshot and verify it was not modified
	fps2 := c.Fingerprints()
	if fps2[0].NormalizedPath == "MUTATED" {
		t.Error("internal NormalizedPath was mutated via external slice!")
	}
	if _, exists := fps2[0].StatusDist[999]; exists {
		t.Error("internal StatusDist map was mutated via external map!")
	}
	for _, r := range fps2[0].Classification.Reasons {
		if r == "MUTATED_REASON" {
			t.Error("internal Reasons was mutated via external slice!")
		}
	}
	if len(fps2[0].SchemaFields) > 0 && fps2[0].SchemaFields[0].ObservedTypes[0] == "MUTATED_TYPE" {
		t.Error("internal SchemaFields was mutated via external slice!")
	}
}

// TestCollector_ConcurrentAccess verifies thread-safety during concurrent jobs,
// session transitions, and report snapshot reads.
func TestCollector_ConcurrentAccess(t *testing.T) {
	c := newCollector(t)
	c.StartSession("sess-conc")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Worker sending jobs
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
					job := sampleTxJob("sess-conc", fmt.Sprintf("op-%d-%d", workerID, j))
					c.ProcessJob(job)
					time.Sleep(100 * time.Microsecond)
				}
			}
		}(i)
	}

	// Worker reading snapshots
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.Fingerprints()
					_ = c.Metrics()
					_ = c.ActiveSession()
					time.Sleep(200 * time.Microsecond)
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	_ = c.StopSession()
	if err := c.PersistSession(); err != nil {
		t.Fatalf("persist error: %v", err)
	}
}

// TestNewSessionID_CollisionResistance verifies that rapid, concurrent generation
// of session IDs yields strictly unique IDs without collisions.
func TestNewSessionID_CollisionResistance(t *testing.T) {
	const total = 10000
	const goroutines = 10
	idsPerG := total / goroutines

	var mu sync.Mutex
	seen := make(map[discovery.SessionID]struct{}, total)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]discovery.SessionID, idsPerG)
			for i := 0; i < idsPerG; i++ {
				local[i] = discovery.NewSessionID()
			}
			mu.Lock()
			for _, id := range local {
				if _, exists := seen[id]; exists {
					t.Errorf("collision detected for session ID: %s", id)
				}
				seen[id] = struct{}{}
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	if len(seen) != total {
		t.Fatalf("expected %d unique session IDs, got %d", total, len(seen))
	}
}

// TestCollector_RepeatedSessionPersistenceAndNoOverwrite verifies that rapidly
// created sessions and their reports do not overwrite each other.
func TestCollector_RepeatedSessionPersistenceAndNoOverwrite(t *testing.T) {
	sessionDir := t.TempDir()
	reportDir := t.TempDir()
	cfg := discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 5000}
	col := discovery.NewCollector(testLogger(), sessionDir, cfg)
	gen := discovery.NewGenerator(reportDir)

	const numSessions = 5
	sessionFiles := make(map[string]bool)
	reportFiles := make(map[string]bool)

	for i := 0; i < numSessions; i++ {
		id := discovery.NewSessionID()
		col.StartSession(id)
		col.ProcessJob(sampleTxJob(id, fmt.Sprintf("op-%d", i)))

		sessCopy, fps, metrics, err := col.FinalizeSession(id)
		if err != nil {
			t.Fatalf("finalize session %d failed: %v", i, err)
		}

		if err := col.PersistSession(); err != nil {
			t.Fatalf("persist session %d failed: %v", i, err)
		}

		sessPath := filepath.Join(sessionDir, string(id)+".json")
		if _, exists := sessionFiles[sessPath]; exists {
			t.Fatalf("session file collision: %s", sessPath)
		}
		sessionFiles[sessPath] = true

		if _, err := os.Stat(sessPath); err != nil {
			t.Fatalf("expected session file %s to exist: %v", sessPath, err)
		}

		mdPath, jsonPath, err := gen.Generate(sessCopy, fps, metrics)
		if err != nil {
			t.Fatalf("generate report %d failed: %v", i, err)
		}

		if reportFiles[mdPath] || reportFiles[jsonPath] {
			t.Fatalf("report file collision for session %s: md=%s, json=%s", id, mdPath, jsonPath)
		}
		reportFiles[mdPath] = true
		reportFiles[jsonPath] = true
	}

	if len(sessionFiles) != numSessions {
		t.Errorf("expected %d distinct session files, got %d", numSessions, len(sessionFiles))
	}
}

// TestCollector_SensitiveErrorSanitization verifies that query strings and authentication
// secrets cannot enter endpoint capture warnings or generated reports through error messages.
func TestCollector_SensitiveErrorSanitization(t *testing.T) {
	sessionDir := t.TempDir()
	reportDir := t.TempDir()
	cfg := discovery.DefaultAnalyzerConfig()
	col := discovery.NewCollector(testLogger(), sessionDir, cfg)
	gen := discovery.NewGenerator(reportDir)

	id := discovery.NewSessionID()
	col.StartSession(id)

	sensitiveErr := "request failed: https://api.tbank.ru/fail?token=SECRET_AUTH_TOKEN_VALUE&pin=8390#frag"
	col.ProcessJob(discovery.CaptureJob{
		SessionID:    id,
		Method:       "GET",
		URL:          "https://api.tbank.ru/fail?token=SECRET_AUTH_TOKEN_VALUE&pin=8390",
		Status:       502,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         nil,
		BodyError:    sensitiveErr,
	})

	sessCopy, fps, metrics, err := col.FinalizeSession(id)
	if err != nil {
		t.Fatalf("finalize session: %v", err)
	}

	for _, fp := range fps {
		for _, w := range fp.CaptureWarnings {
			if strings.Contains(w, "SECRET_AUTH_TOKEN_VALUE") || strings.Contains(w, "pin=8390") || strings.Contains(w, "?") {
				t.Fatalf("sensitive parameter leaked in capture warning: %q", w)
			}
		}
	}

	mdPath, jsonPath, err := gen.Generate(sessCopy, fps, metrics)
	if err != nil {
		t.Fatalf("generate report: %v", err)
	}

	for _, path := range []string{mdPath, jsonPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		content := string(data)
		if strings.Contains(content, "SECRET_AUTH_TOKEN_VALUE") || strings.Contains(content, "pin=8390") {
			t.Fatalf("sensitive secret leaked in report %s", path)
		}
	}
}

// TestCollector_CompletionBarrierDraining verifies session state transitions during stopping
// and guarantees strict session isolation.
func TestCollector_CompletionBarrierDraining(t *testing.T) {
	c := newCollector(t)
	id := discovery.NewSessionID()
	c.StartSession(id)

	// In active state, jobs are processed
	c.ProcessJob(sampleTxJob(id, "op-active"))
	if m := c.Metrics(); m.Processed != 1 {
		t.Fatalf("expected 1 processed job, got %d", m.Processed)
	}

	// Begin stopping
	if err := c.BeginStopping(id); err != nil {
		t.Fatalf("BeginStopping failed: %v", err)
	}

	// During stopping, jobs for this session are STILL processed
	c.ProcessJob(sampleTxJob(id, "op-draining"))
	if m := c.Metrics(); m.Processed != 2 {
		t.Fatalf("expected 2 processed jobs during draining, got %d", m.Processed)
	}

	// Jobs for other sessions are rejected
	c.ProcessJob(sampleTxJob("other-session", "op-other"))
	if m := c.Metrics(); m.Processed != 2 || m.Dropped != 1 {
		t.Fatalf("expected mismatched job dropped: processed=%d, dropped=%d", m.Processed, m.Dropped)
	}

	// Finalize session
	sessCopy, fps, metrics, err := c.FinalizeSession(id)
	if err != nil {
		t.Fatalf("FinalizeSession failed: %v", err)
	}
	if sessCopy.Active || sessCopy.State != discovery.SessionStateStopped {
		t.Errorf("expected session stopped, got state=%s active=%v", sessCopy.State, sessCopy.Active)
	}
	if len(fps) != 1 || fps[0].Observations != 2 {
		t.Errorf("expected 1 fingerprint with 2 observations, got %d observations", fps[0].Observations)
	}
	if metrics.Processed != 2 {
		t.Errorf("expected 2 processed in final metrics, got %d", metrics.Processed)
	}

	// Jobs arriving after finalization are rejected
	c.ProcessJob(sampleTxJob(id, "op-late"))
	fpsAfter := c.Fingerprints()
	if fpsAfter[0].Observations != 2 {
		t.Fatalf("late job mutated stopped session! observations=%d", fpsAfter[0].Observations)
	}
}

// TestCollector_MetricInvariants verifies that the capture metrics adhere strictly
// to defined conservation invariants across all transition paths.
func TestCollector_MetricInvariants(t *testing.T) {
	c := newCollector(t)
	id := discovery.NewSessionID()
	c.StartSession(id)

	// Simulate event flow:
	// Total observed: 15
	// Filtered: 5
	// Eligible: 10
	//   Enqueued: 8
	//   QueueOverflow: 2 (dropped)
	// Of the 8 enqueued:
	//   Processed: 7 (of which 1 has capture failure)
	//   DroppedInQueue: 1
	for i := 0; i < 15; i++ {
		c.IncrObserved()
	}
	for i := 0; i < 5; i++ {
		c.IncrFiltered()
	}
	for i := 0; i < 10; i++ {
		c.IncrEligible()
	}
	for i := 0; i < 2; i++ {
		c.IncrQueueOverflow()
	}
	for i := 0; i < 8; i++ {
		c.IncrEnqueued()
	}
	for i := 0; i < 6; i++ {
		c.ProcessJob(sampleTxJob(id, fmt.Sprintf("op-ok-%d", i)))
	}
	// 1 processed with BodyError (capture failed)
	c.ProcessJob(discovery.CaptureJob{
		SessionID:   id,
		Method:      "GET",
		URL:         "https://www.tbank.ru/api/v1/accounts/123/failed",
		Status:      500,
		ContentType: "application/json",
		BodyError:   "response body size 15000000 exceeds limit 10485760",
	})
	// 1 dropped in queue
	c.IncrDroppedInQueue()

	m := c.Metrics()

	// Invariant 1: Observed == Filtered + Eligible
	if m.Observed != m.Filtered+m.Eligible {
		t.Errorf("Invariant 1 violated: Observed (%d) != Filtered (%d) + Eligible (%d)", m.Observed, m.Filtered, m.Eligible)
	}

	// Invariant 2: Eligible == Enqueued + QueueOverflow
	if m.Eligible != m.Enqueued+m.QueueOverflow {
		t.Errorf("Invariant 2 violated: Eligible (%d) != Enqueued (%d) + QueueOverflow (%d)", m.Eligible, m.Enqueued, m.QueueOverflow)
	}

	// Invariant 3: Dropped == QueueOverflow + DroppedInQueue (where DroppedInQueue = Enqueued - Processed)
	droppedInQueue := m.Enqueued - m.Processed
	if m.Dropped != m.QueueOverflow+droppedInQueue {
		t.Errorf("Invariant 3 violated: Dropped (%d) != QueueOverflow (%d) + DroppedInQueue (%d)", m.Dropped, m.QueueOverflow, droppedInQueue)
	}

	// Invariant 4: Enqueued == Processed + DroppedInQueue
	if m.Enqueued != m.Processed+droppedInQueue {
		t.Errorf("Invariant 4 violated: Enqueued (%d) != Processed (%d) + DroppedInQueue (%d)", m.Enqueued, m.Processed, droppedInQueue)
	}

	// Invariant 5: Observed == Filtered + Processed + Dropped
	if m.Observed != m.Filtered+m.Processed+m.Dropped {
		t.Errorf("Invariant 5 violated: Observed (%d) != Filtered (%d) + Processed (%d) + Dropped (%d)", m.Observed, m.Filtered, m.Processed, m.Dropped)
	}

	// Invariant 6: CaptureFailed <= Processed
	if m.CaptureFailed > m.Processed {
		t.Errorf("Invariant 6 violated: CaptureFailed (%d) > Processed (%d)", m.CaptureFailed, m.Processed)
	}
	if m.CaptureFailed != 1 {
		t.Errorf("expected CaptureFailed == 1, got %d", m.CaptureFailed)
	}

	// Test Report generation with these metrics
	gen := discovery.NewGenerator(t.TempDir())
	sessCopy, fps, _, err := c.FinalizeSession(id)
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	_, jsonPath, err := gen.Generate(sessCopy, fps, m)
	if err != nil {
		t.Fatalf("generate report failed: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep discovery.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}

	if rep.Summary.Observed != m.Observed ||
		rep.Summary.Filtered != m.Filtered ||
		rep.Summary.Eligible != m.Eligible ||
		rep.Summary.Enqueued != m.Enqueued ||
		rep.Summary.Processed != m.Processed ||
		rep.Summary.Dropped != m.Dropped ||
		rep.Summary.CaptureFailed != m.CaptureFailed ||
		rep.Summary.QueueOverflow != m.QueueOverflow {
		t.Errorf("Report JSON summary metrics mismatch with Collector metrics: rep=%+v, m=%+v", rep.Summary, m)
	}
}

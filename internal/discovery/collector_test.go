package discovery_test

import (
	"fmt"
	"log/slog"
	"os"
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

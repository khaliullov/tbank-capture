package capture_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func sampleJob(sessionID discovery.SessionID, i int) discovery.CaptureJob {
	return discovery.CaptureJob{
		SessionID:    sessionID,
		Method:       "GET",
		URL:          fmt.Sprintf("https://www.tbank.ru/api/v1/test/%d", i),
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(fmt.Sprintf(`{"id":"%d"}`, i)),
		BodySize:     10,
	}
}

// TestStore_ShutdownEmptyQueue verifies shutdown with an empty queue.
func TestStore_ShutdownEmptyQueue(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("sess-empty")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 32, col)
	ctx := context.Background()

	go store.Run(ctx)
	store.Close()
	store.Wait() // Must exit cleanly without hanging
}

// TestStore_ShutdownPendingJobs verifies that all pending jobs are drained and processed.
func TestStore_ShutdownPendingJobs(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("sess-pending")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 64, col)
	ctx := context.Background()

	// Enqueue jobs before running worker
	const totalJobs = 15
	for i := 0; i < totalJobs; i++ {
		ok := store.Submit(sampleJob("sess-pending", i))
		if !ok {
			t.Fatalf("failed to submit job %d", i)
		}
	}

	go store.Run(ctx)
	store.Close()
	store.Wait()

	fps := col.Fingerprints()
	if len(fps) == 0 {
		t.Fatal("expected fingerprints from processed jobs")
	}
	var totalObservations int
	for _, fp := range fps {
		totalObservations += fp.Observations
	}
	if totalObservations != totalJobs {
		t.Fatalf("expected %d observations, got %d", totalJobs, totalObservations)
	}
}

// TestStore_QueueSaturation verifies non-blocking behavior when queue capacity is reached.
func TestStore_QueueSaturation(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("sess-sat")
	// Capacity of 2
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 2, col)

	// Submit 2 jobs to fill queue
	if !store.Submit(sampleJob("sess-sat", 1)) {
		t.Fatal("expected first job to be accepted")
	}
	if !store.Submit(sampleJob("sess-sat", 2)) {
		t.Fatal("expected second job to be accepted")
	}

	// Third submission must immediately return false without blocking
	done := make(chan bool, 1)
	go func() {
		accepted := store.Submit(sampleJob("sess-sat", 3))
		done <- accepted
	}()

	select {
	case accepted := <-done:
		if accepted {
			t.Error("expected third job to be rejected due to queue saturation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Submit blocked on saturated queue!")
	}
}

// TestStore_ConcurrentSubmissionDuringShutdown verifies race-safety when multiple
// goroutines call Submit while Close is called.
func TestStore_ConcurrentSubmissionDuringShutdown(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("sess-conc-shutdown")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 128, col)
	ctx := context.Background()

	go store.Run(ctx)

	var wg sync.WaitGroup
	const submitters = 8
	for i := 0; i < submitters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				store.Submit(sampleJob("sess-conc-shutdown", id*100+j))
				time.Sleep(10 * time.Microsecond)
			}
		}(i)
	}

	time.Sleep(1 * time.Millisecond)
	store.Close()

	wg.Wait()
	store.Wait()
}

// TestStore_RepeatedShutdownCalls verifies that Close can be called repeatedly without panic.
func TestStore_RepeatedShutdownCalls(t *testing.T) {
	col := newTestCollector(t)
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 16, col)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Close()
		}()
	}
	wg.Wait()
}

// TestStore_WorkerCancellation verifies that context cancellation terminates worker
// and accounts for any remaining queued jobs.
func TestStore_WorkerCancellation(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("sess-cancel")
	store := capture.NewStore(noopLogger(), t.TempDir(), false, 64, col)

	ctx, cancel := context.WithCancel(context.Background())

	// Fill queue with some jobs
	for i := 0; i < 10; i++ {
		store.Submit(sampleJob("sess-cancel", i))
	}

	go store.Run(ctx)

	// Cancel context immediately
	cancel()
	store.Wait() // Must exit cleanly

	dropped := store.DroppedCount()
	t.Logf("Worker cancelled successfully. Dropped jobs accounted for: %d", dropped)
}

// TestStoreRawCapture verifies that raw files are created with correct permissions.
func TestStoreRawCapture(t *testing.T) {
	rawDir := t.TempDir()
	col := newTestCollector(t)
	col.StartSession("test-session")
	store := capture.NewStore(noopLogger(), rawDir, true /*rawEnabled*/, 32, col)
	ctx := context.Background()
	go store.Run(ctx)

	store.Submit(discovery.CaptureJob{
		SessionID:    "test-session",
		Method:       "GET",
		URL:          "https://www.tbank.ru/api/v1/test",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"id":"synthetic-test-value"}`),
		BodySize:     29,
	})

	store.Close()
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
	ctx := context.Background()
	go store.Run(ctx)

	store.Submit(discovery.CaptureJob{
		SessionID:    "test-session",
		Method:       "GET",
		URL:          "https://www.tbank.ru/api/v1/test",
		Status:       200,
		ContentType:  "application/json",
		ResourceType: "xhr",
		Body:         []byte(`{"id":"synthetic-value"}`),
		BodySize:     22,
	})

	store.Close()
	store.Wait()

	sessDir := filepath.Join(rawDir, "test-session")
	entries, _ := os.ReadDir(sessDir)
	if len(entries) > 0 {
		t.Errorf("expected no raw files but found %d", len(entries))
	}
}

// TestStore_FlushSession_DelayedProcessing verifies that FlushSession blocks until
// all previously accepted jobs have been processed by the worker, even with delayed processing.
func TestStore_FlushSession_DelayedProcessing(t *testing.T) {
	col := newTestCollector(t)
	sessionID := discovery.NewSessionID()
	col.StartSession(sessionID)

	store := capture.NewStore(noopLogger(), t.TempDir(), false, 128, col)
	ctx := context.Background()

	// Enqueue 20 jobs before worker starts
	const initialJobs = 20
	for i := 0; i < initialJobs; i++ {
		if !store.Submit(sampleJob(sessionID, i)) {
			t.Fatalf("failed to submit job %d", i)
		}
	}

	go store.Run(ctx)

	// Enqueue 10 more jobs concurrently
	const concurrentJobs = 10
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < concurrentJobs; i++ {
			time.Sleep(1 * time.Millisecond) // intentional delay
			store.Submit(sampleJob(sessionID, initialJobs+i))
		}
	}()

	wg.Wait()

	// Now call FlushSession with a timeout context
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.FlushSession(flushCtx, sessionID); err != nil {
		t.Fatalf("FlushSession failed: %v", err)
	}

	// At this exact point, all 30 jobs MUST be processed
	m := col.Metrics()
	expectedJobs := initialJobs + concurrentJobs
	if m.Processed != expectedJobs {
		t.Fatalf("expected %d processed jobs after flush, got %d", expectedJobs, m.Processed)
	}

	// Finalize session and verify report
	sessCopy, fps, metrics, err := col.FinalizeSession(sessionID)
	if err != nil {
		t.Fatalf("FinalizeSession failed: %v", err)
	}
	if metrics.Processed != expectedJobs {
		t.Fatalf("expected snapshot processed %d, got %d", expectedJobs, metrics.Processed)
	}

	gen := discovery.NewGenerator(t.TempDir())
	_, _, err = gen.Generate(sessCopy, fps, metrics)
	if err != nil {
		t.Fatalf("Generate report failed: %v", err)
	}

	// Verify store and worker remain operational for a second discovery session
	session2ID := discovery.NewSessionID()
	col.StartSession(session2ID)

	const session2Jobs = 5
	for i := 0; i < session2Jobs; i++ {
		if !store.Submit(sampleJob(session2ID, 100+i)) {
			t.Fatalf("failed to submit job for session 2: %d", i)
		}
	}

	// Stray old job with sessionID from previous session submitted now
	store.Submit(sampleJob(sessionID, 999))

	if err := store.FlushSession(flushCtx, session2ID); err != nil {
		t.Fatalf("FlushSession for session 2 failed: %v", err)
	}

	m2 := col.Metrics()
	if m2.Processed != session2Jobs {
		t.Fatalf("expected %d processed jobs in session 2, got %d", session2Jobs, m2.Processed)
	}
	// Old job must have been dropped, not processed
	if m2.Dropped != 1 {
		t.Fatalf("expected stray old job to be dropped in session 2, got dropped=%d", m2.Dropped)
	}

	store.Close()
	store.Wait()
}

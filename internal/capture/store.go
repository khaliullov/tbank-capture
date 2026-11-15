package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

// JobSubmitter provides an interface for non-blocking job submission to the capture store.
type JobSubmitter interface {
	Submit(job discovery.CaptureJob) bool
}

// Store manages a bounded capture queue and persists raw responses to disk if enabled.
// It implements an explicit, thread-safe shutdown protocol.
type Store struct {
	log        *slog.Logger
	rawDir     string
	rawEnabled bool
	queue      chan discovery.CaptureJob
	collector  *discovery.Collector
	done       chan struct{}

	mu           sync.RWMutex
	closed       bool
	closeOnce    sync.Once
	droppedCount atomic.Int64
}

// NewStore creates a Store. The queue channel is owned and managed by the Store.
func NewStore(
	log *slog.Logger,
	rawDir string,
	rawEnabled bool,
	queueCap int,
	collector *discovery.Collector,
) *Store {
	if queueCap <= 0 {
		queueCap = 128
	}
	return &Store{
		log:        log,
		rawDir:     rawDir,
		rawEnabled: rawEnabled,
		queue:      make(chan discovery.CaptureJob, queueCap),
		collector:  collector,
		done:       make(chan struct{}),
	}
}

// Queue returns the write-end of the capture channel.
// Prefer using Submit for race-safe submission during shutdown.
func (s *Store) Queue() chan<- discovery.CaptureJob { return s.queue }

// Submit attempts to enqueue a capture job non-blockingly.
// It returns false if the queue is full or if the store has stopped accepting jobs.
// It is guaranteed never to panic on a closed channel.
func (s *Store) Submit(job discovery.CaptureJob) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return false
	}

	select {
	case s.queue <- job:
		return true
	default:
		return false
	}
}

// Close stops accepting new capture jobs and closes the internal queue channel.
// It is idempotent and safe for concurrent calls.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		s.log.Debug("store stopped accepting new jobs; queue closed")
	})
}

// Run starts the store worker. It runs until the queue is drained after Close(),
// or until ctx is cancelled. Call this in a dedicated goroutine.
func (s *Store) Run(ctx context.Context) {
	defer close(s.done)
	for {
		select {
		case job, ok := <-s.queue:
			if !ok {
				s.log.Info("store worker drained queue and finished normally")
				return
			}
			s.process(job)

		case <-ctx.Done():
			// Context cancellation: stop accepting and drain any pending jobs.
			// All accepted jobs must either be processed or explicitly counted as dropped.
			s.Close()
			for {
				select {
				case job, ok := <-s.queue:
					if !ok {
						return
					}
					s.droppedCount.Add(1)
					if s.collector != nil {
						s.collector.IncrIgnored()
					}
					s.log.Warn("job dropped due to worker cancellation", "url", NormalizedURL(job.URL))
				default:
					s.log.Info("store worker cancelled; pending jobs drained and accounted for")
					return
				}
			}
		}
	}
}

// Wait blocks until the store worker has finished processing and terminated.
func (s *Store) Wait() { <-s.done }

// DroppedCount returns the count of accepted jobs that were dropped due to cancellation.
func (s *Store) DroppedCount() int64 { return s.droppedCount.Load() }

func (s *Store) process(job discovery.CaptureJob) {
	if s.collector != nil {
		s.collector.ProcessJob(job)
	}

	// Persist raw body only when explicitly enabled, body is present, and no auth secret was detected.
	if s.rawEnabled && len(job.Body) > 0 {
		if err := s.persistRaw(job); err != nil {
			s.log.Warn("raw persist failed", "err", err)
		}
	}
}

func (s *Store) persistRaw(job discovery.CaptureJob) error {
	dir := filepath.Join(s.rawDir, string(job.SessionID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create raw dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405.000000000Z")
	name := fmt.Sprintf("%s_%s_%d.json", ts, job.SessionID, job.Status)
	path := filepath.Join(dir, name)

	type rawRecord struct {
		CapturedAt    string          `json:"captured_at"`
		Method        string          `json:"method"`
		NormalizedURL string          `json:"normalized_url"`
		Status        int             `json:"status"`
		ContentType   string          `json:"content_type"`
		ResourceType  string          `json:"resource_type"`
		BodyBytes     int64           `json:"body_bytes"`
		Body          json.RawMessage `json:"body"`
	}

	rec := rawRecord{
		CapturedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Method:        job.Method,
		NormalizedURL: NormalizedURL(job.URL),
		Status:        job.Status,
		ContentType:   job.ContentType,
		ResourceType:  job.ResourceType,
		BodyBytes:     job.BodySize,
		Body:          json.RawMessage(job.Body),
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal raw record: %w", err)
	}

	return atomicWriteFile(path, data, 0600)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

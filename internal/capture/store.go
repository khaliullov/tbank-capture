package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

// Store manages a bounded capture queue and persists raw responses to disk.
// Raw storage is optional and must be explicitly enabled.
type Store struct {
	log        *slog.Logger
	rawDir     string
	rawEnabled bool
	queue      chan discovery.CaptureJob
	collector  *discovery.Collector
	done       chan struct{}
}

// NewStore creates a Store. The queue channel is owned by the Store.
// queueCap: bounded channel capacity.
func NewStore(
	log *slog.Logger,
	rawDir string,
	rawEnabled bool,
	queueCap int,
	collector *discovery.Collector,
) *Store {
	return &Store{
		log:        log,
		rawDir:     rawDir,
		rawEnabled: rawEnabled,
		queue:      make(chan discovery.CaptureJob, queueCap),
		collector:  collector,
		done:       make(chan struct{}),
	}
}

// Queue returns the write-end of the capture channel for the response handler.
func (s *Store) Queue() chan<- discovery.CaptureJob { return s.queue }

// Run starts the store worker. It runs until ctx is cancelled and all queued
// jobs are drained. Call this in a goroutine.
func (s *Store) Run(ctx context.Context) {
	defer close(s.done)
	for {
		select {
		case job, ok := <-s.queue:
			if !ok {
				return
			}
			s.process(job)
		case <-ctx.Done():
			// Drain remaining jobs before exiting.
			for {
				select {
				case job := <-s.queue:
					s.process(job)
				default:
					s.log.Info("store worker drained and stopped")
					return
				}
			}
		}
	}
}

// Wait blocks until the store worker has exited.
func (s *Store) Wait() { <-s.done }

func (s *Store) process(job discovery.CaptureJob) {
	// Forward to collector for fingerprinting and schema analysis.
	s.collector.ProcessJob(job)

	// Persist raw body only when explicitly enabled and body is available.
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

// atomicWriteFile writes data to path atomically via a temp file.
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

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Collector aggregates endpoint observations and builds fingerprints.
// It is safe for concurrent use.
type Collector struct {
	log         *slog.Logger
	sessionDir  string
	classifier  *Classifier
	analyzerCfg AnalyzerConfig

	mu           sync.Mutex
	session      *Session
	fingerprints map[FingerprintID]*EndpointFingerprint
	bodyHashes   map[FingerprintID]map[string]bool // tracks unique bodies per FP

	// Metrics (read with Metrics()).
	totalObserved     int
	eligibleResponses int
	ignoredResponses  int
	captureFailures   int
	queueOverflows    int
}

// NewCollector creates a Collector. sessionDir is the data/discovery/sessions directory.
func NewCollector(log *slog.Logger, sessionDir string, cfg AnalyzerConfig) *Collector {
	return &Collector{
		log:          log,
		sessionDir:   sessionDir,
		classifier:   NewClassifier(),
		analyzerCfg:  cfg,
		fingerprints: make(map[FingerprintID]*EndpointFingerprint),
		bodyHashes:   make(map[FingerprintID]map[string]bool),
	}
}

// Metrics holds counters for telemetry.
type Metrics struct {
	TotalObserved         int
	EligibleResponses     int
	IgnoredResponses      int
	CaptureFailures       int
	QueueOverflows        int
	UniqueFingerprints    int
	TransactionCandidates int
}

// Metrics returns a snapshot of current counters.
func (c *Collector) Metrics() Metrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := Metrics{
		TotalObserved:      c.totalObserved,
		EligibleResponses:  c.eligibleResponses,
		IgnoredResponses:   c.ignoredResponses,
		CaptureFailures:    c.captureFailures,
		QueueOverflows:     c.queueOverflows,
		UniqueFingerprints: len(c.fingerprints),
	}
	for _, fp := range c.fingerprints {
		if fp.Classification.Category == CategoryTransactions && fp.Classification.Confidence >= 0.6 {
			m.TransactionCandidates++
		}
	}
	return m
}

// IncrQueueOverflow increments the queue overflow counter.
func (c *Collector) IncrQueueOverflow() {
	c.mu.Lock()
	c.queueOverflows++
	c.mu.Unlock()
}

// IncrIgnored increments the ignored counter.
func (c *Collector) IncrIgnored() {
	c.mu.Lock()
	c.ignoredResponses++
	c.totalObserved++
	c.mu.Unlock()
}

// StartSession begins a new discovery session.
func (c *Collector) StartSession(id SessionID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = &Session{
		ID:        id,
		StartedAt: time.Now().UTC(),
		Active:    true,
	}
	c.fingerprints = make(map[FingerprintID]*EndpointFingerprint)
	c.bodyHashes = make(map[FingerprintID]map[string]bool)
	c.totalObserved = 0
	c.eligibleResponses = 0
	c.ignoredResponses = 0
	c.captureFailures = 0
	c.queueOverflows = 0
	c.log.Info("discovery session started", "sessionID", id)
}

// ActiveSession returns the current session, or nil.
func (c *Collector) ActiveSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// ProcessJob processes a captured response job, updating fingerprints.
func (c *Collector) ProcessJob(job CaptureJob) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalObserved++

	if job.BodyError != "" {
		c.captureFailures++
		c.log.Warn("body retrieval failed", "url", sanitizeURLForLog(job.URL), "err", job.BodyError)
	}

	// Analyze JSON structure if body available.
	var fields []FieldSchema
	var topKind JSONKind
	if len(job.Body) > 0 {
		var err error
		fields, topKind, err = AnalyzeJSON(job.Body, c.analyzerCfg)
		if err != nil {
			c.captureFailures++
			c.log.Warn("json analysis failed", "err", err)
		}
	}

	structHash := structureHashFromFields(fields)
	normPath := NormalizePath(extractPath(job.URL))
	fpID := BuildFingerprintID(job.Method, normPath, job.ContentType, job.ResourceType, topKind, structHash)

	now := time.Now().UTC()
	fp, exists := c.fingerprints[fpID]
	if !exists {
		fp = &EndpointFingerprint{
			ID:             fpID,
			SessionID:      job.SessionID,
			Method:         job.Method,
			NormalizedPath: normPath,
			ExampleURL:     stripQueryAndCreds(job.URL),
			ContentType:    job.ContentType,
			ResourceType:   job.ResourceType,
			TopLevelKind:   topKind,
			StructureHash:  structHash,
			SchemaFields:   fields,
			StatusDist:     make(StatusDist),
			FirstSeen:      now,
		}
		c.fingerprints[fpID] = fp
		c.bodyHashes[fpID] = make(map[string]bool)
		c.log.Info("new endpoint fingerprint", "id", fpID, "path", normPath)
	}

	// Update fingerprint.
	fp.LastSeen = now
	fp.Observations++
	fp.StatusDist[job.Status]++
	fp.TotalBytes += job.BodySize
	if job.BodySize > fp.MaxResponseSize {
		fp.MaxResponseSize = job.BodySize
	}
	if job.HasDateParam {
		fp.HasDateParams = true
	}

	// Check for pagination signals.
	if !fp.IsPaginated && hasPaginationSignal(fields) {
		fp.IsPaginated = true
	}
	// Check if returns a list.
	if topKind == JSONKindArray || hasList(fields) {
		fp.ReturnsList = true
	}

	// Track unique bodies by hash.
	if len(job.Body) > 0 {
		h := quickHash(job.Body)
		if !c.bodyHashes[fpID][h] {
			c.bodyHashes[fpID][h] = true
			fp.UniqueBodyCount++
		}
	}

	// Merge new fields into existing schema (new paths encountered later).
	fp.SchemaFields = mergeFields(fp.SchemaFields, fields)
	// Recompute classification.
	fp.Classification = c.classifier.Classify(fp)

	c.eligibleResponses++
}

// StopSession marks the session as stopped and returns its value.
func (c *Collector) StopSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		c.session.StoppedAt = time.Now().UTC()
		c.session.Active = false
	}
	return c.session
}

// Fingerprints returns a copy of all current fingerprints.
func (c *Collector) Fingerprints() []*EndpointFingerprint {
	c.mu.Lock()
	defer c.mu.Unlock()
	fps := make([]*EndpointFingerprint, 0, len(c.fingerprints))
	for _, fp := range c.fingerprints {
		copy := *fp
		fps = append(fps, &copy)
	}
	sort.Slice(fps, func(i, j int) bool {
		return fps[i].Classification.Confidence > fps[j].Classification.Confidence
	})
	return fps
}

// PersistSession writes session metadata to disk.
func (c *Collector) PersistSession() error {
	c.mu.Lock()
	sess := c.session
	fps := make([]*EndpointFingerprint, 0, len(c.fingerprints))
	for _, fp := range c.fingerprints {
		copy := *fp
		fps = append(fps, &copy)
	}
	c.mu.Unlock()

	if sess == nil {
		return nil
	}
	if err := os.MkdirAll(c.sessionDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	sessFile := filepath.Join(c.sessionDir, fmt.Sprintf("%s.json", sess.ID))
	type persisted struct {
		Session      *Session               `json:"session"`
		Fingerprints []*EndpointFingerprint `json:"fingerprints"`
	}
	data, err := json.MarshalIndent(persisted{Session: sess, Fingerprints: fps}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	return atomicWriteFile(sessFile, data, 0600)
}

// --- helpers ---

func extractPath(rawURL string) string {
	// Extract path without query or credentials.
	u := strings.TrimPrefix(rawURL, "https://")
	u = strings.TrimPrefix(u, "http://")
	if idx := strings.Index(u, "/"); idx >= 0 {
		pathAndQuery := u[idx:]
		if qIdx := strings.Index(pathAndQuery, "?"); qIdx >= 0 {
			return pathAndQuery[:qIdx]
		}
		return pathAndQuery
	}
	return "/"
}

func stripQueryAndCreds(rawURL string) string {
	// Return scheme + host + path only.
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			// Remove credentials user:pass@
			if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
				slashIdx := strings.Index(rest, "/")
				if atIdx < slashIdx || slashIdx < 0 {
					rest = rest[atIdx+1:]
				}
			}
			if qIdx := strings.Index(rest, "?"); qIdx >= 0 {
				rest = rest[:qIdx]
			}
			if hIdx := strings.Index(rest, "#"); hIdx >= 0 {
				rest = rest[:hIdx]
			}
			return prefix + rest
		}
	}
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		return rawURL[:idx]
	}
	return rawURL
}

func sanitizeURLForLog(rawURL string) string {
	return stripQueryAndCreds(rawURL)
}

func hasPaginationSignal(fields []FieldSchema) bool {
	paginationKeys := []string{"page", "pagesize", "pagenum", "totalcount", "totalpages",
		"offset", "limit", "cursor", "nexttokenizer", "nextpage", "hasmore", "total", "count"}
	for _, f := range fields {
		leaf := strings.ToLower(fieldLeaf(f.Path))
		for _, k := range paginationKeys {
			if leaf == k || strings.Contains(leaf, k) {
				return true
			}
		}
	}
	return false
}

func hasList(fields []FieldSchema) bool {
	for _, f := range fields {
		if f.Classification == FieldClassCollection {
			return true
		}
		for _, t := range f.ObservedTypes {
			if t == "array" {
				return true
			}
		}
	}
	return false
}

func mergeFields(existing, incoming []FieldSchema) []FieldSchema {
	byPath := make(map[string]int, len(existing))
	for i, f := range existing {
		byPath[f.Path] = i
	}
	for _, f := range incoming {
		if idx, ok := byPath[f.Path]; ok {
			// Merge types.
			existing[idx].Count += f.Count
			typeSet := map[string]bool{}
			for _, t := range existing[idx].ObservedTypes {
				typeSet[t] = true
			}
			for _, t := range f.ObservedTypes {
				if !typeSet[t] {
					existing[idx].ObservedTypes = append(existing[idx].ObservedTypes, t)
				}
			}
		} else {
			existing = append(existing, f)
			byPath[f.Path] = len(existing) - 1
		}
	}
	return existing
}

func quickHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

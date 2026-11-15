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

// Collector aggregates endpoint observations and builds fingerprints for discovery sessions.
// It is safe for concurrent use.
type Collector struct {
	log         *slog.Logger
	sessionDir  string
	classifier  *Classifier
	analyzerCfg AnalyzerConfig

	mu           sync.Mutex
	session      *Session
	fingerprints map[FingerprintID]*EndpointFingerprint
	bodyHashes   map[FingerprintID]map[string]bool

	// Metrics
	totalObserved     int
	eligibleResponses int
	ignoredResponses  int
	captureFailures   int
	queueOverflows    int
}

// NewCollector creates a Collector. sessionDir is where session state JSON files are saved.
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

// Metrics returns a snapshot of current telemetry counters.
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

// IncrIgnored increments the ignored counter and total observed counter.
func (c *Collector) IncrIgnored() {
	c.mu.Lock()
	c.ignoredResponses++
	c.totalObserved++
	c.mu.Unlock()
}

// StartSession begins a new discovery session. Any previous session is stopped.
func (c *Collector) StartSession(id SessionID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil && c.session.Active {
		c.session.Active = false
		c.session.StoppedAt = time.Now().UTC()
	}

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

// ActiveSession returns a snapshot copy of the current session, or nil if no session exists.
func (c *Collector) ActiveSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil
	}
	cp := *c.session
	return &cp
}

// ProcessJob validates the job against the active session and updates endpoint fingerprints.
// Jobs from inactive or mismatched sessions are rejected to ensure strict session isolation.
func (c *Collector) ProcessJob(job CaptureJob) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Strict session validation: job must match the active session.
	if c.session == nil || !c.session.Active || job.SessionID == "" || job.SessionID != c.session.ID {
		c.ignoredResponses++
		return
	}

	c.totalObserved++

	var warnings []string
	if job.BodyError != "" {
		c.captureFailures++
		warningMsg := fmt.Sprintf("body retrieval failed: %s", job.BodyError)
		warnings = append(warnings, warningMsg)
		c.log.Debug("body retrieval issue", "url", sanitizeURLForLog(job.URL), "err", job.BodyError)
	}

	// Analyze JSON structure if body is available.
	var fields []FieldSchema
	var topKind JSONKind = JSONKindUnknown
	if len(job.Body) > 0 {
		var err error
		fields, topKind, err = AnalyzeJSON(job.Body, c.analyzerCfg)
		if err != nil {
			c.captureFailures++
			warningMsg := fmt.Sprintf("json analysis error: %s", err)
			warnings = append(warnings, warningMsg)
			c.log.Debug("json analysis issue", "err", err)
		}
	}

	structHash := structureHashFromFields(fields)
	normPath := NormalizePath(extractPath(job.URL))
	fpID := BuildFingerprintID(job.Method, normPath, job.ContentType, job.ResourceType, topKind, structHash)

	now := time.Now().UTC()
	fp, exists := c.fingerprints[fpID]
	if !exists {
		fp = &EndpointFingerprint{
			ID:              fpID,
			SessionID:       c.session.ID,
			Method:          job.Method,
			NormalizedPath:  normPath,
			ExampleURL:      stripQueryAndCreds(job.URL),
			ContentType:     job.ContentType,
			ResourceType:    job.ResourceType,
			TopLevelKind:    topKind,
			StructureHash:   structHash,
			SchemaFields:    fields,
			StatusDist:      make(StatusDist),
			FirstSeen:       now,
			CaptureWarnings: warnings,
		}
		c.fingerprints[fpID] = fp
		c.bodyHashes[fpID] = make(map[string]bool)
		c.log.Info("new endpoint fingerprint", "id", fpID, "path", normPath)
	} else if len(warnings) > 0 {
		fp.CaptureWarnings = appendUniqueStrings(fp.CaptureWarnings, warnings)
	}

	// Update fingerprint metrics
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

	if !fp.IsPaginated && hasPaginationSignal(fields) {
		fp.IsPaginated = true
	}
	if topKind == JSONKindArray || hasList(fields) {
		fp.ReturnsList = true
	}

	// Track unique response bodies by hash.
	if len(job.Body) > 0 {
		h := quickHash(job.Body)
		if !c.bodyHashes[fpID][h] {
			c.bodyHashes[fpID][h] = true
			fp.UniqueBodyCount++
		}
	}

	// Merge new fields and recalculate optionality across observations.
	fp.SchemaFields = mergeFields(fp.SchemaFields, fields, fp.Observations)

	// Recompute classification with latest evidence.
	fp.Classification = c.classifier.Classify(fp)

	c.eligibleResponses++
}

// StopSession marks the active session as stopped and returns a snapshot copy.
func (c *Collector) StopSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil && c.session.Active {
		c.session.StoppedAt = time.Now().UTC()
		c.session.Active = false
	}
	if c.session == nil {
		return nil
	}
	cp := *c.session
	return &cp
}

// Fingerprints returns a deep-copy snapshot of all collected fingerprints.
func (c *Collector) Fingerprints() []*EndpointFingerprint {
	c.mu.Lock()
	defer c.mu.Unlock()
	fps := make([]*EndpointFingerprint, 0, len(c.fingerprints))
	for _, fp := range c.fingerprints {
		fps = append(fps, cloneFingerprint(fp))
	}
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Classification.Confidence != fps[j].Classification.Confidence {
			return fps[i].Classification.Confidence > fps[j].Classification.Confidence
		}
		return fps[i].NormalizedPath < fps[j].NormalizedPath
	})
	return fps
}

// PersistSession writes the session metadata and fingerprints snapshot to disk atomically.
func (c *Collector) PersistSession() error {
	c.mu.Lock()
	if c.session == nil {
		c.mu.Unlock()
		return nil
	}
	sessCopy := *c.session
	fps := make([]*EndpointFingerprint, 0, len(c.fingerprints))
	for _, fp := range c.fingerprints {
		fps = append(fps, cloneFingerprint(fp))
	}
	c.mu.Unlock()

	if err := os.MkdirAll(c.sessionDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	sessFile := filepath.Join(c.sessionDir, fmt.Sprintf("%s.json", sessCopy.ID))
	type persisted struct {
		Session      Session                `json:"session"`
		Fingerprints []*EndpointFingerprint `json:"fingerprints"`
	}
	data, err := json.MarshalIndent(persisted{Session: sessCopy, Fingerprints: fps}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	return atomicWriteFile(sessFile, data, 0600)
}

// cloneFingerprint creates a deep copy of an EndpointFingerprint.
func cloneFingerprint(fp *EndpointFingerprint) *EndpointFingerprint {
	if fp == nil {
		return nil
	}
	cp := *fp

	// Deep copy SchemaFields
	if fp.SchemaFields != nil {
		cp.SchemaFields = make([]FieldSchema, len(fp.SchemaFields))
		for i, f := range fp.SchemaFields {
			fCopy := f
			if f.ObservedTypes != nil {
				fCopy.ObservedTypes = make([]string, len(f.ObservedTypes))
				copy(fCopy.ObservedTypes, f.ObservedTypes)
			}
			cp.SchemaFields[i] = fCopy
		}
	}

	// Deep copy StatusDist map
	if fp.StatusDist != nil {
		cp.StatusDist = make(StatusDist, len(fp.StatusDist))
		for k, v := range fp.StatusDist {
			cp.StatusDist[k] = v
		}
	}

	// Deep copy Classification reasons
	if fp.Classification.Reasons != nil {
		cp.Classification.Reasons = make([]string, len(fp.Classification.Reasons))
		copy(cp.Classification.Reasons, fp.Classification.Reasons)
	}

	// Deep copy CaptureWarnings
	if fp.CaptureWarnings != nil {
		cp.CaptureWarnings = make([]string, len(fp.CaptureWarnings))
		copy(cp.CaptureWarnings, fp.CaptureWarnings)
	}

	return &cp
}

// --- helpers ---

func extractPath(rawURL string) string {
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
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
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

func mergeFields(existing, incoming []FieldSchema, totalObservations int) []FieldSchema {
	byPath := make(map[string]int, len(existing))
	for i, f := range existing {
		byPath[f.Path] = i
	}
	for _, f := range incoming {
		if idx, ok := byPath[f.Path]; ok {
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

	// Update optionality across observations: if a field was not present in all observations
	for i := range existing {
		if totalObservations > 1 && existing[i].Count < totalObservations {
			existing[i].Optional = true
		}
	}

	return existing
}

func appendUniqueStrings(slice []string, items []string) []string {
	seen := make(map[string]bool, len(slice)+len(items))
	var out []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func quickHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

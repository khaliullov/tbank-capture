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

	// Unified metrics counters
	observed      int
	filtered      int
	eligible      int
	enqueued      int
	processed     int
	dropped       int
	captureFailed int
	queueOverflow int
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
	return c.metricsLocked()
}

func (c *Collector) metricsLocked() Metrics {
	m := Metrics{
		Observed:           c.observed,
		Filtered:           c.filtered,
		Eligible:           c.eligible,
		Enqueued:           c.enqueued,
		Processed:          c.processed,
		Dropped:            c.dropped,
		CaptureFailed:      c.captureFailed,
		QueueOverflow:      c.queueOverflow,
		UniqueFingerprints: len(c.fingerprints),

		// Legacy aliases
		TotalObserved:     c.observed,
		EligibleResponses: c.eligible,
		IgnoredResponses:  c.filtered,
		CaptureFailures:   c.captureFailed,
		QueueOverflows:    c.queueOverflow,
	}

	for _, fp := range c.fingerprints {
		if fp.Classification.Category == CategoryTransactions && fp.Classification.Confidence >= 0.6 {
			m.TransactionCandidates++
		}
		if fp.Classification.Category == CategoryAccounts && fp.Classification.Confidence >= 0.6 {
			m.AccountCandidates++
		}
		if fp.Classification.Category == CategoryCards && fp.Classification.Confidence >= 0.6 {
			m.CardCandidates++
		}
		if fp.Classification.Category == CategoryBalances && fp.Classification.Confidence >= 0.6 {
			m.BalanceCandidates++
		}
		if fp.Classification.Category == CategoryPayments && fp.Classification.Confidence >= 0.6 {
			m.PaymentCandidates++
		}
		if fp.Classification.Category == CategoryTransfers && fp.Classification.Confidence >= 0.6 {
			m.TransferCandidates++
		}
		if fp.Classification.Category == CategoryStatements && fp.Classification.Confidence >= 0.6 {
			m.StatementCandidates++
		}
	}
	return m
}

// IncrObserved increments the total observed response counter.
func (c *Collector) IncrObserved() {
	c.mu.Lock()
	c.observed++
	c.mu.Unlock()
}

// IncrFiltered increments the filtered response counter.
func (c *Collector) IncrFiltered() {
	c.mu.Lock()
	c.filtered++
	c.mu.Unlock()
}

// IncrEligible increments the eligible response counter.
func (c *Collector) IncrEligible() {
	c.mu.Lock()
	c.eligible++
	c.mu.Unlock()
}

// IncrEnqueued increments the enqueued job counter.
func (c *Collector) IncrEnqueued() {
	c.mu.Lock()
	c.enqueued++
	c.mu.Unlock()
}

// IncrQueueOverflow increments both queue overflow and dropped counters.
func (c *Collector) IncrQueueOverflow() {
	c.mu.Lock()
	c.queueOverflow++
	c.dropped++
	c.mu.Unlock()
}

// IncrDroppedInQueue increments dropped count for jobs drained during cancellation.
func (c *Collector) IncrDroppedInQueue() {
	c.mu.Lock()
	c.dropped++
	c.mu.Unlock()
}

// IncrCaptureFailed increments the capture failure counter.
func (c *Collector) IncrCaptureFailed() {
	c.mu.Lock()
	c.captureFailed++
	c.mu.Unlock()
}

// IncrIgnored is a backward-compatible alias that increments both filtered and observed.
func (c *Collector) IncrIgnored() {
	c.mu.Lock()
	c.filtered++
	c.observed++
	c.mu.Unlock()
}

// StartSession begins a new discovery session. Any previous active session is finalized.
func (c *Collector) StartSession(id SessionID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil && (c.session.State == SessionStateActive || c.session.State == SessionStateStopping) {
		c.session.Active = false
		c.session.State = SessionStateStopped
		c.session.StoppedAt = time.Now().UTC()
	}

	c.session = &Session{
		ID:        id,
		StartedAt: time.Now().UTC(),
		State:     SessionStateActive,
		Active:    true,
	}
	c.fingerprints = make(map[FingerprintID]*EndpointFingerprint)
	c.bodyHashes = make(map[FingerprintID]map[string]bool)

	c.observed = 0
	c.filtered = 0
	c.eligible = 0
	c.enqueued = 0
	c.processed = 0
	c.dropped = 0
	c.captureFailed = 0
	c.queueOverflow = 0

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

// BeginStopping transitions the session to SessionStateStopping, preventing new events
// while allowing existing queued jobs for this session to be processed.
func (c *Collector) BeginStopping(id SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil || c.session.ID != id {
		return fmt.Errorf("session %s not found", id)
	}
	if c.session.State != SessionStateActive {
		return fmt.Errorf("session %s is not active (state: %s)", id, c.session.State)
	}

	c.session.State = SessionStateStopping
	c.log.Info("discovery session stopping (draining queued jobs)", "sessionID", id)
	return nil
}

// FinalizeSession transitions the session to SessionStateStopped and returns consistent
// snapshots of session state, fingerprints, and metrics.
func (c *Collector) FinalizeSession(id SessionID) (*Session, []*EndpointFingerprint, Metrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil || c.session.ID != id {
		return nil, nil, Metrics{}, fmt.Errorf("session %s not found", id)
	}
	if c.session.State == SessionStateStopped {
		return nil, nil, Metrics{}, fmt.Errorf("session %s already stopped", id)
	}

	c.session.State = SessionStateStopped
	c.session.Active = false
	c.session.StoppedAt = time.Now().UTC()

	sessCopy := *c.session
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

	metrics := c.metricsLocked()
	c.log.Info("discovery session finalized", "sessionID", id, "fingerprints", len(fps), "processed", metrics.Processed)

	return &sessCopy, fps, metrics, nil
}

// StopSession marks the active session as stopped immediately and returns a snapshot copy.
func (c *Collector) StopSession() *Session {
	c.mu.Lock()
	if c.session == nil {
		c.mu.Unlock()
		return nil
	}
	id := c.session.ID
	c.mu.Unlock()

	_ = c.BeginStopping(id)
	sess, _, _, _ := c.FinalizeSession(id)
	return sess
}

// ProcessJob validates the job against the active or stopping session and updates endpoint fingerprints.
// Jobs from inactive or mismatched sessions are rejected to ensure strict session isolation.
func (c *Collector) ProcessJob(job CaptureJob) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Strict session validation: job must match the active or stopping session.
	if c.session == nil || (c.session.State != SessionStateActive && c.session.State != SessionStateStopping) || job.SessionID == "" || job.SessionID != c.session.ID {
		if c.session != nil && (c.session.State == SessionStateActive || c.session.State == SessionStateStopping) {
			c.dropped++
		} else {
			c.filtered++
		}
		return
	}

	c.processed++

	var warnings []string
	if job.BodyError != "" {
		c.captureFailed++
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
			c.captureFailed++
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

package capture

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
	pw "github.com/playwright-community/playwright-go"
)

const (
	DefaultResponseWorkerCount = 8
	DefaultResponseQueueCap    = 256
)

type defaultChanSubmitter struct {
	queue chan<- discovery.CaptureJob
}

func (s *defaultChanSubmitter) Submit(job discovery.CaptureJob) bool {
	select {
	case s.queue <- job:
		return true
	default:
		return false
	}
}

// ResponseHandlerOption configures optional parameters for ResponseHandler.
type ResponseHandlerOption func(*ResponseHandler)

// WithWorkerCount sets the worker pool size for concurrent response processing.
func WithWorkerCount(workers int) ResponseHandlerOption {
	return func(h *ResponseHandler) {
		if workers > 0 {
			h.workerCount = workers
		}
	}
}

// WithQueueCapacity sets the internal response queue buffer capacity.
func WithQueueCapacity(cap int) ResponseHandlerOption {
	return func(h *ResponseHandler) {
		if cap > 0 {
			h.queueCap = cap
		}
	}
}

// ResponseHandler observes network responses in Playwright, applies filters,
// enforces payload size limits before and after body retrieval, and safely enqueues
// capture jobs for asynchronous processing using a bounded worker pool.
//
// Limitation Note:
// In Playwright Go, response events are emitted after Chromium has received the HTTP response.
// Chromium may buffer response bodies internally in browser memory before this handler is invoked.
// Application-level Content-Length and body size checks protect Go process memory and capture storage,
// but cannot enforce a strict upper bound on Chromium's internal memory footprint.
type ResponseHandler struct {
	log             *slog.Logger
	filter          *Filter
	submitter       JobSubmitter
	collector       *discovery.Collector
	sessionID       func() discovery.SessionID
	activeSessionID discovery.SessionID
	maxBody         int64

	workerCount int
	queueCap    int
	respQueue   chan pw.Response

	mu        sync.RWMutex
	active    bool
	workerWg  sync.WaitGroup // waits for worker pool goroutines on shutdown
	inFlight  atomic.Int64   // tracks queued and in-progress response jobs
	drainMu   sync.Mutex
	cond      *sync.Cond
	closeOnce sync.Once

	// Metrics counters
	countObserved  atomic.Int64
	countEligible  atomic.Int64
	countFiltered  atomic.Int64
	countQueueFull atomic.Int64
}

// NewResponseHandler creates a ResponseHandler with a bounded worker pool and queue.
func NewResponseHandler(
	log *slog.Logger,
	filter *Filter,
	queue chan<- discovery.CaptureJob,
	sessionID func() discovery.SessionID,
	maxBody int64,
	opts ...ResponseHandlerOption,
) *ResponseHandler {
	h := &ResponseHandler{
		log:         log,
		filter:      filter,
		submitter:   &defaultChanSubmitter{queue: queue},
		sessionID:   sessionID,
		maxBody:     maxBody,
		workerCount: DefaultResponseWorkerCount,
		queueCap:    DefaultResponseQueueCap,
		active:      true,
	}

	for _, opt := range opts {
		opt(h)
	}

	h.respQueue = make(chan pw.Response, h.queueCap)
	h.cond = sync.NewCond(&h.drainMu)

	// Start bounded worker pool
	for i := 0; i < h.workerCount; i++ {
		h.workerWg.Add(1)
		go h.workerLoop()
	}

	return h
}

func (h *ResponseHandler) workerLoop() {
	defer h.workerWg.Done()
	for resp := range h.respQueue {
		h.HandleResponse(resp)
		if h.inFlight.Add(-1) == 0 {
			h.drainMu.Lock()
			h.cond.Broadcast()
			h.drainMu.Unlock()
		}
	}
}

// SetCollector associates a discovery.Collector with the handler for metric telemetry.
func (h *ResponseHandler) SetCollector(col *discovery.Collector) {
	h.mu.Lock()
	h.collector = col
	h.mu.Unlock()
}

// SetSubmitter allows configuring a custom JobSubmitter (such as *Store directly).
func (h *ResponseHandler) SetSubmitter(sub JobSubmitter) {
	h.mu.Lock()
	h.submitter = sub
	h.mu.Unlock()
}

// SetSessionID sets the active session ID for discovery capture.
func (h *ResponseHandler) SetSessionID(id discovery.SessionID) {
	h.mu.Lock()
	h.activeSessionID = id
	h.mu.Unlock()
}

// StopSession halts capture for the specified sessionID synchronously and waits
// for all currently queued responses for that session to be processed.
func (h *ResponseHandler) StopSession(sessionID discovery.SessionID) {
	h.mu.Lock()
	if h.activeSessionID == sessionID {
		h.activeSessionID = ""
	}
	h.mu.Unlock()

	// Drain any in-flight responses that were enqueued
	h.Wait()
}

// Deactivate stops the handler from accepting or enqueueing any new responses,
// waits for all in-flight responses to finish, closes the worker queue, and stops all workers.
func (h *ResponseHandler) Deactivate() {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.active = false
		h.activeSessionID = ""
		h.mu.Unlock()

		// Wait for all in-flight items to complete
		h.Wait()

		// Close worker queue and wait for workers to exit
		close(h.respQueue)
		h.workerWg.Wait()
		h.log.Debug("response handler deactivated")
	})
}

// Enqueue non-blockingly submits a response to the bounded worker queue without spawning goroutines.
func (h *ResponseHandler) Enqueue(resp pw.Response) {
	h.enqueue(resp)
}

// enqueue non-blockingly submits a response to the bounded worker queue without spawning goroutines.
func (h *ResponseHandler) enqueue(resp pw.Response) {
	h.mu.RLock()
	active := h.active
	if !active {
		h.mu.RUnlock()
		h.countFiltered.Add(1)
		if h.collector != nil {
			h.collector.RecordRejection(discovery.ReasonHandlerInactive)
		}
		return
	}

	h.inFlight.Add(1)
	select {
	case h.respQueue <- resp:
		h.mu.RUnlock()
	default:
		h.inFlight.Add(-1)
		h.mu.RUnlock()
		h.countQueueFull.Add(1)
		if h.collector != nil {
			h.collector.RecordQueueOverflow()
		}
		h.log.Warn("response processing queue full, response dropped",
			"url", NormalizedURL(resp.URL()),
			"queueCap", h.queueCap)
	}
}

// Attach registers OnResponse on the given Playwright page using the bounded worker pool.
func (h *ResponseHandler) Attach(page pw.Page) {
	page.OnResponse(func(resp pw.Response) {
		h.enqueue(resp)
	})
}

// AttachContext registers OnResponse on the entire browser context using the bounded worker pool.
func (h *ResponseHandler) AttachContext(bctx pw.BrowserContext) {
	bctx.OnResponse(func(resp pw.Response) {
		h.enqueue(resp)
	})
}

// Wait blocks until all queued and currently in-flight responses have completed processing.
func (h *ResponseHandler) Wait() {
	h.drainMu.Lock()
	for h.inFlight.Load() > 0 {
		h.cond.Wait()
	}
	h.drainMu.Unlock()
}

// HandleResponse processes a network response event with structured diagnostic tracking.
func (h *ResponseHandler) HandleResponse(resp pw.Response) {
	// Snapshot handler state under a brief read lock to avoid holding locks during Playwright RPCs.
	h.mu.RLock()
	active := h.active
	sessID := h.activeSessionID
	if sessID == "" && h.sessionID != nil {
		sessID = h.sessionID()
	}
	filter := h.filter
	submitter := h.submitter
	collector := h.collector
	maxBody := h.maxBody
	h.mu.RUnlock()

	rawURL := resp.URL()
	req := resp.Request()
	resourceType := strings.ToLower(strings.TrimSpace(req.ResourceType()))
	headers := resp.Headers()
	contentType := headers["content-type"]
	status := resp.Status()

	// Extract normalized hostname for passive telemetry
	host, hostErr := ExtractHostname(rawURL)
	isAllowed := false
	if hostErr == nil && filter != nil {
		isAllowed = filter.IsAllowedHost(host)
	}

	// Unconditionally observe every response and record aggregate metadata
	h.countObserved.Add(1)
	if collector != nil {
		collector.RecordObservation(host, isAllowed, resourceType, contentType, status)
	}

	// 1. Check handler active state
	if !active {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonHandlerInactive)
		}
		return
	}

	// 2. Check active session
	if sessID == "" {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonNoActiveSession)
		}
		return
	}

	// 3. URL validity check
	if hostErr != nil {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonMalformedURL)
		}
		return
	}

	// 4. Domain filter check
	if !isAllowed {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonNonAllowedDomain)
		}
		return
	}

	// 5. Excluded auth path check
	if filter != nil {
		if eligible, rej := filter.CheckEligiblePath(rawURL); !eligible {
			h.countFiltered.Add(1)
			if collector != nil {
				collector.RecordRejection(rej)
			}
			h.log.Debug("excluded auth path", "url", NormalizedURL(rawURL), "reason", rej)
			return
		}
	}

	// 6. Resource type filter check
	if filter != nil && !filter.EligibleResourceType(resourceType) {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonUnsupportedResourceType)
		}
		return
	}

	// 7. Content-Type filter check
	if filter != nil && !filter.EligibleContentType(contentType) {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonUnsupportedContentType)
		}
		return
	}

	// 8. Pre-read size limit check via Content-Length header
	var clDeclared int64 = -1
	if clStr, ok := headers["content-length"]; ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(clStr), 10, 64); err == nil && n >= 0 {
			clDeclared = n
		}
	}

	if clDeclared > maxBody {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonBodyTooLarge)
		}
		h.log.Debug("response rejected before reading: Content-Length exceeds limit",
			"url", NormalizedURL(rawURL),
			"contentLength", clDeclared,
			"maxAllowed", maxBody)
		return
	}

	// 9. Read body without holding mutex locks
	body, err := resp.Body()
	if err != nil {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonBodyReadError)
		}
		h.log.Debug("body read error", "url", NormalizedURL(rawURL), "err", err)

		// Metadata-only failure event: record failure diagnostic without sensitive query or headers
		var reportedSize int64
		if clDeclared > 0 {
			reportedSize = clDeclared
		}
		failJob := discovery.CaptureJob{
			SessionID:    sessID,
			Method:       req.Method(),
			URL:          NormalizedURL(rawURL), // Query parameters, fragments, userinfo stripped
			Status:       status,
			ContentType:  contentType,
			ResourceType: resourceType,
			Body:         nil, // Never include response contents
			BodySize:     reportedSize,
			RawBodySize:  reportedSize,
			BodyError:    err.Error(),
			HasDateParam: false,
			Sanitized:    false,
			CapturedAt:   time.Now().UTC(),
		}
		h.countEligible.Add(1)
		if submitter != nil {
			if submitter.Submit(failJob) {
				if collector != nil {
					collector.RecordEnqueued()
				}
			} else {
				h.countQueueFull.Add(1)
				if collector != nil {
					collector.RecordQueueOverflow()
				}
				h.log.Warn("capture queue full or closed, dropping failed-body response",
					"url", NormalizedURL(rawURL),
					"queueFull", true)
			}
		}
		return
	}

	// Explicitly copy body bytes immediately to decouple from Playwright's internal buffer
	rawBodyBytes := make([]byte, len(body))
	copy(rawBodyBytes, body)
	rawSize := int64(len(rawBodyBytes))

	if rawSize > maxBody {
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonBodyTooLarge)
		}
		h.log.Debug("body rejected after read: size exceeds limit",
			"url", NormalizedURL(rawURL),
			"size", rawSize,
			"maxAllowed", maxBody)
		return
	}

	// 10. Credential detection & safe structural sanitization
	sanitizedBody, wasSanitized, sanFields, sanErr := SanitizeCredentials(rawBodyBytes)
	if sanErr != nil {
		// Fails closed on malformed JSON or pathological nesting
		h.countFiltered.Add(1)
		if collector != nil {
			collector.RecordRejection(discovery.ReasonCredentialDetected)
		}
		h.log.Debug("body rejected: malformed JSON or credential inspection failure", "url", NormalizedURL(rawURL), "err", sanErr)
		return
	}

	// 11. Build safe capture job preserving raw body size separately from sanitized size
	job := discovery.CaptureJob{
		SessionID:       sessID,
		Method:          req.Method(),
		URL:             rawURL,
		Status:          status,
		ContentType:     contentType,
		ResourceType:    resourceType,
		Body:            sanitizedBody,
		BodySize:        int64(len(sanitizedBody)),
		RawBodySize:     rawSize,
		HasDateParam:    discovery.QueryHasDateParams(RawQueryString(rawURL)),
		Sanitized:       wasSanitized,
		SanitizedFields: sanFields,
		CapturedAt:      time.Now().UTC(),
	}

	// 12. Submit job to queue
	h.countEligible.Add(1)
	if submitter != nil {
		if submitter.Submit(job) {
			if collector != nil {
				collector.RecordEnqueued()
			}
		} else {
			h.countQueueFull.Add(1)
			if collector != nil {
				collector.RecordQueueOverflow()
			}
			h.log.Warn("capture queue full or closed, dropping response",
				"url", NormalizedURL(rawURL),
				"queueFull", true)
		}
	}
}

// CountObserved returns total observed responses.
func (h *ResponseHandler) CountObserved() int64 { return h.countObserved.Load() }

// CountEligible returns eligible responses attempted.
func (h *ResponseHandler) CountEligible() int64 { return h.countEligible.Load() }

// CountFiltered returns filtered responses count.
func (h *ResponseHandler) CountFiltered() int64 { return h.countFiltered.Load() }

// CountIgnored is a backward-compatible alias for CountFiltered.
func (h *ResponseHandler) CountIgnored() int64 { return h.countFiltered.Load() }

// CountQueueFull returns queue overflow count.
func (h *ResponseHandler) CountQueueFull() int64 { return h.countQueueFull.Load() }

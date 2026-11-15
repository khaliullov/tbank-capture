package capture

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/khaliullov/tbank-capture/internal/discovery"
	pw "github.com/playwright-community/playwright-go"
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

// ResponseHandler observes network responses in Playwright, applies filters,
// enforces payload size limits before and after body retrieval, and safely enqueues
// capture jobs for asynchronous processing.
//
// Limitation Note:
// In Playwright Go, response events are emitted after Chromium has received the HTTP response.
// Chromium may buffer response bodies internally in browser memory before this handler is invoked.
// Application-level Content-Length and body size checks protect Go process memory and capture storage,
// but cannot enforce a strict upper bound on Chromium's internal memory footprint.
type ResponseHandler struct {
	log       *slog.Logger
	filter    *Filter
	submitter JobSubmitter
	collector *discovery.Collector
	sessionID func() discovery.SessionID
	maxBody   int64

	mu     sync.RWMutex
	active bool

	// Metrics counters
	countObserved  atomic.Int64
	countEligible  atomic.Int64
	countIgnored   atomic.Int64
	countQueueFull atomic.Int64
}

// NewResponseHandler creates a ResponseHandler with a raw queue channel.
func NewResponseHandler(
	log *slog.Logger,
	filter *Filter,
	queue chan<- discovery.CaptureJob,
	sessionID func() discovery.SessionID,
	maxBody int64,
) *ResponseHandler {
	return &ResponseHandler{
		log:       log,
		filter:    filter,
		submitter: &defaultChanSubmitter{queue: queue},
		sessionID: sessionID,
		maxBody:   maxBody,
		active:    true,
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

// Deactivate stops the handler from accepting or enqueueing any new responses.
// After Deactivate returns, no callbacks will send into the queue.
func (h *ResponseHandler) Deactivate() {
	h.mu.Lock()
	h.active = false
	h.mu.Unlock()
	h.log.Debug("response handler deactivated")
}

// Attach registers OnResponse on the given Playwright page.
func (h *ResponseHandler) Attach(page pw.Page) {
	page.OnResponse(func(resp pw.Response) {
		h.HandleResponse(resp)
	})
}

// AttachContext registers OnResponse on the entire browser context to observe all pages.
func (h *ResponseHandler) AttachContext(bctx pw.BrowserContext) {
	bctx.OnResponse(func(resp pw.Response) {
		h.HandleResponse(resp)
	})
}

// HandleResponse processes a network response event synchronously.
func (h *ResponseHandler) HandleResponse(resp pw.Response) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.active {
		h.countIgnored.Add(1)
		return
	}

	h.countObserved.Add(1)
	sessID := h.sessionID()
	if sessID == "" {
		h.countIgnored.Add(1)
		return
	}

	rawURL := resp.URL()

	// 1. Domain filter
	if !h.filter.EligibleURL(rawURL) {
		h.countIgnored.Add(1)
		return
	}

	// 2. Auth path filter
	if !h.filter.EligiblePath(rawURL) {
		h.countIgnored.Add(1)
		h.log.Debug("excluded auth path", "url", NormalizedURL(rawURL))
		return
	}

	// 3. Resource type filter
	req := resp.Request()
	resourceType := strings.ToLower(strings.TrimSpace(req.ResourceType()))
	if !h.filter.EligibleResourceType(resourceType) {
		h.countIgnored.Add(1)
		return
	}

	// 4. Content-Type filter
	headers := resp.Headers()
	contentType := headers["content-type"]
	if !h.filter.EligibleContentType(contentType) {
		h.countIgnored.Add(1)
		return
	}

	// Base capture job with URL and response metadata (safe for metadata-only discovery)
	job := discovery.CaptureJob{
		SessionID:    sessID,
		Method:       req.Method(),
		URL:          rawURL,
		Status:       resp.Status(),
		ContentType:  contentType,
		ResourceType: resourceType,
		HasDateParam: discovery.QueryHasDateParams(RawQueryString(rawURL)),
	}

	// 5. Pre-read size limit check via Content-Length header to avoid expensive allocation
	var clDeclared int64 = -1
	if clStr, ok := headers["content-length"]; ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(clStr), 10, 64); err == nil && n >= 0 {
			clDeclared = n
		}
	}

	if clDeclared > h.maxBody {
		job.BodyError = fmt.Sprintf("Content-Length %d exceeds max allowed %d bytes", clDeclared, h.maxBody)
		job.BodySize = clDeclared
		h.log.Debug("response rejected before reading: Content-Length exceeds limit",
			"url", NormalizedURL(rawURL),
			"contentLength", clDeclared,
			"maxAllowed", h.maxBody)
	} else {
		// Read body synchronously within Playwright response callback
		body, err := resp.Body()
		if err != nil {
			job.BodyError = fmt.Sprintf("body retrieval error: %v", err)
			h.log.Debug("body read error", "url", NormalizedURL(rawURL), "err", err)
		} else if int64(len(body)) > h.maxBody {
			// Second safety check on actual received body size
			job.BodyError = fmt.Sprintf("body size %d exceeds max allowed %d bytes", len(body), h.maxBody)
			job.BodySize = int64(len(body))
			h.log.Debug("body rejected after read: size exceeds limit",
				"url", NormalizedURL(rawURL),
				"size", len(body),
				"maxAllowed", h.maxBody)
		} else {
			// Inspect for authentication secrets conservatively
			if ContainsAuthSecret(body) {
				h.countIgnored.Add(1)
				h.log.Debug("excluded: auth secret detected in response body", "url", NormalizedURL(rawURL))
				return
			}
			job.Body = body
			job.BodySize = int64(len(body))
		}
	}

	h.countEligible.Add(1)

	// Enqueue job via submitter
	if h.submitter != nil {
		if !h.submitter.Submit(job) {
			h.countQueueFull.Add(1)
			if h.collector != nil {
				h.collector.IncrQueueOverflow()
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

// CountIgnored returns ignored responses count.
func (h *ResponseHandler) CountIgnored() int64 { return h.countIgnored.Load() }

// CountQueueFull returns queue overflow count.
func (h *ResponseHandler) CountQueueFull() int64 { return h.countQueueFull.Load() }

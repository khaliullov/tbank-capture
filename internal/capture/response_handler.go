package capture

import (
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/khaliullov/tbank-capture/internal/discovery"
	pw "github.com/playwright-community/playwright-go"
)

// ResponseHandler attaches to a Playwright page and enqueues eligible responses.
// It never blocks the Playwright event loop for disk I/O.
type ResponseHandler struct {
	log       *slog.Logger
	filter    *Filter
	queue     chan<- discovery.CaptureJob
	sessionID func() discovery.SessionID // returns current session ID, or ""
	maxBody   int64

	// Metrics — accessed atomically.
	countObserved  atomic.Int64
	countEligible  atomic.Int64
	countIgnored   atomic.Int64
	countQueueFull atomic.Int64
}

// NewResponseHandler creates a ResponseHandler.
// queue must be a buffered channel owned by the Store worker.
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
		queue:     queue,
		sessionID: sessionID,
		maxBody:   maxBody,
	}
}

// Attach registers OnResponse on the given page.
func (h *ResponseHandler) Attach(page pw.Page) {
	page.OnResponse(func(resp pw.Response) {
		h.handle(resp)
	})
}

// AttachContext registers OnResponse on the entire browser context.
func (h *ResponseHandler) AttachContext(bctx pw.BrowserContext) {
	bctx.OnResponse(func(resp pw.Response) {
		h.handle(resp)
	})
}

func (h *ResponseHandler) handle(resp pw.Response) {
	h.countObserved.Add(1)
	sessID := h.sessionID()
	if sessID == "" {
		// No active session — ignore silently.
		h.countIgnored.Add(1)
		return
	}

	rawURL := resp.URL()

	// Domain filter.
	if !h.filter.EligibleURL(rawURL) {
		h.countIgnored.Add(1)
		return
	}

	// Path filter (excludes auth paths).
	if !h.filter.EligiblePath(rawURL) {
		h.countIgnored.Add(1)
		h.log.Debug("excluded auth path", "url", NormalizedURL(rawURL))
		return
	}

	// Resource type filter via request.
	req := resp.Request()
	resourceType := strings.ToLower(req.ResourceType())
	if !h.filter.EligibleResourceType(resourceType) {
		h.countIgnored.Add(1)
		return
	}

	// Content-Type filter via response headers.
	headers := resp.Headers()
	contentType := headers["content-type"]
	if !h.filter.EligibleContentType(contentType) {
		h.countIgnored.Add(1)
		return
	}

	// Build the job — read the body before returning from this callback.
	job := discovery.CaptureJob{
		SessionID:    sessID,
		Method:       req.Method(),
		URL:          rawURL,
		Status:       resp.Status(),
		ContentType:  contentType,
		ResourceType: resourceType,
		HasDateParam: discovery.QueryHasDateParams(RawQueryString(rawURL)),
	}

	// Read body in the callback (Playwright requires this synchronously).
	body, err := resp.Body()
	if err != nil {
		job.BodyError = err.Error()
		h.log.Debug("body read error", "url", NormalizedURL(rawURL), "err", err)
	} else if int64(len(body)) > h.maxBody {
		job.BodyError = "body exceeds max size"
		job.BodySize = int64(len(body))
		h.log.Debug("body too large", "url", NormalizedURL(rawURL), "size", len(body))
	} else {
		// Copy body to avoid holding Playwright's buffer.
		copied := make([]byte, len(body))
		copy(copied, body)

		// Check for auth secrets conservatively.
		if ContainsAuthSecret(copied) {
			h.countIgnored.Add(1)
			h.log.Debug("excluded: auth secret detected", "url", NormalizedURL(rawURL))
			return
		}

		job.Body = copied
		job.BodySize = int64(len(copied))
	}

	h.countEligible.Add(1)

	// Non-blocking enqueue with explicit backpressure.
	select {
	case h.queue <- job:
	default:
		h.countQueueFull.Add(1)
		h.log.Warn("capture queue full, dropping response",
			"url", NormalizedURL(rawURL),
			"queueFull", true)
	}
}

// CountObserved returns total observed responses.
func (h *ResponseHandler) CountObserved() int64 { return h.countObserved.Load() }

// CountEligible returns eligible (enqueued or attempted) responses.
func (h *ResponseHandler) CountEligible() int64 { return h.countEligible.Load() }

// CountIgnored returns ignored response count.
func (h *ResponseHandler) CountIgnored() int64 { return h.countIgnored.Load() }

// CountQueueFull returns queue overflow count.
func (h *ResponseHandler) CountQueueFull() int64 { return h.countQueueFull.Load() }

package capture_test

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/khaliullov/tbank-capture/internal/capture"
	"github.com/khaliullov/tbank-capture/internal/discovery"
	pw "github.com/playwright-community/playwright-go"
)

// mockRequest implements pw.Request for testing.
type mockRequest struct {
	pw.Request
	method  string
	resType string
	url     string
}

func (m *mockRequest) Method() string       { return m.method }
func (m *mockRequest) ResourceType() string { return m.resType }
func (m *mockRequest) URL() string          { return m.url }

// mockResponse implements pw.Response for testing.
type mockResponse struct {
	pw.Response
	url         string
	status      int
	headers     map[string]string
	bodyBytes   []byte
	bodyErr     error
	bodyCalled  atomic.Bool
	requestMock *mockRequest
}

func (m *mockResponse) URL() string                { return m.url }
func (m *mockResponse) Status() int                { return m.status }
func (m *mockResponse) Headers() map[string]string { return m.headers }
func (m *mockResponse) Request() pw.Request        { return m.requestMock }
func (m *mockResponse) Body() ([]byte, error) {
	m.bodyCalled.Store(true)
	return m.bodyBytes, m.bodyErr
}

// blockingResponse wraps mockResponse and triggers a callback when Body() is invoked.
type blockingResponse struct {
	mockResponse
	onBody func()
}

func (b *blockingResponse) Body() ([]byte, error) {
	if b.onBody != nil {
		b.onBody()
	}
	return b.mockResponse.Body()
}

// mockSubmitter records submitted jobs.
type mockSubmitter struct {
	mu      sync.Mutex
	jobs    []discovery.CaptureJob
	accept  bool
	invoked int
}

func (m *mockSubmitter) Submit(job discovery.CaptureJob) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invoked++
	if m.accept {
		m.jobs = append(m.jobs, job)
		return true
	}
	return false
}

func (m *mockSubmitter) Jobs() []discovery.CaptureJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]discovery.CaptureJob, len(m.jobs))
	copy(cp, m.jobs)
	return cp
}

func (m *mockSubmitter) Invoked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invoked
}

func createTestHandler(submitter capture.JobSubmitter, col *discovery.Collector, maxBody int64) *capture.ResponseHandler {
	filter := capture.NewFilter(noopLogger(), maxBody, []string{"tbank.ru"})
	dummyChan := make(chan discovery.CaptureJob, 10)
	h := capture.NewResponseHandler(noopLogger(), filter, dummyChan, func() discovery.SessionID {
		return "test-session"
	}, maxBody)
	h.SetSubmitter(submitter)
	h.SetCollector(col)
	return h
}

// TestResponseHandler_ContentLengthPreCheck verifies that an oversized Content-Length
// causes the handler to reject reading the body before allocation.
func TestResponseHandler_ContentLengthPreCheck(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	maxBody := int64(1024)
	h := createTestHandler(sub, col, maxBody)

	req := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/large"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/large",
		status:      200,
		headers:     map[string]string{"content-type": "application/json", "content-length": "50000"},
		bodyBytes:   make([]byte, 50000),
		requestMock: req,
	}

	h.HandleResponse(resp)

	// Body() MUST NOT have been called!
	if resp.bodyCalled.Load() {
		t.Fatal("resp.Body() was called despite oversized Content-Length header!")
	}

	// Oversized responses must be rejected at handler with ReasonBodyTooLarge
	if len(sub.jobs) != 0 {
		t.Fatalf("expected 0 jobs submitted for oversized response, got %d", len(sub.jobs))
	}
	if h.CountFiltered() != 1 {
		t.Errorf("expected 1 filtered response, got %d", h.CountFiltered())
	}
	diag := col.Diagnostics()
	if diag.Rejections[discovery.ReasonBodyTooLarge] != 1 {
		t.Errorf("expected rejection reason %s = 1, got %d", discovery.ReasonBodyTooLarge, diag.Rejections[discovery.ReasonBodyTooLarge])
	}
}

// TestResponseHandler_PostReadSizeCheck verifies post-read size check when Content-Length
// is missing or inaccurate.
func TestResponseHandler_PostReadSizeCheck(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	maxBody := int64(100)
	h := createTestHandler(sub, col, maxBody)

	oversizedPayload := make([]byte, 500)
	for i := range oversizedPayload {
		oversizedPayload[i] = 'a'
	}

	req := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/chunked"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/chunked",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"}, // no content-length
		bodyBytes:   oversizedPayload,
		requestMock: req,
	}

	h.HandleResponse(resp)

	if !resp.bodyCalled.Load() {
		t.Fatal("expected Body() to be called when Content-Length is missing")
	}

	// Post-read oversized responses must be rejected at handler with ReasonBodyTooLarge
	if len(sub.jobs) != 0 {
		t.Fatalf("expected 0 jobs submitted for oversized response, got %d", len(sub.jobs))
	}
	if h.CountFiltered() != 1 {
		t.Errorf("expected 1 filtered response, got %d", h.CountFiltered())
	}
	diag := col.Diagnostics()
	if diag.Rejections[discovery.ReasonBodyTooLarge] != 1 {
		t.Errorf("expected rejection reason %s = 1, got %d", discovery.ReasonBodyTooLarge, diag.Rejections[discovery.ReasonBodyTooLarge])
	}
}

// TestResponseHandler_Deactivation verifies that after Deactivate(), no more jobs are submitted.
func TestResponseHandler_Deactivation(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)
	h.Deactivate()

	req := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/test"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/test",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"id": 1}`),
		requestMock: req,
	}

	h.HandleResponse(resp)

	if sub.invoked != 0 {
		t.Errorf("job was submitted after deactivation!")
	}
	if h.CountIgnored() != 1 {
		t.Errorf("expected 1 ignored count, got %d", h.CountIgnored())
	}
}

// TestResponseHandler_QueueOverflow verifies metrics when queue rejects submission.
func TestResponseHandler_QueueOverflow(t *testing.T) {
	sub := &mockSubmitter{accept: false} // Queue full simulation
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)

	req := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/test"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/test",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"id": 1}`),
		requestMock: req,
	}

	h.HandleResponse(resp)

	if h.CountQueueFull() != 1 {
		t.Errorf("expected CountQueueFull = 1, got %d", h.CountQueueFull())
	}
	if m := col.Metrics(); m.QueueOverflows != 1 {
		t.Errorf("expected collector QueueOverflows = 1, got %d", m.QueueOverflows)
	}
}

// TestResponseHandler_AuthSecretRejected verifies that responses with invalid JSON
// or unsanitizable secrets are rejected with ReasonCredentialDetected.
func TestResponseHandler_AuthSecretRejected(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)

	req := &mockRequest{method: "POST", resType: "xhr", url: "https://www.tbank.ru/api/v1/test"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/test",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"accessToken": invalid_json_here}`),
		requestMock: req,
	}

	h.HandleResponse(resp)

	if len(sub.jobs) != 0 {
		t.Errorf("unparseable response was submitted to queue!")
	}
	if h.CountFiltered() != 1 {
		t.Errorf("expected filtered count 1, got %d", h.CountFiltered())
	}
	diag := col.Diagnostics()
	if diag.Rejections[discovery.ReasonCredentialDetected] != 1 {
		t.Errorf("expected rejection reason %s = 1, got %d", discovery.ReasonCredentialDetected, diag.Rejections[discovery.ReasonCredentialDetected])
	}
}

// TestResponseHandler_AuthSecretSanitized verifies that responses containing authentication
// credentials alongside useful business fields have sensitive fields stripped,
// are flagged as sanitized, and are successfully enqueued.
func TestResponseHandler_AuthSecretSanitized(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)

	req := &mockRequest{method: "POST", resType: "xhr", url: "https://www.tbank.ru/api/v1/operations"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/operations",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"accessToken": "super-secret-token-123", "accountNumber": "40817810000000001234", "balance": 15000}`),
		requestMock: req,
	}

	h.HandleResponse(resp)

	if len(sub.jobs) != 1 {
		t.Fatalf("expected sanitized job to be submitted to queue, got %d", len(sub.jobs))
	}
	job := sub.jobs[0]
	if !job.Sanitized {
		t.Error("expected job.Sanitized to be true")
	}
	bodyStr := string(job.Body)
	if strings.Contains(bodyStr, "super-secret-token") || strings.Contains(bodyStr, "accessToken") {
		t.Errorf("secret credentials leaked in sanitized job body: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "40817810000000001234") || !strings.Contains(bodyStr, "15000") {
		t.Errorf("business fields missing from sanitized job body: %s", bodyStr)
	}
}

// TestResponseHandler_MetadataOnlyFailureOnBodyError verifies that when resp.Body() fails,
// a metadata-only event is created without URL query params or secrets and enqueued without error.
func TestResponseHandler_MetadataOnlyFailureOnBodyError(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)

	req := &mockRequest{method: "GET", resType: "fetch", url: "https://www.tbank.ru/api/v1/fail?token=secret123&user=john"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/fail?token=secret123&user=john",
		status:      502,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   nil,
		bodyErr:     errors.New("target closed"),
		requestMock: req,
	}

	h.HandleResponse(resp)

	jobs := sub.Jobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 metadata-only job submitted on Body() error, got %d", len(jobs))
	}
	job := jobs[0]
	if job.Body != nil {
		t.Errorf("expected Body == nil on error, got %v", job.Body)
	}
	if job.BodySize != 0 {
		t.Errorf("expected BodySize == 0 on error, got %d", job.BodySize)
	}
	if job.RawBodySize != 0 {
		t.Errorf("expected RawBodySize == 0 on error, got %d", job.RawBodySize)
	}
	if job.BodyError != "target closed" {
		t.Errorf("expected BodyError == 'target closed', got %q", job.BodyError)
	}
	if strings.Contains(job.URL, "secret123") || strings.Contains(job.URL, "john") || strings.Contains(job.URL, "?") {
		t.Errorf("query parameters or credentials leaked in metadata-only URL: %s", job.URL)
	}
	if job.Status != 502 {
		t.Errorf("expected Status == 502, got %d", job.Status)
	}
	if job.Method != "GET" {
		t.Errorf("expected Method == 'GET', got %q", job.Method)
	}
}

// TestResponseHandler_RawBodySizePreserved verifies that raw network response size is
// preserved separately from sanitized body size.
func TestResponseHandler_RawBodySizePreserved(t *testing.T) {
	sub := &mockSubmitter{accept: true}
	col := newTestCollector(t)
	col.StartSession("test-session")

	h := createTestHandler(sub, col, 1024)

	rawBody := []byte(`{"accessToken": "super-secret-token-abcdef1234567890", "id": 12345, "amount": 500}`)
	req := &mockRequest{method: "POST", resType: "xhr", url: "https://www.tbank.ru/api/v1/data"}
	resp := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/data",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   rawBody,
		requestMock: req,
	}

	h.HandleResponse(resp)

	jobs := sub.Jobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job submitted, got %d", len(jobs))
	}
	job := jobs[0]
	if job.RawBodySize != int64(len(rawBody)) {
		t.Errorf("expected RawBodySize == %d, got %d", len(rawBody), job.RawBodySize)
	}
	if job.BodySize != int64(len(job.Body)) {
		t.Errorf("expected BodySize == %d, got %d", len(job.Body), job.BodySize)
	}
	if job.RawBodySize <= job.BodySize {
		t.Errorf("expected RawBodySize (%d) > BodySize (%d) after sanitization", job.RawBodySize, job.BodySize)
	}
}

// TestResponseHandler_WorkerQueueBoundedOverflow verifies that the bounded worker queue
// drops incoming responses and increments overflow metrics without spawning goroutines or blocking.
func TestResponseHandler_WorkerQueueBoundedOverflow(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("test-session")

	filter := capture.NewFilter(noopLogger(), 1024, []string{"tbank.ru"})
	dummyChan := make(chan discovery.CaptureJob, 10)

	// Create handler with 1 worker and 1 queue capacity
	h := capture.NewResponseHandler(noopLogger(), filter, dummyChan, func() discovery.SessionID {
		return "test-session"
	}, 1024, capture.WithWorkerCount(1), capture.WithQueueCapacity(1))

	sub := &mockSubmitter{accept: true}
	h.SetSubmitter(sub)
	h.SetCollector(col)
	defer h.Deactivate()

	workerBlocked := make(chan struct{})
	workerRelease := make(chan struct{})

	blockingReq := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/block"}
	blockingResp := &blockingResponse{
		mockResponse: mockResponse{
			url:         "https://www.tbank.ru/api/v1/block",
			status:      200,
			headers:     map[string]string{"content-type": "application/json"},
			bodyBytes:   []byte(`{"id": 1}`),
			requestMock: blockingReq,
		},
		onBody: func() {
			close(workerBlocked)
			<-workerRelease
		},
	}

	// 1. Enqueue blocking response; worker will pick it up and block in Body()
	h.Enqueue(blockingResp)
	<-workerBlocked

	// 2. Worker is busy. Send 1 response to fill the queue (capacity 1)
	req2 := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/fill"}
	resp2 := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/fill",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"id": 2}`),
		requestMock: req2,
	}
	h.Enqueue(resp2)

	// 3. Queue is now full (1 worker busy, 1 in queue). Send 3rd response; must overflow immediately
	req3 := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/overflow"}
	resp3 := &mockResponse{
		url:         "https://www.tbank.ru/api/v1/overflow",
		status:      200,
		headers:     map[string]string{"content-type": "application/json"},
		bodyBytes:   []byte(`{"id": 3}`),
		requestMock: req3,
	}
	h.Enqueue(resp3)

	if h.CountQueueFull() < 1 {
		t.Errorf("expected CountQueueFull >= 1 on worker queue overflow, got %d", h.CountQueueFull())
	}
	if m := col.Metrics(); m.QueueOverflows < 1 {
		t.Errorf("expected col.Metrics().QueueOverflows >= 1, got %d", m.QueueOverflows)
	}

	// Unblock worker and wait for clean drain
	close(workerRelease)
	h.Wait()
}

// TestResponseHandler_ConcurrentShutdownRace tests that concurrent calls to
// Enqueue, Wait, StopSession, and Deactivate do not cause data races or panics.
func TestResponseHandler_ConcurrentShutdownRace(t *testing.T) {
	col := newTestCollector(t)
	col.StartSession("test-session")

	filter := capture.NewFilter(noopLogger(), 1024, []string{"tbank.ru"})
	dummyChan := make(chan discovery.CaptureJob, 20)
	h := capture.NewResponseHandler(noopLogger(), filter, dummyChan, func() discovery.SessionID {
		return "test-session"
	}, 1024, capture.WithWorkerCount(4), capture.WithQueueCapacity(32))

	sub := &mockSubmitter{accept: true}
	h.SetSubmitter(sub)
	h.SetCollector(col)

	var wg sync.WaitGroup
	// Launch producers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &mockRequest{method: "GET", resType: "xhr", url: "https://www.tbank.ru/api/v1/test"}
			resp := &mockResponse{
				url:         "https://www.tbank.ru/api/v1/test",
				status:      200,
				headers:     map[string]string{"content-type": "application/json"},
				bodyBytes:   []byte(`{"id": 1}`),
				requestMock: req,
			}
			for j := 0; j < 10; j++ {
				h.Enqueue(resp)
				time.Sleep(100 * time.Microsecond)
			}
		}(i)
	}

	// Launch concurrent callers of StopSession and Wait
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				h.StopSession("test-session")
				h.Wait()
				time.Sleep(200 * time.Microsecond)
			}
		}()
	}

	// Launch deactivator
	go func() {
		time.Sleep(2 * time.Millisecond)
		h.Deactivate()
	}()

	wg.Wait()
	h.Deactivate() // Idempotent second deactivation
}

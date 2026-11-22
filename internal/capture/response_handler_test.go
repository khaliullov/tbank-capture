package capture_test

import (
	"strings"
	"sync/atomic"
	"testing"

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

// mockSubmitter records submitted jobs.
type mockSubmitter struct {
	jobs    []discovery.CaptureJob
	accept  bool
	invoked int
}

func (m *mockSubmitter) Submit(job discovery.CaptureJob) bool {
	m.invoked++
	if m.accept {
		m.jobs = append(m.jobs, job)
		return true
	}
	return false
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

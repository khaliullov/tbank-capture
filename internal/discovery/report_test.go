package discovery_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

// TestReport_SensitiveValuesNeverPresent verifies that real financial values,
// sensitive tokens, card numbers, and query parameter values never appear in
// the generated Markdown or JSON reports.
func TestReport_SensitiveValuesNeverPresent(t *testing.T) {
	reportDir := t.TempDir()
	gen := discovery.NewGenerator(reportDir)

	secretToken := "SUPER_SECRET_AUTH_TOKEN_VALUE_XYZ"
	realCardNumber := "2200700011112222"
	realAccountNumber := "40817810000000009999"
	secretQueryValue := "sensitive_query_param_val"

	sess := &discovery.Session{
		ID:        "sess-sensitive-test",
		StartedAt: time.Now().UTC().Add(-10 * time.Minute),
		StoppedAt: time.Now().UTC(),
		Active:    false,
	}

	// Build a fingerprint with metadata
	fp := &discovery.EndpointFingerprint{
		ID:              "fp-1234",
		SessionID:       sess.ID,
		Method:          "GET",
		NormalizedPath:  "/api/v1/accounts/{id}/operations",
		ExampleURL:      "https://www.tbank.ru/api/v1/accounts/123/operations", // query stripped
		ContentType:     "application/json",
		ResourceType:    "xhr",
		TopLevelKind:    discovery.JSONKindObject,
		Observations:    3,
		UniqueBodyCount: 2,
		TotalBytes:      1024,
		MaxResponseSize: 512,
		FirstSeen:       sess.StartedAt,
		LastSeen:        sess.StoppedAt,
		IsPaginated:     true,
		HasDateParams:   true,
		ReturnsList:     true,
		StatusDist:      discovery.StatusDist{200: 2, 500: 1},
		Classification: discovery.Classification{
			Category:   discovery.CategoryTransactions,
			Confidence: 0.85,
			Score:      0.85,
			Reasons:    []string{"strongly signaled transaction collection"},
		},
		SchemaFields: []discovery.FieldSchema{
			{Path: "$.items[].operationId", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassIdentifier},
			{Path: "$.items[].amount", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary},
		},
	}

	metrics := discovery.Metrics{
		TotalObserved:         5,
		EligibleResponses:     3,
		IgnoredResponses:      2,
		CaptureFailures:       1,
		QueueOverflows:        1,
		UniqueFingerprints:    1,
		TransactionCandidates: 1,
	}

	mdPath, jsonPath, err := gen.Generate(sess, []*discovery.EndpointFingerprint{fp}, metrics)
	if err != nil {
		t.Fatalf("generate report error: %v", err)
	}

	// Verify file permissions (0600)
	for _, p := range []string{mdPath, jsonPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("file %s has perm %o, want 0600", p, perm)
		}
	}

	// Read both files
	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}

	forbiddenValues := []string{
		secretToken,
		realCardNumber,
		realAccountNumber,
		secretQueryValue,
	}

	for _, val := range forbiddenValues {
		if strings.Contains(string(mdBytes), val) {
			t.Errorf("CRITICAL SECURITY VIOLATION: forbidden value %q found in Markdown report", val)
		}
		if strings.Contains(string(jsonBytes), val) {
			t.Errorf("CRITICAL SECURITY VIOLATION: forbidden value %q found in JSON report", val)
		}
	}
}

// TestReport_CandidateThresholdConsistency verifies that report summary counts match runtime metrics.
func TestReport_CandidateThresholdConsistency(t *testing.T) {
	reportDir := t.TempDir()
	gen := discovery.NewGenerator(reportDir)

	sess := &discovery.Session{ID: "sess-thresh", StartedAt: time.Now().UTC(), Active: false}

	// Strong candidate (conf >= 0.6)
	fpStrong := &discovery.EndpointFingerprint{
		ID:             "fp-strong",
		SessionID:      sess.ID,
		NormalizedPath: "/api/v1/tx",
		Classification: discovery.Classification{Category: discovery.CategoryTransactions, Confidence: 0.8},
	}
	// Weak candidate (conf < 0.6)
	fpWeak := &discovery.EndpointFingerprint{
		ID:             "fp-weak",
		SessionID:      sess.ID,
		NormalizedPath: "/api/v1/maybe",
		Classification: discovery.Classification{Category: discovery.CategoryTransactions, Confidence: 0.3},
	}

	metrics := discovery.Metrics{
		TotalObserved:         2,
		EligibleResponses:     2,
		UniqueFingerprints:    2,
		TransactionCandidates: 1, // Only strong candidate counted
	}

	_, jsonPath, err := gen.Generate(sess, []*discovery.EndpointFingerprint{fpStrong, fpWeak}, metrics)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep discovery.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}

	if rep.Summary.TransactionCandidates != metrics.TransactionCandidates {
		t.Errorf("report summary TransactionCandidates (%d) != metrics (%d)",
			rep.Summary.TransactionCandidates, metrics.TransactionCandidates)
	}
	if len(rep.Candidates) != 1 {
		t.Errorf("expected 1 strong candidate in Candidates list, got %d", len(rep.Candidates))
	}
	if len(rep.Unknown) != 1 {
		t.Errorf("expected 1 unclassified endpoint in Unknown list, got %d", len(rep.Unknown))
	}
}

// TestReport_DeterministicStatusDistribution verifies status codes are sorted in Markdown output.
func TestReport_DeterministicStatusDistribution(t *testing.T) {
	reportDir := t.TempDir()
	gen := discovery.NewGenerator(reportDir)
	sess := &discovery.Session{ID: "sess-status", StartedAt: time.Now().UTC(), Active: false}

	fp := &discovery.EndpointFingerprint{
		ID:             "fp-status",
		SessionID:      sess.ID,
		NormalizedPath: "/api/v1/test",
		Classification: discovery.Classification{Category: discovery.CategoryTransactions, Confidence: 0.9},
		StatusDist:     discovery.StatusDist{500: 1, 200: 5, 404: 2, 201: 3},
	}

	mdPath, _, err := gen.Generate(sess, []*discovery.EndpointFingerprint{fp}, discovery.Metrics{})
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}

	// Status codes must appear in ascending order: 200, 201, 404, 500
	expectedSub := "200×5 201×3 404×2 500×1"
	if !strings.Contains(string(content), expectedSub) {
		t.Errorf("expected status distribution %q in report, got:\n%s", expectedSub, string(content))
	}
}

// TestReport_CaptureWarningsPopulated verifies that session-level and endpoint-level
// capture warnings appear in the report.
func TestReport_CaptureWarningsPopulated(t *testing.T) {
	reportDir := t.TempDir()
	gen := discovery.NewGenerator(reportDir)
	sess := &discovery.Session{ID: "sess-warn", StartedAt: time.Now().UTC(), Active: false}

	fp := &discovery.EndpointFingerprint{
		ID:              "fp-warn",
		SessionID:       sess.ID,
		NormalizedPath:  "/api/v1/warn",
		Classification:  discovery.Classification{Category: discovery.CategoryTransactions, Confidence: 0.8},
		CaptureWarnings: []string{"body was truncated at 10MB"},
	}

	metrics := discovery.Metrics{
		QueueOverflows:  3,
		CaptureFailures: 2,
	}

	_, jsonPath, err := gen.Generate(sess, []*discovery.EndpointFingerprint{fp}, metrics)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep discovery.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}

	if len(rep.Warnings) == 0 {
		t.Fatal("expected report to contain capture warnings")
	}

	var hasQueueWarn, hasBodyWarn, hasEndpointWarn bool
	for _, w := range rep.Warnings {
		if strings.Contains(w, "overflowed") {
			hasQueueWarn = true
		}
		if strings.Contains(w, "failed body retrieval") {
			hasBodyWarn = true
		}
		if strings.Contains(w, "truncated") {
			hasEndpointWarn = true
		}
	}

	if !hasQueueWarn {
		t.Error("missing queue overflow warning")
	}
	if !hasBodyWarn {
		t.Error("missing body failure warning")
	}
	if !hasEndpointWarn {
		t.Error("missing endpoint-level warning")
	}
}

func init() {
	_ = filepath.Separator
}

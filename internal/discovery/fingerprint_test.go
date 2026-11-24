package discovery_test

import (
	"testing"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

// TestNormalizePath verifies that dynamic segments are replaced and meaningful
// segments are preserved.
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/api/v1/accounts/123456/transactions", "/api/v1/accounts/{id}/transactions"},
		{"/api/v1/accounts/987654/transactions", "/api/v1/accounts/{id}/transactions"},
		{"/api/v1/accounts/550e8400-e29b-41d4-a716-446655440000/transactions", "/api/v1/accounts/{id}/transactions"},
		{"/api/v1/cards", "/api/v1/cards"},
		{"/api/v1/cards/00112233445566778899aabbccddeeff/details", "/api/v1/cards/{id}/details"},
		{"/", "/"},
		{"", "/"},
		{"/api/v2/payments/9876543210/status", "/api/v2/payments/{id}/status"},
		{"/api/v1/accounts/acc_12345678/details", "/api/v1/accounts/{id}/details"},
		{"/api/v1/cards/card-abcdef1234/balance", "/api/v1/cards/{id}/balance"},
		{"/api/v1/operations/op_9876543210/receipt", "/api/v1/operations/{id}/receipt"},
	}
	for _, tc := range cases {
		got := discovery.NormalizePath(tc.input)
		if got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestBuildFingerprintIDStability verifies that the same inputs always produce
// the same fingerprint ID.
func TestBuildFingerprintIDStability(t *testing.T) {
	id1 := discovery.BuildFingerprintID("GET", "/api/v1/accounts/{id}/transactions",
		"application/json", "xhr", discovery.JSONKindObject, "abc123", 200)
	id2 := discovery.BuildFingerprintID("GET", "/api/v1/accounts/{id}/transactions",
		"application/json", "xhr", discovery.JSONKindObject, "abc123", 200)
	if id1 != id2 {
		t.Errorf("fingerprint not stable: %s != %s", id1, id2)
	}
}

// TestBuildFingerprintIDDistinct verifies different structures produce different IDs.
func TestBuildFingerprintIDDistinct(t *testing.T) {
	id1 := discovery.BuildFingerprintID("GET", "/api/v1/accounts",
		"application/json", "xhr", discovery.JSONKindArray, "hash1", 200)
	id2 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", discovery.JSONKindArray, "hash1", 200)
	if id1 == id2 {
		t.Errorf("expected distinct fingerprints but got same: %s", id1)
	}
}

// TestBuildFingerprintIDStatus verifies that different HTTP status codes produce distinct fingerprints.
func TestBuildFingerprintIDStatus(t *testing.T) {
	statuses := []int{200, 400, 401, 403, 404, 500}
	seen := make(map[discovery.FingerprintID]int)
	for _, status := range statuses {
		id := discovery.BuildFingerprintID("GET", "/api/v1/accounts",
			"application/json", "xhr", discovery.JSONKindObject, "hash_same", status)
		if prevStatus, exists := seen[id]; exists {
			t.Fatalf("collision between status %d and %d: fingerprint=%s", prevStatus, status, id)
		}
		seen[id] = status
	}
}

// TestFingerprint_ValueInvariance verifies that identical structures with different
// data values produce identical fingerprints.
func TestFingerprint_ValueInvariance(t *testing.T) {
	cfg := discovery.DefaultAnalyzerConfig()
	body1 := []byte(`{"balance": 1500.50, "currency": "RUB", "account_id": "ACC-12345"}`)
	body2 := []byte(`{"balance": 9999999.00, "currency": "USD", "account_id": "ACC-99999"}`)

	fields1, topKind1, err := discovery.AnalyzeJSON(body1, cfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON body1 error: %v", err)
	}
	fields2, topKind2, err := discovery.AnalyzeJSON(body2, cfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON body2 error: %v", err)
	}

	hash1 := hashFields(fields1)
	hash2 := hashFields(fields2)
	if hash1 != hash2 {
		t.Fatalf("expected identical structure hashes, got %q vs %q", hash1, hash2)
	}

	id1 := discovery.BuildFingerprintID("GET", "/api/v1/accounts/{id}", "application/json", "xhr", topKind1, hash1, 200)
	id2 := discovery.BuildFingerprintID("GET", "/api/v1/accounts/{id}", "application/json", "xhr", topKind2, hash2, 200)
	if id1 != id2 {
		t.Fatalf("expected identical fingerprints for different financial values, got %s vs %s", id1, id2)
	}
}

// TestFingerprint_KeyOrderInvariance verifies that different JSON key ordering
// produces identical structure hashes and fingerprints.
func TestFingerprint_KeyOrderInvariance(t *testing.T) {
	cfg := discovery.DefaultAnalyzerConfig()
	body1 := []byte(`{"a": 1, "b": "hello", "c": true}`)
	body2 := []byte(`{"c": false, "a": 2, "b": "world"}`)

	fields1, topKind1, err := discovery.AnalyzeJSON(body1, cfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON body1 error: %v", err)
	}
	fields2, topKind2, err := discovery.AnalyzeJSON(body2, cfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON body2 error: %v", err)
	}

	hash1 := hashFields(fields1)
	hash2 := hashFields(fields2)
	if hash1 != hash2 {
		t.Fatalf("expected identical structure hashes for reordered keys, got %q vs %q", hash1, hash2)
	}

	id1 := discovery.BuildFingerprintID("POST", "/api/v1/data", "application/json", "fetch", topKind1, hash1, 200)
	id2 := discovery.BuildFingerprintID("POST", "/api/v1/data", "application/json", "fetch", topKind2, hash2, 200)
	if id1 != id2 {
		t.Fatalf("expected identical fingerprints for reordered keys, got %s vs %s", id1, id2)
	}
}

// TestQueryHasDateParams verifies case and delimiter insensitive date param detection.
func TestQueryHasDateParams(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"from=2024-01-01&to=2024-02-01", true},
		{"FROM=2024-01-01&TO=2024-02-01", true},
		{"from_date=2024-01-01&to_date=2024-02-01", true},
		{"START-DATE=2024-01-01", true},
		{"limit=20&offset=0", false},
		{"startDate=2024-01-01", true},
		{"", false},
		{"page=2&dateFrom=2024-01-01", true},
		{"period=monthly", true},
	}
	for _, tc := range cases {
		got := discovery.QueryHasDateParams(tc.query)
		if got != tc.want {
			t.Errorf("QueryHasDateParams(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

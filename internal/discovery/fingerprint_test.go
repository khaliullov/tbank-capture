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
		"application/json", "xhr", discovery.JSONKindObject, "abc123")
	id2 := discovery.BuildFingerprintID("GET", "/api/v1/accounts/{id}/transactions",
		"application/json", "xhr", discovery.JSONKindObject, "abc123")
	if id1 != id2 {
		t.Errorf("fingerprint not stable: %s != %s", id1, id2)
	}
}

// TestBuildFingerprintIDDistinct verifies different structures produce different IDs.
func TestBuildFingerprintIDDistinct(t *testing.T) {
	id1 := discovery.BuildFingerprintID("GET", "/api/v1/accounts",
		"application/json", "xhr", discovery.JSONKindArray, "hash1")
	id2 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", discovery.JSONKindArray, "hash1")
	if id1 == id2 {
		t.Errorf("expected distinct fingerprints but got same: %s", id1)
	}
}

// TestQueryHasDateParams verifies date param detection without storing values.
func TestQueryHasDateParams(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"from=2024-01-01&to=2024-02-01", true},
		{"limit=20&offset=0", false},
		{"startDate=2024-01-01", true},
		{"", false},
		{"page=2&dateFrom=2024-01-01", true},
	}
	for _, tc := range cases {
		got := discovery.QueryHasDateParams(tc.query)
		if got != tc.want {
			t.Errorf("QueryHasDateParams(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

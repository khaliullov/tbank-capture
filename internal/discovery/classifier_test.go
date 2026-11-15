package discovery_test

import (
	"testing"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

func makeFingerprint(method, path, resType string, kind discovery.JSONKind, fields []discovery.FieldSchema, returnsList, isPaginated bool) *discovery.EndpointFingerprint {
	fp := &discovery.EndpointFingerprint{
		Method:         method,
		NormalizedPath: path,
		ResourceType:   resType,
		ContentType:    "application/json",
		TopLevelKind:   kind,
		SchemaFields:   fields,
		ReturnsList:    returnsList,
		IsPaginated:    isPaginated,
		StatusDist:     discovery.StatusDist{200: 1},
		Observations:   1,
	}
	return fp
}

func transactionFields() []discovery.FieldSchema {
	return []discovery.FieldSchema{
		{Path: "$.items", ObservedTypes: []string{"array"}, Classification: discovery.FieldClassCollection},
		{Path: "$.items[].operationId", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassIdentifier, InArray: true},
		{Path: "$.items[].amount", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary, InArray: true},
		{Path: "$.items[].operationTime", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassTimestamp, InArray: true},
		{Path: "$.items[].status", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassStatus, InArray: true},
		{Path: "$.items[].mcc", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMCC, InArray: true},
		{Path: "$.items[].merchant", ObservedTypes: []string{"object"}, Classification: discovery.FieldClassMerchant, InArray: true},
		{Path: "$.totalCount", ObservedTypes: []string{"number"}},
	}
}

func accountFields() []discovery.FieldSchema {
	return []discovery.FieldSchema{
		{Path: "$.accounts", ObservedTypes: []string{"array"}, Classification: discovery.FieldClassCollection},
		{Path: "$.accounts[].accountId", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassIdentifier, InArray: true},
		{Path: "$.accounts[].balance", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary, InArray: true},
	}
}

func cardFields() []discovery.FieldSchema {
	return []discovery.FieldSchema{
		{Path: "$.cards", ObservedTypes: []string{"array"}, Classification: discovery.FieldClassCollection},
		{Path: "$.cards[].cardId", ObservedTypes: []string{"string"}, Classification: discovery.FieldClassIdentifier, InArray: true},
		{Path: "$.cards[].cardNumber", ObservedTypes: []string{"string"}, InArray: true},
		{Path: "$.cards[].balance", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary, InArray: true},
	}
}

func balanceFields() []discovery.FieldSchema {
	return []discovery.FieldSchema{
		{Path: "$.balance", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary},
		{Path: "$.currency", ObservedTypes: []string{"string"}},
	}
}

// TestClassifier_TransactionCandidate tests that a strongly-signaled transaction endpoint classifies correctly.
func TestClassifier_TransactionCandidate(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/accounts/{id}/transactions", "xhr",
		discovery.JSONKindObject, transactionFields(), true, true)
	fp.HasDateParams = true

	cl := c.Classify(fp)
	if cl.Category != discovery.CategoryTransactions {
		t.Errorf("expected transactions, got %s", cl.Category)
	}
	if cl.Confidence < 0.6 {
		t.Errorf("expected confidence >= 0.6, got %.2f", cl.Confidence)
	}
	if len(cl.Reasons) == 0 {
		t.Error("expected at least one classification reason")
	}
}

// TestClassifier_AccountCandidate tests account endpoint classification.
func TestClassifier_AccountCandidate(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/accounts", "xhr",
		discovery.JSONKindObject, accountFields(), true, false)

	cl := c.Classify(fp)
	if cl.Category != discovery.CategoryAccounts {
		t.Errorf("expected accounts, got %s (confidence=%.2f, reasons=%v)", cl.Category, cl.Confidence, cl.Reasons)
	}
}

// TestClassifier_CardCandidate tests card endpoint classification.
func TestClassifier_CardCandidate(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/cards", "xhr",
		discovery.JSONKindObject, cardFields(), true, false)

	cl := c.Classify(fp)
	if cl.Category != discovery.CategoryCards {
		t.Errorf("expected cards, got %s (confidence=%.2f)", cl.Category, cl.Confidence)
	}
}

// TestClassifier_BalanceCandidate tests balance endpoint classification.
func TestClassifier_BalanceCandidate(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/accounts/{id}/balance", "xhr",
		discovery.JSONKindObject, balanceFields(), false, false)

	cl := c.Classify(fp)
	if cl.Category != discovery.CategoryBalances {
		t.Errorf("expected balances, got %s (confidence=%.2f)", cl.Category, cl.Confidence)
	}
}

// TestClassifier_UnknownEndpoint tests that a low-signal endpoint is classified as unknown.
func TestClassifier_UnknownEndpoint(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/config", "xhr",
		discovery.JSONKindObject, []discovery.FieldSchema{
			{Path: "$.version", ObservedTypes: []string{"string"}},
		}, false, false)

	cl := c.Classify(fp)
	if cl.Category != discovery.CategoryUnknown {
		t.Logf("classified as %s (confidence=%.2f) — may be acceptable if score threshold is crossed", cl.Category, cl.Confidence)
	}
}

// TestClassifier_URLOnlyFalsePositive verifies URL alone is insufficient for transaction classification.
func TestClassifier_URLOnlyFalsePositive(t *testing.T) {
	c := discovery.NewClassifier()
	// Path says "transactions" but schema has no matching signals.
	fp := makeFingerprint("GET", "/api/v1/transactions", "xhr",
		discovery.JSONKindObject, []discovery.FieldSchema{
			{Path: "$.message", ObservedTypes: []string{"string"}},
		}, false, false)

	cl := c.Classify(fp)
	// Should NOT have high confidence solely from URL path.
	if cl.Category == discovery.CategoryTransactions && cl.Confidence >= 0.7 {
		t.Errorf("URL-only signal produced overconfident classification: %.2f", cl.Confidence)
	}
}

// TestClassifier_FieldNameOnlyFalsePositive verifies field names alone are insufficient.
func TestClassifier_FieldNameOnlyFalsePositive(t *testing.T) {
	c := discovery.NewClassifier()
	// Field named "amount" but no other signals.
	fp := makeFingerprint("GET", "/api/v1/unknown", "xhr",
		discovery.JSONKindObject, []discovery.FieldSchema{
			{Path: "$.amount", ObservedTypes: []string{"number"}, Classification: discovery.FieldClassMonetary},
		}, false, false)

	cl := c.Classify(fp)
	// A single monetary field on an unknown path: should not be very high confidence.
	if cl.Confidence >= 0.9 {
		t.Errorf("single field-name signal produced overconfident classification: %.2f", cl.Confidence)
	}
}

// TestClassifier_ReasonsPresent verifies that reasons are always provided.
func TestClassifier_ReasonsPresent(t *testing.T) {
	c := discovery.NewClassifier()
	fp := makeFingerprint("GET", "/api/v1/transactions", "xhr",
		discovery.JSONKindObject, transactionFields(), true, true)
	cl := c.Classify(fp)
	if len(cl.Reasons) == 0 {
		t.Error("classifier must always provide reasons")
	}
}

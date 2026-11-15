package discovery

import (
	"strings"
)

// Classifier scores an endpoint fingerprint against known categories.
// It is fully deterministic and uses no external AI/LLM.
type Classifier struct{}

// NewClassifier creates a Classifier.
func NewClassifier() *Classifier { return &Classifier{} }

// Classify assigns a category and confidence score to a fingerprint.
// Multiple independent signals must agree for a high-confidence result.
func (c *Classifier) Classify(fp *EndpointFingerprint) Classification {
	type scored struct {
		cat    Category
		score  float64
		reason string
	}

	var signals []scored
	path := strings.ToLower(fp.NormalizedPath)

	// --- URL path signals (weak: single signal is never sufficient) ---
	if containsAny(path, "transaction", "operation", "payment", "transfer", "history") {
		signals = append(signals, scored{CategoryTransactions, 0.3, "path contains a transaction-related segment"})
	}
	if containsAny(path, "account") {
		signals = append(signals, scored{CategoryAccounts, 0.3, "path contains an account-related segment"})
	}
	if containsAny(path, "card") {
		signals = append(signals, scored{CategoryCards, 0.3, "path contains a card-related segment"})
	}
	if containsAny(path, "balance") {
		signals = append(signals, scored{CategoryBalances, 0.4, "path contains a balance-related segment"})
	}
	if containsAny(path, "statement") {
		signals = append(signals, scored{CategoryStatements, 0.3, "path contains a statement-related segment"})
	}

	// --- JSON structure signals (stronger) ---
	hasList := fp.ReturnsList || fp.TopLevelKind == JSONKindArray
	if hasList {
		signals = append(signals, scored{CategoryTransactions, 0.25, "response contains an array/list of objects"})
	}

	var hasID, hasTimestamp, hasAmount, hasStatus, hasMCC, hasMerchant bool
	var hasCardField, hasAccountField, hasBalanceField bool

	for _, f := range fp.SchemaFields {
		leaf := fieldLeaf(f.Path)
		lower := strings.ToLower(leaf)

		switch f.Classification {
		case FieldClassIdentifier:
			hasID = true
		case FieldClassTimestamp:
			hasTimestamp = true
		case FieldClassMonetary:
			hasAmount = true
			if containsAny(lower, "balance") {
				hasBalanceField = true
			}
		case FieldClassStatus:
			hasStatus = true
		case FieldClassMCC:
			hasMCC = true
		case FieldClassMerchant:
			hasMerchant = true
		}

		if containsAny(lower, "card", "pan") {
			hasCardField = true
		}
		if containsAny(lower, "account", "iban", "bban") {
			hasAccountField = true
		}
	}

	if hasID {
		signals = append(signals, scored{CategoryTransactions, 0.1, "objects contain an identifier-like field"})
	}
	if hasTimestamp {
		signals = append(signals, scored{CategoryTransactions, 0.15, "objects contain a timestamp-like field"})
		signals = append(signals, scored{CategoryStatements, 0.1, "objects contain a timestamp-like field"})
	}
	if hasAmount {
		signals = append(signals, scored{CategoryTransactions, 0.2, "objects contain an amount-like field"})
		signals = append(signals, scored{CategoryBalances, 0.15, "objects contain a monetary field"})
	}
	if hasStatus {
		signals = append(signals, scored{CategoryTransactions, 0.15, "objects contain a status-like field"})
	}
	if hasMCC {
		signals = append(signals, scored{CategoryTransactions, 0.3, "objects contain an MCC-like field"})
	}
	if hasMerchant {
		signals = append(signals, scored{CategoryTransactions, 0.2, "objects contain a merchant-like field"})
	}
	if hasCardField {
		signals = append(signals, scored{CategoryCards, 0.4, "schema contains card-related fields"})
	}
	if hasAccountField {
		signals = append(signals, scored{CategoryAccounts, 0.4, "schema contains account-related fields"})
	}
	if hasBalanceField {
		signals = append(signals, scored{CategoryBalances, 0.3, "schema contains a field named balance"})
	}

	// Pagination is a strong transaction list signal when combined with other evidence.
	if fp.IsPaginated {
		signals = append(signals, scored{CategoryTransactions, 0.2, "response includes pagination indicators"})
		signals = append(signals, scored{CategoryStatements, 0.1, "response is paginated"})
	}
	if fp.HasDateParams {
		signals = append(signals, scored{CategoryTransactions, 0.1, "URL has date-range parameters"})
	}

	// --- Aggregate scores per category ---
	totals := map[Category]float64{}
	reasons := map[Category][]string{}
	for _, s := range signals {
		totals[s.cat] += s.score
		reasons[s.cat] = append(reasons[s.cat], s.reason)
	}

	// Dedup reasons.
	for cat, rs := range reasons {
		reasons[cat] = dedupStrings(rs)
	}

	// Find winner.
	var best Category
	var bestScore float64
	for cat, score := range totals {
		if score > bestScore {
			bestScore = score
			best = cat
		}
	}

	if best == "" || bestScore < 0.3 {
		return Classification{
			Category:   CategoryUnknown,
			Confidence: 0,
			Score:      bestScore,
			Reasons:    []string{"insufficient signals to classify"},
		}
	}

	// Cap confidence at 0.99.
	confidence := bestScore
	if confidence > 0.99 {
		confidence = 0.99
	}

	return Classification{
		Category:   best,
		Confidence: confidence,
		Score:      bestScore,
		Reasons:    reasons[best],
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func fieldLeaf(path string) string {
	idx := strings.LastIndexAny(path, ".[]")
	if idx < 0 {
		return path
	}
	c := path[idx+1:]
	if c == "" {
		return path
	}
	return c
}

func dedupStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

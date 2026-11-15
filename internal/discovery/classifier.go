package discovery

import (
	"sort"
	"strings"
)

// Classifier scores an endpoint fingerprint against known functional categories.
// It is fully deterministic, rule-based, and explainable.
type Classifier struct{}

// NewClassifier creates a Classifier.
func NewClassifier() *Classifier { return &Classifier{} }

// Classify assigns a category, confidence score, and human-readable reasons to a fingerprint.
func (c *Classifier) Classify(fp *EndpointFingerprint) Classification {
	if fp == nil {
		return Classification{
			Category:   CategoryUnknown,
			Confidence: 0,
			Score:      0,
			Reasons:    []string{"no fingerprint data"},
		}
	}

	// Guard against misleading high-confidence classification when response body was not inspected.
	if fp.TopLevelKind == JSONKindUnknown || len(fp.SchemaFields) == 0 {
		return Classification{
			Category:   CategoryUnknown,
			Confidence: 0.1,
			Score:      0.1,
			Reasons:    []string{"response body was not inspected; insufficient evidence for high confidence"},
		}
	}

	normPath := strings.ToLower(fp.NormalizedPath)
	pathSegments := strings.Split(normPath, "/")

	// Extract schema facts once without duplicate counting.
	facts := analyzeSchemaFacts(fp)

	// Evaluate candidate categories
	candidates := []categoryCandidate{
		c.evaluateTransactions(normPath, pathSegments, fp, facts),
		c.evaluateStatements(normPath, pathSegments, fp, facts),
		c.evaluatePayments(normPath, pathSegments, fp, facts),
		c.evaluateTransfers(normPath, pathSegments, fp, facts),
		c.evaluateAccounts(normPath, pathSegments, fp, facts),
		c.evaluateCards(normPath, pathSegments, fp, facts),
		c.evaluateBalances(normPath, pathSegments, fp, facts),
	}

	// Sort candidates deterministically: highest score first, tie-break by priority.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return categoryPriority(candidates[i].category) < categoryPriority(candidates[j].category)
	})

	best := candidates[0]

	// URL-only signal or insufficient independent evidence must return unknown.
	if best.score < 0.35 || best.independentSignals < 2 {
		return Classification{
			Category:   CategoryUnknown,
			Confidence: 0,
			Score:      best.score,
			Reasons:    []string{"insufficient independent signals to classify endpoint"},
		}
	}

	// Ensure confidence is monotonic and strictly capped at 0.95.
	confidence := best.score
	if confidence > 0.95 {
		confidence = 0.95
	}
	// A path signal alone without domain-specific schema fields cannot exceed 0.49.
	if !best.hasDomainSchema && confidence >= 0.50 {
		confidence = 0.49
	}

	return Classification{
		Category:   best.category,
		Confidence: confidence,
		Score:      best.score,
		Reasons:    best.reasons,
	}
}

type categoryCandidate struct {
	category           Category
	score              float64
	independentSignals int
	hasDomainSchema    bool
	reasons            []string
}

func categoryPriority(cat Category) int {
	switch cat {
	case CategoryTransactions:
		return 1
	case CategoryStatements:
		return 2
	case CategoryPayments:
		return 3
	case CategoryTransfers:
		return 4
	case CategoryAccounts:
		return 5
	case CategoryCards:
		return 6
	case CategoryBalances:
		return 7
	default:
		return 99
	}
}

type schemaFacts struct {
	hasID              bool
	hasTimestamp       bool
	hasAmount          bool
	hasStatus          bool
	hasMCC             bool
	hasMerchant        bool
	hasAccountFields   bool
	hasCardFields      bool
	hasBalanceFields   bool
	hasPaymentFields   bool
	hasTransferFields  bool
	hasStatementFields bool
	hasCollection      bool
	inArrayFields      int
}

func analyzeSchemaFacts(fp *EndpointFingerprint) schemaFacts {
	var facts schemaFacts
	if fp.ReturnsList || fp.TopLevelKind == JSONKindArray {
		facts.hasCollection = true
	}

	for _, f := range fp.SchemaFields {
		leaf := strings.ToLower(extractLeafName(f.Path))
		if f.InArray {
			facts.inArrayFields++
		}
		if f.Classification == FieldClassCollection {
			facts.hasCollection = true
		}

		switch f.Classification {
		case FieldClassIdentifier:
			facts.hasID = true
		case FieldClassTimestamp:
			facts.hasTimestamp = true
		case FieldClassMonetary:
			facts.hasAmount = true
		case FieldClassStatus:
			facts.hasStatus = true
		case FieldClassMCC:
			facts.hasMCC = true
		case FieldClassMerchant:
			facts.hasMerchant = true
		}

		// Domain field detection
		if containsAnyLeaf(leaf, "accountid", "accountnumber", "agreementnumber", "accounttype", "iban", "bban") {
			facts.hasAccountFields = true
		}
		if containsAnyLeaf(leaf, "cardid", "cardnumber", "pan", "paymentsystem", "cardstatus", "expirationdate") {
			facts.hasCardFields = true
		}
		if containsAnyLeaf(leaf, "balance", "availablebalance", "currentbalance", "totalbalance") {
			facts.hasBalanceFields = true
		}
		if containsAnyLeaf(leaf, "paymentid", "payee", "billid", "serviceid", "providerid", "receiptid", "commission") {
			facts.hasPaymentFields = true
		}
		if containsAnyLeaf(leaf, "transferid", "sourceaccount", "destinationaccount", "fromcard", "tocard", "recipientphone", "recipientbank", "sbpmemberid") {
			facts.hasTransferFields = true
		}
		if containsAnyLeaf(leaf, "statementid", "periodstart", "periodend", "openingbalance", "closingbalance", "turnover", "totalcredit", "totaldebit") {
			facts.hasStatementFields = true
		}
	}

	return facts
}

func (c *Classifier) evaluateTransactions(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryTransactions}

	// 1. Path evidence (weak on its own)
	if hasPathSegment(segments, "transactions", "transaction", "operations", "operation", "history") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates a transaction history or operations endpoint")
	}

	// 2. Collection of transaction records (identifier + timestamp + monetary amount)
	hasItemTriad := f.hasID && f.hasTimestamp && f.hasAmount && (f.hasCollection || f.inArrayFields >= 3)
	if hasItemTriad {
		cand.score += 0.35
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema defines a collection of records with identifier, timestamp, and monetary amount")
	}

	// 3. Merchant / MCC categorization
	if f.hasMerchant || f.hasMCC {
		cand.score += 0.20
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema includes merchant or MCC categorization fields")
	}

	// 4. Behavioral signals (pagination, date range)
	if fp.IsPaginated {
		cand.score += 0.10
		cand.reasons = append(cand.reasons, "endpoint indicates pagination support")
	}
	if fp.HasDateParams {
		cand.score += 0.10
		cand.reasons = append(cand.reasons, "endpoint uses date-range query parameters")
	}

	return cand
}

func (c *Classifier) evaluateStatements(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryStatements}

	if hasPathSegment(segments, "statement", "statements", "extract", "extracts") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates an account statement or extract endpoint")
	}

	if f.hasStatementFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains statement-specific boundary fields (period or balance totals)")
	}

	if f.hasAmount && f.hasTimestamp {
		cand.score += 0.15
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema contains monetary totals and date information")
	}

	return cand
}

func (c *Classifier) evaluatePayments(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryPayments}

	if hasPathSegment(segments, "payments", "payment", "pay", "bills", "invoices", "templates") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates a payment or billing endpoint")
	}

	if f.hasPaymentFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains payment-specific fields (e.g. payee, billId, or serviceId)")
	}

	if f.hasAmount && f.hasStatus {
		cand.score += 0.15
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema includes payment amount and execution status")
	}

	return cand
}

func (c *Classifier) evaluateTransfers(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryTransfers}

	if hasPathSegment(segments, "transfers", "transfer", "sbp", "c2c", "me2me", "p2p") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates a money transfer or SBP endpoint")
	}

	if f.hasTransferFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains transfer routing fields (source/destination or SBP data)")
	}

	if f.hasAmount && (f.hasStatus || f.hasID) {
		cand.score += 0.15
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema includes transfer amount and status/identifier")
	}

	return cand
}

func (c *Classifier) evaluateAccounts(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryAccounts}

	if hasPathSegment(segments, "accounts", "account") && !hasPathSegment(segments, "balance", "transactions", "operations", "statement") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates an account endpoint")
	}

	if f.hasAccountFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains account identifier or contract fields")
	}

	if f.hasBalanceFields {
		cand.score += 0.15
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema includes account balance information")
	}

	return cand
}

func (c *Classifier) evaluateCards(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryCards}

	if hasPathSegment(segments, "cards", "card") && !hasPathSegment(segments, "transactions", "operations") {
		cand.score += 0.25
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates a card endpoint")
	}

	if f.hasCardFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains card identifier or PAN/payment system fields")
	}

	if f.hasStatus {
		cand.score += 0.10
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema includes card status")
	}

	return cand
}

func (c *Classifier) evaluateBalances(normPath string, segments []string, fp *EndpointFingerprint, f schemaFacts) categoryCandidate {
	cand := categoryCandidate{category: CategoryBalances}

	if hasPathSegment(segments, "balance", "balances") {
		cand.score += 0.30
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "path indicates a balance endpoint")
	}

	if f.hasBalanceFields {
		cand.score += 0.45
		cand.independentSignals++
		cand.hasDomainSchema = true
		cand.reasons = append(cand.reasons, "schema contains dedicated balance fields")
	}

	// Balances are typically not long lists of historical transaction items
	if !f.hasMCC && !f.hasMerchant && f.hasAmount {
		cand.score += 0.10
		cand.independentSignals++
		cand.reasons = append(cand.reasons, "schema is focused on monetary balances without merchant operations")
	}

	return cand
}

func hasPathSegment(segments []string, targets ...string) bool {
	for _, seg := range segments {
		clean := strings.ToLower(strings.Trim(seg, "{}"))
		for _, target := range targets {
			if clean == target {
				return true
			}
		}
	}
	return false
}

func containsAnyLeaf(leaf string, targets ...string) bool {
	for _, target := range targets {
		if leaf == target || strings.Contains(leaf, target) {
			return true
		}
	}
	return false
}

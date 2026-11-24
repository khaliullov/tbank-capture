package discovery

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// AnalyzerConfig controls limits for JSON structural analysis.
type AnalyzerConfig struct {
	MaxDepth      int
	MaxArrayElems int
	MaxFields     int
}

// DefaultAnalyzerConfig returns safe defaults.
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 5000}
}

// AnalyzeJSON parses raw JSON and returns a list of FieldSchema entries
// describing its structure. Values are never returned — only paths, types,
// and heuristic classifications.
func AnalyzeJSON(data []byte, cfg AnalyzerConfig) ([]FieldSchema, JSONKind, error) {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 32
	}
	if cfg.MaxArrayElems <= 0 {
		cfg.MaxArrayElems = 20
	}
	if cfg.MaxFields <= 0 {
		cfg.MaxFields = 5000
	}

	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, JSONKindUnknown, fmt.Errorf("json unmarshal: %w", err)
	}

	a := newAnalyzer(cfg)
	if _, isMap := root.(map[string]interface{}); isMap {
		a.scopeCounts["$"] = 1
	}
	a.walk("$", root, 0, false, "")

	return a.results(), topKind(root), nil
}

func topKind(v interface{}) JSONKind {
	switch v.(type) {
	case map[string]interface{}:
		return JSONKindObject
	case []interface{}:
		return JSONKindArray
	case string:
		return JSONKindString
	case float64:
		return JSONKindNumber
	case bool:
		return JSONKindBool
	case nil:
		return JSONKindNull
	default:
		return JSONKindUnknown
	}
}

type schemaEntry struct {
	path           string
	parentPath     string
	types          map[string]bool
	count          int
	inArray        bool
	nested         bool
	optional       bool
	classification FieldClassification
}

type analyzer struct {
	cfg         AnalyzerConfig
	entries     map[string]*schemaEntry
	scopeCounts map[string]int // tracks total inspected instances of objects/collections by scope path
}

func newAnalyzer(cfg AnalyzerConfig) *analyzer {
	return &analyzer{
		cfg:         cfg,
		entries:     make(map[string]*schemaEntry, 64),
		scopeCounts: make(map[string]int, 32),
	}
}

func (a *analyzer) walk(path string, v interface{}, depth int, inArray bool, parentPath string) {
	if depth > a.cfg.MaxDepth {
		return
	}

	typeName := jsonTypeName(v)

	switch val := v.(type) {
	case map[string]interface{}:
		if path != "$" {
			a.recordField(path, parentPath, typeName, depth > 1, inArray)
			if !strings.HasSuffix(path, "[]") {
				a.scopeCounts[path]++
			}
		}

		// Sort keys for deterministic traversal.
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			childPath := formatPropertyPath(path, k)
			a.walk(childPath, val[k], depth+1, inArray, path)
		}

	case []interface{}:
		if path != "$" {
			a.recordCollection(path, parentPath, depth > 1, inArray)
		}

		limit := len(val)
		if limit > a.cfg.MaxArrayElems {
			limit = a.cfg.MaxArrayElems
		}

		elemPath := path + "[]"
		a.scopeCounts[elemPath] += limit

		for i := 0; i < limit; i++ {
			a.walk(elemPath, val[i], depth+1, true, path)
		}

	default:
		if path != "$" {
			a.recordField(path, parentPath, typeName, depth > 1, inArray)
		}
	}
}

func (a *analyzer) recordField(path, parentPath, typeName string, nested, inArray bool) {
	e, exists := a.entries[path]
	if exists {
		e.count++
		e.types[typeName] = true
		return
	}

	if len(a.entries) >= a.cfg.MaxFields {
		return
	}

	a.entries[path] = &schemaEntry{
		path:           path,
		parentPath:     parentPath,
		types:          map[string]bool{typeName: true},
		count:          1,
		inArray:        inArray,
		nested:         nested,
		classification: classifyField(path, typeName),
	}
}

func (a *analyzer) recordCollection(path, parentPath string, nested, inArray bool) {
	e, exists := a.entries[path]
	if exists {
		e.count++
		e.types["array"] = true
		return
	}

	if len(a.entries) >= a.cfg.MaxFields {
		return
	}

	a.entries[path] = &schemaEntry{
		path:           path,
		parentPath:     parentPath,
		types:          map[string]bool{"array": true},
		count:          1,
		inArray:        inArray,
		nested:         nested,
		classification: FieldClassCollection,
	}
}

// results produces deterministically ordered FieldSchema entries with reliable optional-field analysis.
func (a *analyzer) results() []FieldSchema {
	paths := make([]string, 0, len(a.entries))
	for p := range a.entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	// Phase 1: Determine direct optionality based on parent scope count
	for _, p := range paths {
		e := a.entries[p]
		parentTotal := a.scopeCounts[e.parentPath]
		if parentTotal > 0 && e.count < parentTotal {
			e.optional = true
		}
	}

	// Phase 2: Propagate ancestor optionality
	// If a parent object or array is optional, all fields within it are also optional.
	// Since paths are sorted lexicographically, shorter ancestor paths come before descendant paths.
	for _, p := range paths {
		e := a.entries[p]
		if e.parentPath != "$" && e.parentPath != "" {
			if parentEntry, exists := a.entries[e.parentPath]; exists && parentEntry.optional {
				e.optional = true
			}
			if strings.HasSuffix(e.parentPath, "[]") {
				arrPath := strings.TrimSuffix(e.parentPath, "[]")
				if arrEntry, exists := a.entries[arrPath]; exists && arrEntry.optional {
					e.optional = true
				}
			}
		}
	}

	out := make([]FieldSchema, len(paths))
	for i, p := range paths {
		e := a.entries[p]
		sortedTypes := make([]string, 0, len(e.types))
		for t := range e.types {
			sortedTypes = append(sortedTypes, t)
		}
		sort.Strings(sortedTypes)

		out[i] = FieldSchema{
			Path:           e.path,
			ObservedTypes:  sortedTypes,
			Count:          e.count,
			Optional:       e.optional,
			InArray:        e.inArray,
			Nested:         e.nested,
			Classification: e.classification,
		}
	}
	return out
}

func jsonTypeName(v interface{}) string {
	switch v.(type) {
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// formatPropertyPath cleanly joins parent JSONPath with a child property key.
// Normal alphanumeric keys use dot-notation: $.items.id
// Keys containing dots, brackets, quotes, or special characters use bracket notation:
// $["foo.bar"] or $.items[]["special-key"]
func formatPropertyPath(parent, key string) string {
	if isSimpleIdentifier(key) {
		if parent == "$" {
			return "$." + key
		}
		return parent + "." + key
	}

	escaped := strings.ReplaceAll(key, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return fmt.Sprintf(`%s["%s"]`, parent, escaped)
}

func isSimpleIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// classifyField uses field name heuristics to infer semantic role without inspecting values.
func classifyField(path, typeName string) FieldClassification {
	leaf := extractLeafName(path)
	lower := strings.ToLower(leaf)

	if isIdentifierField(lower, typeName) {
		return FieldClassIdentifier
	}
	if isTimestampField(lower) {
		return FieldClassTimestamp
	}
	if isCurrencyField(lower, typeName) {
		return FieldClassCurrency
	}
	if isMonetaryField(lower, typeName) {
		return FieldClassMonetary
	}
	if isStatusField(lower, typeName) {
		return FieldClassStatus
	}
	if isMCCField(lower, typeName) {
		return FieldClassMCC
	}
	if isMerchantField(lower) {
		return FieldClassMerchant
	}
	return FieldClassNone
}

func fieldLeaf(path string) string {
	return extractLeafName(path)
}

func extractLeafName(path string) string {
	// Handle bracket notation: e.g. $["user.name"] or $.items[]["key"]
	if strings.HasSuffix(path, `"]`) {
		idx := strings.LastIndex(path, `["`)
		if idx >= 0 {
			inner := path[idx+2 : len(path)-2]
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			return inner
		}
	}

	// Normal dot or array notation
	idx := strings.LastIndexAny(path, ".[]")
	if idx < 0 {
		return path
	}
	candidate := path[idx+1:]
	if candidate != "" {
		return candidate
	}
	return path
}

func isIdentifierField(lower, typeName string) bool {
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "period") {
		return false
	}
	idWords := []string{
		"id", "uuid", "guid", "key", "ref", "code", "number", "pan",
		"accountid", "cardid", "operationid", "transactionid", "paymentid",
		"transferid", "agreementid", "contractid", "statementid", "docid",
		"clientid", "customerid", "accountnumber", "cardnumber", "agreementnumber",
	}
	for _, w := range idWords {
		if lower == w || strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "uuid") ||
			strings.HasSuffix(lower, "number") || strings.HasSuffix(lower, "ref") {
			return true
		}
	}
	return false
}

func isTimestampField(lower string) bool {
	if strings.Contains(lower, "timeout") {
		return false
	}
	tsWords := []string{
		"time", "date", "timestamp", "created", "updated", "posted",
		"executed", "processed", "authorized", "booking", "operationtime",
		"operationdate", "transactiondate", "periodstart", "periodend",
	}
	for _, w := range tsWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func isCurrencyField(lower, typeName string) bool {
	if typeName != "string" && typeName != "number" {
		return false
	}
	return lower == "currency" || lower == "currencycode" || lower == "cur" || lower == "iso" ||
		strings.HasSuffix(lower, "currency") || strings.HasSuffix(lower, "currencycode")
}

func isMonetaryField(lower, typeName string) bool {
	if typeName != "number" && typeName != "string" {
		return false
	}
	monWords := []string{
		"amount", "sum", "total", "balance", "credit", "debit", "fee",
		"charge", "price", "commission", "turnover", "availablebalance",
		"currentbalance", "totalbalance", "cashback", "bonus", "holdamount",
	}
	for _, w := range monWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func isStatusField(lower, typeName string) bool {
	if typeName != "string" && typeName != "number" {
		return false
	}
	return lower == "status" || lower == "state" || strings.HasSuffix(lower, "status") || strings.HasSuffix(lower, "state")
}

func isMCCField(lower, typeName string) bool {
	if typeName != "number" && typeName != "string" {
		return false
	}
	return lower == "mcc" || lower == "mcccode" || strings.HasSuffix(lower, "mcc")
}

func isMerchantField(lower string) bool {
	merchantWords := []string{
		"merchant", "shop", "store", "vendor", "payee", "counterparty", "brand", "merchantname",
	}
	for _, w := range merchantWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// SanitizeJSON produces a structurally equivalent JSON document with all values
// replaced by type placeholders. No real financial or personal data is kept.
func SanitizeJSON(data []byte, maxDepth, maxArrayElems int) ([]byte, error) {
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("json unmarshal for sanitize: %w", err)
	}
	sanitized := sanitizeValue(root, 0, maxDepth, maxArrayElems)
	out, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("json marshal sanitized: %w", err)
	}
	return out, nil
}

func sanitizeValue(v interface{}, depth, maxDepth, maxArrayElems int) interface{} {
	if depth > maxDepth {
		return "<truncated>"
	}
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, child := range val {
			out[k] = sanitizeValue(child, depth+1, maxDepth, maxArrayElems)
		}
		return out
	case []interface{}:
		limit := len(val)
		if limit > maxArrayElems {
			limit = maxArrayElems
		}
		out := make([]interface{}, limit)
		for i := 0; i < limit; i++ {
			out[i] = sanitizeValue(val[i], depth+1, maxDepth, maxArrayElems)
		}
		return out
	case string:
		return "<string>"
	case float64:
		return 0
	case bool:
		return false
	case nil:
		return nil
	default:
		return nil
	}
}

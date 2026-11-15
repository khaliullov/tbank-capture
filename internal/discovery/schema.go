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
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, JSONKindUnknown, fmt.Errorf("json unmarshal: %w", err)
	}

	a := &analyzer{cfg: cfg}
	a.walk("$", root, 0, false)
	return a.fields, topKind(root), nil
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

type analyzer struct {
	cfg    AnalyzerConfig
	fields []FieldSchema
	total  int
}

// fieldMap tracks per-path aggregation during a single analysis pass.
// (For cross-observation aggregation see collector.go.)
type schemaEntry struct {
	types   map[string]bool
	count   int
	inArray bool
	nested  bool
}

func (a *analyzer) walk(path string, v interface{}, depth int, inArray bool) {
	if depth > a.cfg.MaxDepth {
		return
	}
	if a.total >= a.cfg.MaxFields {
		return
	}

	typeName := jsonTypeName(v)

	switch val := v.(type) {
	case map[string]interface{}:
		// Record the object node itself only if it is a child (not root "$").
		if path != "$" {
			a.emit(path, typeName, depth > 1, inArray)
		}
		// Sort keys for deterministic output.
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := path + "." + k
			a.walk(childPath, val[k], depth+1, false)
		}

	case []interface{}:
		if path != "$" {
			a.emitCollection(path, depth > 1, inArray)
		}
		limit := len(val)
		if limit > a.cfg.MaxArrayElems {
			limit = a.cfg.MaxArrayElems
		}
		for i := 0; i < limit; i++ {
			a.walk(path+"[]", val[i], depth+1, true)
		}

	default:
		if path != "$" {
			a.emit(path, typeName, depth > 1, inArray)
		}
	}
}

func (a *analyzer) emit(path, typeName string, nested, inArray bool) {
	if a.total >= a.cfg.MaxFields {
		return
	}
	// Find or create entry for this path.
	for i := range a.fields {
		if a.fields[i].Path == path {
			a.fields[i].Count++
			// Merge type.
			found := false
			for _, t := range a.fields[i].ObservedTypes {
				if t == typeName {
					found = true
					break
				}
			}
			if !found {
				a.fields[i].ObservedTypes = append(a.fields[i].ObservedTypes, typeName)
			}
			return
		}
	}
	a.total++
	f := FieldSchema{
		Path:          path,
		ObservedTypes: []string{typeName},
		Count:         1,
		InArray:       inArray,
		Nested:        nested,
	}
	f.Classification = classifyField(path, typeName)
	a.fields = append(a.fields, f)
}

func (a *analyzer) emitCollection(path string, nested, inArray bool) {
	for i := range a.fields {
		if a.fields[i].Path == path {
			a.fields[i].Count++
			return
		}
	}
	a.total++
	a.fields = append(a.fields, FieldSchema{
		Path:           path,
		ObservedTypes:  []string{"array"},
		Count:          1,
		InArray:        inArray,
		Nested:         nested,
		Classification: FieldClassCollection,
	})
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

// classifyField uses field name heuristics to infer semantic role.
// It never inspects field values.
func classifyField(path, typeName string) FieldClassification {
	// Extract the leaf key name from the path.
	leaf := path
	if idx := strings.LastIndexAny(path, ".[]"); idx >= 0 {
		candidate := path[idx+1:]
		if candidate != "" {
			leaf = candidate
		}
	}
	lower := strings.ToLower(leaf)

	// Identifier heuristics.
	if isIdentifierField(lower, typeName) {
		return FieldClassIdentifier
	}
	// Timestamp heuristics.
	if isTimestampField(lower) {
		return FieldClassTimestamp
	}
	// Monetary heuristics.
	if isMonetaryField(lower, typeName) {
		return FieldClassMonetary
	}
	// Status heuristics.
	if isStatusField(lower, typeName) {
		return FieldClassStatus
	}
	// MCC heuristics.
	if isMCCField(lower, typeName) {
		return FieldClassMCC
	}
	// Merchant heuristics.
	if isMerchantField(lower) {
		return FieldClassMerchant
	}
	return FieldClassNone
}

func isIdentifierField(lower, typeName string) bool {
	idWords := []string{"id", "uuid", "guid", "key", "ref", "token", "code", "number"}
	for _, w := range idWords {
		if lower == w || strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "uuid") {
			return true
		}
		_ = w
	}
	// Pure "id" or ends with "Id"
	return lower == "id" || strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "uuid")
}

func isTimestampField(lower string) bool {
	tsWords := []string{"time", "date", "at", "timestamp", "created", "updated", "posted", "executed", "processed", "authorized", "booking"}
	for _, w := range tsWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func isMonetaryField(lower, typeName string) bool {
	if typeName != "number" && typeName != "string" {
		return false
	}
	monWords := []string{"amount", "sum", "total", "balance", "credit", "debit", "fee", "charge", "price", "value"}
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
	return lower == "status" || lower == "state" || lower == "type" && strings.Contains(lower, "status")
}

func isMCCField(lower, typeName string) bool {
	if typeName != "number" && typeName != "string" {
		return false
	}
	return lower == "mcc" || lower == "mcccode" || strings.Contains(lower, "mcc")
}

func isMerchantField(lower string) bool {
	merchantWords := []string{"merchant", "shop", "store", "vendor", "payee", "recipient", "counterparty", "partner"}
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

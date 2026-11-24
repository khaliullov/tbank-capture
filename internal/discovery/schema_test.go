package discovery_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

func cfg() discovery.AnalyzerConfig {
	return discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 5000}
}

// TestAnalyzeJSON_NestedObject verifies nested object analysis.
func TestAnalyzeJSON_NestedObject(t *testing.T) {
	data := []byte(`{"id":"abc","merchant":{"name":"Shop","mcc":5411}}`)
	fields, kind, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != discovery.JSONKindObject {
		t.Errorf("expected object kind, got %s", kind)
	}
	assertFieldPresent(t, fields, "$.id")
	assertFieldPresent(t, fields, "$.merchant.name")
	assertFieldPresent(t, fields, "$.merchant.mcc")
}

// TestAnalyzeJSON_ArrayOfObjects verifies array analysis with object elements.
func TestAnalyzeJSON_ArrayOfObjects(t *testing.T) {
	data := []byte(`[{"id":1,"amount":100},{"id":2,"amount":200}]`)
	fields, kind, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != discovery.JSONKindArray {
		t.Errorf("expected array kind, got %s", kind)
	}
	assertFieldPresent(t, fields, "$[].id")
	assertFieldPresent(t, fields, "$[].amount")
}

// TestAnalyzeJSON_EmptyArray verifies empty arrays don't crash.
func TestAnalyzeJSON_EmptyArray(t *testing.T) {
	data := []byte(`[]`)
	_, kind, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != discovery.JSONKindArray {
		t.Errorf("expected array, got %s", kind)
	}
}

// TestAnalyzeJSON_MixedArray verifies mixed-type arrays.
func TestAnalyzeJSON_MixedArray(t *testing.T) {
	data := []byte(`{"items":[1,"two",true,null,{"x":1}]}`)
	fields, _, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFieldPresent(t, fields, "$.items")
}

// TestAnalyzeJSON_NullValues verifies null fields are recorded.
func TestAnalyzeJSON_NullValues(t *testing.T) {
	data := []byte(`{"name":null,"value":42}`)
	fields, _, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFieldPresent(t, fields, "$.name")
	assertTypePresent(t, fields, "$.name", "null")
}

// TestAnalyzeJSON_InvalidJSON verifies graceful handling of invalid JSON.
func TestAnalyzeJSON_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid json}`)
	_, _, err := discovery.AnalyzeJSON(data, cfg())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestAnalyzeJSON_MaxDepth verifies that analysis stops at max depth.
func TestAnalyzeJSON_MaxDepth(t *testing.T) {
	// Build deeply nested JSON: {"a":{"a":{"a":...}}}
	var root interface{} = map[string]interface{}{"leaf": true}
	for i := 0; i < 40; i++ {
		root = map[string]interface{}{"a": root}
	}
	data, _ := json.Marshal(root)

	limitedCfg := discovery.AnalyzerConfig{MaxDepth: 5, MaxArrayElems: 20, MaxFields: 5000}
	fields, _, err := discovery.AnalyzeJSON(data, limitedCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range fields {
		depth := strings.Count(f.Path, ".")
		if depth > limitedCfg.MaxDepth+1 {
			t.Errorf("field %s exceeds max depth %d", f.Path, limitedCfg.MaxDepth)
		}
	}
}

// TestAnalyzeJSON_MaxFieldCount verifies truncation at field count limit.
func TestAnalyzeJSON_MaxFieldCount(t *testing.T) {
	obj := make(map[string]interface{})
	for i := 0; i < 200; i++ {
		key := fmt.Sprintf("field_%d", i)
		obj[key] = i
	}
	data, _ := json.Marshal(obj)
	limitedCfg := discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 20, MaxFields: 10}
	fields, _, err := discovery.AnalyzeJSON(data, limitedCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fields) > limitedCfg.MaxFields {
		t.Errorf("expected at most %d fields, got %d", limitedCfg.MaxFields, len(fields))
	}
}

// TestAnalyzeJSON_LargeArray verifies array sampling limit.
func TestAnalyzeJSON_LargeArray(t *testing.T) {
	arr := make([]interface{}, 100)
	for i := range arr {
		arr[i] = map[string]interface{}{"id": i}
	}
	data, _ := json.Marshal(arr)
	limitedCfg := discovery.AnalyzerConfig{MaxDepth: 32, MaxArrayElems: 5, MaxFields: 5000}
	_, _, err := discovery.AnalyzeJSON(data, limitedCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSanitizeJSON verifies that all values are replaced with placeholders.
func TestSanitizeJSON(t *testing.T) {
	input := []byte(`{"name":"Alice","amount":9999.99,"active":true,"ref":null,"items":[{"id":"secret123"}]}`)
	out, err := discovery.SanitizeJSON(input, 32, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("sanitized output is not valid JSON: %v", err)
	}
	if result["name"] != "<string>" {
		t.Errorf("expected <string> for name, got %v", result["name"])
	}
	if result["amount"] != float64(0) {
		t.Errorf("expected 0 for amount, got %v", result["amount"])
	}
	if result["active"] != false {
		t.Errorf("expected false for active, got %v", result["active"])
	}
	if _, ok := result["ref"]; !ok {
		t.Error("ref key should be present")
	}
}

// TestSameStructureSameHash verifies that identical structures produce the same fingerprint.
func TestSameStructureSameHash(t *testing.T) {
	body1 := []byte(`{"id":"111","amount":100,"status":"ok"}`)
	body2 := []byte(`{"id":"999","amount":9999999,"status":"pending"}`)

	fields1, kind1, _ := discovery.AnalyzeJSON(body1, cfg())
	fields2, kind2, _ := discovery.AnalyzeJSON(body2, cfg())

	if kind1 != kind2 {
		t.Fatalf("kinds differ: %s != %s", kind1, kind2)
	}

	fp1 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind1, hashFields(fields1), 200)
	fp2 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind2, hashFields(fields2), 200)

	if fp1 != fp2 {
		t.Errorf("same structure produced different fingerprints:\n  %s\n  %s", fp1, fp2)
	}
}

// TestDifferentStructureDifferentHash verifies different JSON structures produce different fingerprints.
func TestDifferentStructureDifferentHash(t *testing.T) {
	body1 := []byte(`{"id":"111","amount":100}`)
	body2 := []byte(`{"id":"111","amount":100,"extraField":"surprise"}`)

	fields1, kind1, _ := discovery.AnalyzeJSON(body1, cfg())
	fields2, kind2, _ := discovery.AnalyzeJSON(body2, cfg())

	fp1 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind1, hashFields(fields1), 200)
	fp2 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind2, hashFields(fields2), 200)

	if fp1 == fp2 {
		t.Error("different structures produced the same fingerprint")
	}
}

// TestKeyOrderIndependence verifies that object key order doesn't affect fingerprint.
func TestKeyOrderIndependence(t *testing.T) {
	body1 := []byte(`{"amount":100,"id":"111","status":"ok"}`)
	body2 := []byte(`{"id":"111","status":"ok","amount":100}`)

	fields1, kind1, _ := discovery.AnalyzeJSON(body1, cfg())
	fields2, kind2, _ := discovery.AnalyzeJSON(body2, cfg())

	fp1 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind1, hashFields(fields1), 200)
	fp2 := discovery.BuildFingerprintID("GET", "/api/v1/transactions",
		"application/json", "xhr", kind2, hashFields(fields2), 200)

	if fp1 != fp2 {
		t.Errorf("key order changed fingerprint: %s != %s", fp1, fp2)
	}
}

// TestAnalyzeJSON_UnusualPropertyNames verifies that keys containing dots, brackets, quotes are handled properly.
func TestAnalyzeJSON_UnusualPropertyNames(t *testing.T) {
	data := []byte(`{
		"user.name": "Alice",
		"foo[bar]": 123,
		"quote\"key": true,
		"normal_key": "ok"
	}`)

	fields, _, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFieldPresent(t, fields, `$["user.name"]`)
	assertFieldPresent(t, fields, `$["foo[bar]"]`)
	assertFieldPresent(t, fields, `$["quote\"key"]`)
	assertFieldPresent(t, fields, `$.normal_key`)
}

// TestAnalyzeJSON_PathologicalNesting verifies that very deep nesting is bounded by MaxDepth.
func TestAnalyzeJSON_PathologicalNesting(t *testing.T) {
	var current interface{} = "leaf"
	for i := 0; i < 200; i++ {
		current = map[string]interface{}{"level": current}
	}
	data, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	limited := discovery.AnalyzerConfig{MaxDepth: 10, MaxArrayElems: 5, MaxFields: 1000}
	fields, _, err := discovery.AnalyzeJSON(data, limited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fields) > limited.MaxDepth+2 {
		t.Errorf("expected at most %d fields, got %d", limited.MaxDepth+2, len(fields))
	}
}

// TestAnalyzeJSON_MixedArrayTypes verifies multiple types inside an array.
func TestAnalyzeJSON_MixedArrayTypes(t *testing.T) {
	data := []byte(`{"values": [1, "two", true, null, {"id": 123}]}`)
	fields, _, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFieldPresent(t, fields, "$.values")
	assertFieldPresent(t, fields, "$.values[]")
	assertTypePresent(t, fields, "$.values[]", "number")
	assertTypePresent(t, fields, "$.values[]", "string")
	assertTypePresent(t, fields, "$.values[]", "bool")
	assertTypePresent(t, fields, "$.values[]", "null")
	assertTypePresent(t, fields, "$.values[]", "object")
	assertFieldPresent(t, fields, "$.values[].id")
}

// TestAnalyzeJSON_LargeObjectPerformance verifies that analyzing an object with 2000 fields is fast.
func TestAnalyzeJSON_LargeObjectPerformance(t *testing.T) {
	obj := make(map[string]interface{}, 2000)
	for i := 0; i < 2000; i++ {
		obj[fmt.Sprintf("key_%04d", i)] = i
	}
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	fields, _, err := discovery.AnalyzeJSON(data, cfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fields) != 2000 {
		t.Errorf("expected 2000 fields, got %d", len(fields))
	}
}

// --- helpers ---

func assertFieldPresent(t *testing.T, fields []discovery.FieldSchema, path string) {
	t.Helper()
	for _, f := range fields {
		if f.Path == path {
			return
		}
	}
	t.Errorf("expected field %q in schema", path)
}

func assertTypePresent(t *testing.T, fields []discovery.FieldSchema, path, typeName string) {
	t.Helper()
	for _, f := range fields {
		if f.Path == path {
			for _, ot := range f.ObservedTypes {
				if ot == typeName {
					return
				}
			}
			t.Errorf("field %q: expected type %q, got %v", path, typeName, f.ObservedTypes)
			return
		}
	}
	t.Errorf("field %q not found", path)
}

// hashFields replicates the internal structureHashFromFields logic for test use.
func hashFields(fields []discovery.FieldSchema) string {
	type entry struct {
		path  string
		types string
	}
	entries := make([]entry, len(fields))
	for i, f := range fields {
		ts := make([]string, len(f.ObservedTypes))
		copy(ts, f.ObservedTypes)
		sort.Strings(ts)
		entries[i] = entry{path: f.Path, types: strings.Join(ts, ",")}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.path)
		sb.WriteByte(':')
		sb.WriteString(e.types)
		sb.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:8])
}

func assertFieldRequired(t *testing.T, fields []discovery.FieldSchema, path string) {
	t.Helper()
	for _, f := range fields {
		if f.Path == path {
			if f.Optional {
				t.Errorf("field %q was marked optional, expected required", path)
			}
			return
		}
	}
	t.Errorf("field %q not found in schema", path)
}

func assertFieldOptional(t *testing.T, fields []discovery.FieldSchema, path string) {
	t.Helper()
	for _, f := range fields {
		if f.Path == path {
			if !f.Optional {
				t.Errorf("field %q was marked required, expected optional", path)
			}
			return
		}
	}
	t.Errorf("field %q not found in schema", path)
}

func TestAnalyzeJSON_OptionalFieldsComprehensive(t *testing.T) {
	// 1. Required and optional fields in array of objects
	data1 := []byte(`{
		"status": "ok",
		"items": [
			{"id": "1", "name": "Item 1", "description": "desc 1"},
			{"id": "2", "name": "Item 2"}
		]
	}`)
	fields1, _, err := discovery.AnalyzeJSON(data1, cfg())
	if err != nil {
		t.Fatalf("AnalyzeJSON data1: %v", err)
	}
	assertFieldRequired(t, fields1, "$.status")
	assertFieldRequired(t, fields1, "$.items")
	assertFieldRequired(t, fields1, "$.items[].id")
	assertFieldRequired(t, fields1, "$.items[].name")
	assertFieldOptional(t, fields1, "$.items[].description") // missing in item 2

	// 2. Nested optional fields
	data2 := []byte(`{
		"items": [
			{"id": 1, "card": {"pan": "*1234", "exp": "12/28"}},
			{"id": 2, "card": {"pan": "*5678"}},
			{"id": 3}
		]
	}`)
	fields2, _, err := discovery.AnalyzeJSON(data2, cfg())
	if err != nil {
		t.Fatalf("AnalyzeJSON data2: %v", err)
	}
	assertFieldRequired(t, fields2, "$.items[].id")
	assertFieldOptional(t, fields2, "$.items[].card")     // missing in item 3
	assertFieldOptional(t, fields2, "$.items[].card.pan") // missing in item 3
	assertFieldOptional(t, fields2, "$.items[].card.exp") // missing in item 2 & 3

	// 3. Different array objects
	data3 := []byte(`{
		"records": [
			{"type": "A", "valA": 10},
			{"type": "B", "valB": "twenty"}
		]
	}`)
	fields3, _, err := discovery.AnalyzeJSON(data3, cfg())
	if err != nil {
		t.Fatalf("AnalyzeJSON data3: %v", err)
	}
	assertFieldRequired(t, fields3, "$.records[].type")
	assertFieldOptional(t, fields3, "$.records[].valA")
	assertFieldOptional(t, fields3, "$.records[].valB")

	// 4. Empty arrays
	data4 := []byte(`{"results": []}`)
	fields4, _, err := discovery.AnalyzeJSON(data4, cfg())
	if err != nil {
		t.Fatalf("AnalyzeJSON data4: %v", err)
	}
	assertFieldRequired(t, fields4, "$.results")

	// 5. Truncated array inspection
	customCfg := discovery.AnalyzerConfig{MaxDepth: 10, MaxArrayElems: 2, MaxFields: 100}
	data5 := []byte(`{
		"list": [
			{"id": 1, "common": "x"},
			{"id": 2, "common": "y"},
			{"id": 3}
		]
	}`)
	fields5, _, err := discovery.AnalyzeJSON(data5, customCfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON data5: %v", err)
	}
	// Since MaxArrayElems is 2, only first 2 items are inspected. Both have "common".
	assertFieldRequired(t, fields5, "$.list[].id")
	assertFieldRequired(t, fields5, "$.list[].common")

	// But if one of the first 2 items omits "note":
	data6 := []byte(`{
		"list": [
			{"id": 1, "note": "x"},
			{"id": 2},
			{"id": 3, "note": "z"}
		]
	}`)
	fields6, _, err := discovery.AnalyzeJSON(data6, customCfg)
	if err != nil {
		t.Fatalf("AnalyzeJSON data6: %v", err)
	}
	assertFieldRequired(t, fields6, "$.list[].id")
	assertFieldOptional(t, fields6, "$.list[].note")
}

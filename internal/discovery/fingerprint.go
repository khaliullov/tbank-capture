package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// reNumeric matches purely numeric path segments.
	reNumeric = regexp.MustCompile(`^\d+$`)
	// reUUID matches standard UUIDs.
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// reHexToken matches hex identifiers (e.g. 16+ hex characters, MongoDB ObjectIds, hashes).
	reHexToken = regexp.MustCompile(`^[0-9a-fA-F]{16,64}$`)
	// rePrefixedID matches common prefixed entity IDs: acc_12345, card-abcdef, op_12345678.
	rePrefixedID = regexp.MustCompile(`^(?:acc|account|card|op|operation|tx|transaction|usr|user|req|id|msg)[-_][0-9a-zA-Z]{6,}$`)
)

// NormalizePath replaces dynamic path segments (numeric IDs, UUIDs, hex tokens, prefixed IDs)
// with the placeholder {id}. Static semantic paths (e.g., /accounts, /transactions) are preserved.
func NormalizePath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	parts := strings.Split(rawPath, "/")
	out := make([]string, len(parts))
	for i, p := range parts {
		if p == "" {
			out[i] = p
			continue
		}
		if isDynamicSegment(p) {
			out[i] = "{id}"
		} else {
			out[i] = p
		}
	}
	return strings.Join(out, "/")
}

func isDynamicSegment(s string) bool {
	if reNumeric.MatchString(s) {
		return true
	}
	if reUUID.MatchString(s) {
		return true
	}
	if reHexToken.MatchString(s) {
		return true
	}
	if rePrefixedID.MatchString(s) {
		return true
	}
	return false
}

// BuildFingerprintID creates a stable opaque ID from the components that define
// an endpoint family, including HTTP status code for fingerprint completeness.
// It is intentionally independent of response values and query parameters.
func BuildFingerprintID(method, normalizedPath, contentType, resourceType string, topLevelKind JSONKind, structureHash string, status int) FingerprintID {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d",
		strings.ToUpper(strings.TrimSpace(method)),
		strings.TrimSpace(normalizedPath),
		strings.ToLower(strings.TrimSpace(contentType)),
		strings.ToLower(strings.TrimSpace(resourceType)),
		string(topLevelKind),
		structureHash,
		status,
	)
	sum := sha256.Sum256([]byte(raw))
	return FingerprintID(hex.EncodeToString(sum[:8]))
}

// structureHashFromFields produces a stable hash of a JSON structural signature.
// The signature is built from sorted field names and their sorted types — never values.
func structureHashFromFields(fields []FieldSchema) string {
	if len(fields) == 0 {
		return "no_fields"
	}

	type entry struct {
		path  string
		types string
	}
	entries := make([]entry, len(fields))
	for i, f := range fields {
		sorted := make([]string, len(f.ObservedTypes))
		copy(sorted, f.ObservedTypes)
		sort.Strings(sorted)
		entries[i] = entry{path: f.Path, types: strings.Join(sorted, ",")}
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

// dateParamNames are normalized query param names that suggest date-range filtering.
var dateParamNames = map[string]bool{
	"from":          true,
	"to":            true,
	"start":         true,
	"end":           true,
	"startdate":     true,
	"enddate":       true,
	"datefrom":      true,
	"dateto":        true,
	"begindate":     true,
	"finishdate":    true,
	"period":        true,
	"starttime":     true,
	"endtime":       true,
	"fromdate":      true,
	"todate":        true,
	"date":          true,
	"operationdate": true,
}

// QueryHasDateParams returns true if the raw query string contains date-related parameters.
// Parameter names are normalized case-insensitively and delimiter-insensitively.
// Parameter values are never inspected or retained.
func QueryHasDateParams(rawQuery string) bool {
	if rawQuery == "" {
		return false
	}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) >= 1 {
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			normalized := strings.ReplaceAll(strings.ReplaceAll(k, "_", ""), "-", "")
			if dateParamNames[normalized] {
				return true
			}
		}
	}
	return false
}

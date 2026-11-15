package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// reID matches path segments that look like identifiers (numbers, UUIDs).
var reID = regexp.MustCompile(`^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24,32})$`)

// reHexToken matches long hex-like tokens that are clearly opaque identifiers.
var reHexToken = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

// NormalizePath replaces dynamic path segments (numeric IDs, UUIDs, hex tokens)
// with the placeholder {id}. Meaningful words are preserved.
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
		if reID.MatchString(p) || reHexToken.MatchString(p) {
			out[i] = "{id}"
		} else {
			out[i] = p
		}
	}
	return strings.Join(out, "/")
}

// BuildFingerprintID creates a stable opaque ID from the components that define
// an endpoint family. It is intentionally independent of response values.
func BuildFingerprintID(method, normalizedPath, contentType, resourceType string, topLevelKind JSONKind, structureHash string) FingerprintID {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		strings.ToUpper(method),
		normalizedPath,
		contentType,
		resourceType,
		string(topLevelKind),
		structureHash,
	)
	sum := sha256.Sum256([]byte(raw))
	return FingerprintID(hex.EncodeToString(sum[:8]))
}

// structureHash produces a stable hash of a JSON structural signature.
// The signature is built from sorted field names and their types — never values.
func structureHashFromFields(fields []FieldSchema) string {
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

// dateParamNames are query param names that suggest date-range filtering.
var dateParamNames = map[string]bool{
	"from": true, "to": true, "start": true, "end": true,
	"startDate": true, "endDate": true, "dateFrom": true, "dateTo": true,
	"beginDate": true, "finishDate": true, "period": true,
	"startTime": true, "endTime": true,
}

// QueryHasDateParams returns true if the raw query string contains date-related parameters
// without exposing the values.
func QueryHasDateParams(rawQuery string) bool {
	if rawQuery == "" {
		return false
	}
	for _, part := range strings.Split(rawQuery, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) >= 1 && dateParamNames[kv[0]] {
			return true
		}
	}
	return false
}

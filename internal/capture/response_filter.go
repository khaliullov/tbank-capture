// Package capture implements network response observation, filtering, and raw storage.
package capture

import (
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
)

// Filter decides whether a network response is eligible for capture.
type Filter struct {
	log            *slog.Logger
	maxBodySize    int64
	allowedDomains []string
}

// NewFilter creates a Filter.
// allowedDomains: list of domains (e.g. "tbank.ru") to accept.
func NewFilter(log *slog.Logger, maxBodySize int64, allowedDomains []string) *Filter {
	return &Filter{log: log, maxBodySize: maxBodySize, allowedDomains: allowedDomains}
}

// EligibleURL returns true if the URL belongs to an allowed domain.
func (f *Filter) EligibleURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, domain := range f.allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// EligibleResourceType returns true for XHR and Fetch resource types.
func (f *Filter) EligibleResourceType(rt string) bool {
	switch strings.ToLower(strings.TrimSpace(rt)) {
	case "xhr", "fetch":
		return true
	}
	return false
}

// EligibleContentType returns true for JSON content types.
func (f *Filter) EligibleContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

// EligibleBodySize returns true if the content length is within limits.
// -1 means unknown size (accepted for post-read check).
func (f *Filter) EligibleBodySize(size int64) bool {
	if size < 0 {
		return true
	}
	return size <= f.maxBodySize
}

// authPathKeywords lists URL path segments or prefixes indicating auth, login, or session management.
var authPathKeywords = []string{
	"/authorize",
	"/login",
	"/logout",
	"/token",
	"/session",
	"/auth",
	"/sign",
	"/oauth",
	"/oidc",
	"/sso",
	"/passport",
	"/security",
}

// EligiblePath returns true if the URL path is not an authentication, session, or token endpoint.
func (f *Filter) EligiblePath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, kw := range authPathKeywords {
		if strings.HasPrefix(path, kw) || strings.Contains(path, kw+"/") || strings.HasSuffix(path, kw) {
			return false
		}
	}
	return true
}

// sensitiveNormalizedExact matches normalized field names that indicate authentication secrets.
var sensitiveNormalizedExact = map[string]bool{
	"accesstoken":      true,
	"refreshtoken":     true,
	"idtoken":          true,
	"authtoken":        true,
	"authorization":    true,
	"bearer":           true,
	"password":         true,
	"passwd":           true,
	"pwd":              true,
	"userpassword":     true,
	"clientsecret":     true,
	"sessiontoken":     true,
	"csrftoken":        true,
	"xsrftoken":        true,
	"xcsrftoken":       true,
	"xxsrftoken":       true,
	"privatekey":       true,
	"secret":           true,
	"secretkey":        true,
	"sharedsecret":     true,
	"apikey":           true,
	"token":            true,
	"jwt":              true,
	"otp":              true,
	"onetimepassword":  true,
	"smscode":          true,
	"confirmationcode": true,
	"verificationcode": true,
	"pincode":          true,
	"pin":              true,
	"cvv":              true,
	"cvc":              true,
	"cvv2":             true,
	"cvc2":             true,
}

// normalizeFieldName removes separators and lowercases a key name.
// Examples:
// - "access_token" -> "accesstoken"
// - "accessToken"  -> "accesstoken"
// - "CSRF-Token"   -> "csrftoken"
// - "one_time_password" -> "onetimepassword"
func normalizeFieldName(key string) string {
	var sb strings.Builder
	sb.Grow(len(key))
	for _, r := range strings.ToLower(key) {
		if r != '_' && r != '-' && r != '.' && r != ' ' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// isSensitiveField tests if a normalized field name matches sensitive authentication or secret patterns.
func isSensitiveField(norm string) bool {
	if norm == "" {
		return false
	}
	if sensitiveNormalizedExact[norm] {
		return true
	}
	// Check suffix/prefix patterns while avoiding false positives on pagination or normal fields.
	if strings.HasSuffix(norm, "token") && !strings.Contains(norm, "page") && !strings.Contains(norm, "cursor") {
		return true
	}
	if strings.HasSuffix(norm, "secret") {
		return true
	}
	if strings.HasSuffix(norm, "password") {
		return true
	}
	if strings.HasSuffix(norm, "privatekey") {
		return true
	}
	if strings.HasSuffix(norm, "otp") {
		return true
	}
	if strings.Contains(norm, "onetimepassword") {
		return true
	}
	if strings.Contains(norm, "csrftoken") || strings.Contains(norm, "xsrftoken") {
		return true
	}
	return false
}

// ContainsAuthSecret performs a conservative recursive JSON inspection that detects
// sensitive authentication and credential field names independently of capitalization
// and common naming conventions (camelCase, snake_case, kebab-case).
//
// Limitations:
//   - The detector inspects JSON keys and known credential value patterns; it cannot
//     infer whether an opaque string in an arbitrary unmodeled property name is a secret.
//   - Fails closed: if the body cannot be parsed as valid JSON, it returns true to avoid
//     ingesting uninspected data.
//   - Callers must never log rejected bodies or extract secret values.
func ContainsAuthSecret(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		// Fail closed when JSON cannot be safely parsed and inspected.
		return true
	}

	return inspectJSONNode(root, 0)
}

func inspectJSONNode(node interface{}, depth int) bool {
	if depth > 64 {
		// Fail closed on pathological nesting.
		return true
	}

	switch val := node.(type) {
	case map[string]interface{}:
		for k, v := range val {
			norm := normalizeFieldName(k)
			if isSensitiveField(norm) {
				return true
			}
			if inspectJSONNode(v, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, elem := range val {
			if inspectJSONNode(elem, depth+1) {
				return true
			}
		}
	case string:
		// Check for embedded PEM private keys or bearer tokens in string values.
		if strings.HasPrefix(val, "-----BEGIN") && strings.Contains(val, "PRIVATE KEY") {
			return true
		}
		lower := strings.ToLower(val)
		if strings.HasPrefix(lower, "bearer eyj") && len(val) > 20 {
			return true
		}
	}
	return false
}

// NormalizedURL returns the scheme + host + path only, discarding query, userinfo, and fragment.
func NormalizedURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// RawQueryString returns only the query string of the URL, for date-param detection.
func RawQueryString(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.RawQuery
}

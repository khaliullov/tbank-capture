// Package capture implements network response observation, filtering, and raw storage.
package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"strings"

	"github.com/khaliullov/tbank-capture/internal/discovery"
)

// Filter decides whether a network response is eligible for capture.
type Filter struct {
	log            *slog.Logger
	maxBodySize    int64
	allowedDomains []string
}

// NewFilter creates a Filter.
// allowedDomains: list of domains (e.g. "tbank.ru", "tinkoff.ru") to accept.
func NewFilter(log *slog.Logger, maxBodySize int64, allowedDomains []string) *Filter {
	normalized := make([]string, 0, len(allowedDomains))
	for _, d := range allowedDomains {
		norm := strings.ToLower(strings.TrimSpace(d))
		norm = strings.TrimSuffix(norm, ".")
		if norm != "" {
			normalized = append(normalized, norm)
		}
	}
	return &Filter{log: log, maxBodySize: maxBodySize, allowedDomains: normalized}
}

// ExtractHostname parses a URL and returns its normalized lowercase hostname without port or trailing dot.
func ExtractHostname(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("malformed url: %w", err)
	}
	h := strings.ToLower(strings.TrimSpace(u.Hostname()))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", errors.New("empty hostname")
	}
	return h, nil
}

// EligibleURL returns true if the URL belongs to an allowed domain or its subdomains.
// It prevents lookalike domains (e.g. evil-tbank.ru, tbank.ru.attacker.com).
func (f *Filter) EligibleURL(rawURL string) bool {
	host, err := ExtractHostname(rawURL)
	if err != nil {
		return false
	}
	return f.IsAllowedHost(host)
}

// IsAllowedHost checks whether a normalized hostname matches any configured allowed domain or subdomain.
func (f *Filter) IsAllowedHost(host string) bool {
	if host == "" {
		return false
	}
	for _, domain := range f.allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// AllowedDomains returns a copy of the allowed domains list.
func (f *Filter) AllowedDomains() []string {
	cp := make([]string, len(f.allowedDomains))
	copy(cp, f.allowedDomains)
	return cp
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
	ct = strings.ToLower(strings.TrimSpace(ct))
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

// CheckEligiblePath evaluates whether a URL path should be excluded as an authentication or credential endpoint.
// It returns true if eligible (not excluded), or false with ReasonExcludedAuthPath.
func (f *Filter) CheckEligiblePath(rawURL string) (bool, discovery.RejectionReason) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, discovery.ReasonMalformedURL
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	host = strings.TrimSuffix(host, ".")
	// Exclude dedicated authentication and identity domains
	if host == "id.tbank.ru" || host == "passport.tbank.ru" || host == "auth.tbank.ru" || host == "sso.tbank.ru" ||
		host == "id.tinkoff.ru" || host == "passport.tinkoff.ru" || host == "auth.tinkoff.ru" || host == "sso.tinkoff.ru" ||
		strings.HasPrefix(host, "id.") || strings.HasPrefix(host, "passport.") || strings.HasPrefix(host, "sso.") {
		return false, discovery.ReasonExcludedAuthPath
	}

	clean := path.Clean("/" + u.Path)
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return true, ""
	}

	for i, part := range parts {
		seg := strings.ToLower(strings.TrimSpace(part))
		// Standalone auth actions and credential paths
		switch seg {
		case "login", "signin", "sign-in", "logout", "signout", "sign-out", "saml", "sso",
			"webauthn", "2fa", "mfa", "preidentity", "identity", "passkey",
			"pin", "pincode", "otp", "challenge", "captcha",
			"session_status", "session-status", "sessionstatus":
			return false, discovery.ReasonExcludedAuthPath
		case "oauth", "oidc", "passport":
			// If subsequent segment is token, authorize, login, auth, sms, otp, code, callback, step
			if i+1 < len(parts) {
				next := strings.ToLower(strings.TrimSpace(parts[i+1]))
				switch next {
				case "token", "authorize", "login", "auth", "sms", "otp", "code", "callback", "step", "user-info":
					return false, discovery.ReasonExcludedAuthPath
				}
			}
			// Standalone /oauth or /passport or /oidc
			if i == len(parts)-1 {
				return false, discovery.ReasonExcludedAuthPath
			}
		case "auth":
			// Any /auth segment represents an authentication workflow endpoint.
			// (Plural "authorizations" for card holds is separate and preserved).
			return false, discovery.ReasonExcludedAuthPath
		case "session":
			// /session alone is often session creation/login check
			// BUT /session/accounts, /session/user, /session/products, /session/cards, etc. are business endpoints!
			if i == len(parts)-1 {
				return false, discovery.ReasonExcludedAuthPath
			}
			next := strings.ToLower(strings.TrimSpace(parts[i+1]))
			switch next {
			case "login", "logout", "authenticate", "auth", "confirm", "create", "start",
				"check_auth", "validate", "status", "check", "state", "init", "ping":
				return false, discovery.ReasonExcludedAuthPath
			}
		case "authorize":
			// Single authorize segment (e.g. OAuth authorize)
			// Note: "authorizations" (plural) is NOT matched here!
			return false, discovery.ReasonExcludedAuthPath
		case "token":
			// If segment is "token" at the end (e.g. /api/token, /v1/token)
			if i == len(parts)-1 {
				return false, discovery.ReasonExcludedAuthPath
			}
		}
	}

	return true, ""
}

// EligiblePath returns true if the URL path is not an authentication, session, or token endpoint.
func (f *Filter) EligiblePath(rawURL string) bool {
	ok, _ := f.CheckEligiblePath(rawURL)
	return ok
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
	// Check suffix/prefix patterns while avoiding false positives on business/pagination fields.
	if strings.HasSuffix(norm, "token") {
		if strings.Contains(norm, "page") || strings.Contains(norm, "cursor") ||
			strings.Contains(norm, "scroll") || strings.Contains(norm, "sync") ||
			strings.Contains(norm, "delta") || strings.Contains(norm, "operation") ||
			strings.Contains(norm, "transaction") || strings.Contains(norm, "payment") ||
			strings.Contains(norm, "order") {
			return false
		}
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

// SanitizeCredentials recursively inspects a JSON body, removes authentication and credential
// fields and their values, and preserves all other schema and business data for analysis and storage.
// It returns the sanitized body, whether any credential was removed, the names of sanitized fields,
// and any parsing/nesting error.
// Fails closed if the input is not valid JSON or nesting exceeds limits.
func SanitizeCredentials(body []byte) (sanitizedBody []byte, wasSanitized bool, sanitizedFields []string, err error) {
	if len(body) == 0 {
		return body, false, nil, nil
	}

	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, false, nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	fieldSet := make(map[string]bool)
	cleanedRoot, wasSanitized, err := sanitizeNode(root, 0, fieldSet)
	if err != nil {
		return nil, false, nil, err
	}

	fields := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fields = append(fields, f)
	}

	if wasSanitized {
		out, err := json.Marshal(cleanedRoot)
		if err != nil {
			return nil, false, nil, fmt.Errorf("json marshal sanitized body failed: %w", err)
		}
		return out, true, fields, nil
	}

	return body, false, nil, nil
}

func sanitizeNode(node interface{}, depth int, fieldSet map[string]bool) (interface{}, bool, error) {
	if depth > 64 {
		return nil, false, errors.New("maximum nesting depth exceeded (pathological nesting)")
	}

	var anySanitized bool
	switch val := node.(type) {
	case map[string]interface{}:
		cleanedMap := make(map[string]interface{}, len(val))
		for k, v := range val {
			norm := normalizeFieldName(k)
			if isSensitiveField(norm) {
				fieldSet[k] = true
				anySanitized = true
				// Exclude credential field and value entirely
				continue
			}
			childCleaned, childSanitized, err := sanitizeNode(v, depth+1, fieldSet)
			if err != nil {
				return nil, false, err
			}
			if childSanitized {
				anySanitized = true
			}
			cleanedMap[k] = childCleaned
		}
		return cleanedMap, anySanitized, nil

	case []interface{}:
		cleanedArr := make([]interface{}, len(val))
		for i, elem := range val {
			childCleaned, childSanitized, err := sanitizeNode(elem, depth+1, fieldSet)
			if err != nil {
				return nil, false, err
			}
			if childSanitized {
				anySanitized = true
			}
			cleanedArr[i] = childCleaned
		}
		return cleanedArr, anySanitized, nil

	case string:
		// Check for embedded PEM private keys or bearer JWTs in string values
		if strings.HasPrefix(val, "-----BEGIN") && strings.Contains(val, "PRIVATE KEY") {
			fieldSet["[embedded_private_key]"] = true
			return "<redacted_secret>", true, nil
		}
		lower := strings.ToLower(val)
		if strings.HasPrefix(lower, "bearer eyj") && len(val) > 20 {
			fieldSet["[bearer_jwt]"] = true
			return "<redacted_secret>", true, nil
		}
		return val, false, nil

	default:
		return val, false, nil
	}
}

// ContainsAuthSecret performs a conservative recursive JSON inspection that detects
// sensitive authentication and credential field names.
// Fails closed on invalid JSON.
func ContainsAuthSecret(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	_, wasSanitized, _, err := SanitizeCredentials(body)
	if err != nil {
		return true
	}
	return wasSanitized
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

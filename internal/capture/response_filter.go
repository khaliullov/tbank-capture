// Package capture implements network response observation, filtering, and raw storage.
package capture

import (
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
	switch strings.ToLower(rt) {
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
// -1 means unknown size (accepted).
func (f *Filter) EligibleBodySize(size int64) bool {
	if size < 0 {
		return true // unknown — will check after reading
	}
	return size <= f.maxBodySize
}

// authPathPrefixes lists URL path prefixes that are excluded because they are
// likely to be authentication, session-establishment, or token endpoints.
var authPathPrefixes = []string{
	"/api/common/v1/authorize",
	"/api/common/v1/login",
	"/api/common/v1/logout",
	"/api/common/v1/token",
	"/api/common/v1/session",
	"/api/common/v1/auth",
	"/sign",
	"/oauth",
	"/oidc",
	"/sso",
}

// EligiblePath returns true if the URL path is not an auth/session endpoint.
func (f *Filter) EligiblePath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, prefix := range authPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

// authHeaderKeywords are content keywords indicating an authentication response.
var authHeaderKeywords = []string{
	"access_token", "refresh_token", "id_token", "password", "otp", "secret",
}

// ContainsAuthSecret performs a conservative check for auth-related fields in a JSON body.
// Only checks for obvious top-level key patterns; does not parse deeply.
// Returns true if the body likely contains authentication secrets.
func ContainsAuthSecret(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, kw := range authHeaderKeywords {
		// Look for key: "access_token" or "accessToken" etc.
		if strings.Contains(lower, `"`+kw+`"`) {
			return true
		}
	}
	return false
}

// NormalizedURL returns the scheme + host + path only, discarding query and fragment.
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

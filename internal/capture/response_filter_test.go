package capture_test

import (
	"strings"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/capture"
)

func TestContainsAuthSecret_Cases(t *testing.T) {
	cases := []struct {
		name string
		json string
		want bool
	}{
		// Sensitive fields in snake_case, camelCase, kebab-case
		{"access_token snake", `{"access_token":"xyz"}`, true},
		{"accessToken camel", `{"accessToken":"xyz"}`, true},
		{"access-token kebab", `{"access-token":"xyz"}`, true},
		{"refresh_token snake", `{"refresh_token":"xyz"}`, true},
		{"refreshToken camel", `{"refreshToken":"xyz"}`, true},
		{"id_token snake", `{"id_token":"xyz"}`, true},
		{"idToken camel", `{"idToken":"xyz"}`, true},
		{"authorization camel", `{"authorization":"Bearer xyz"}`, true},
		{"bearer token", `{"bearer":"xyz"}`, true},
		{"password", `{"password":"secret"}`, true},
		{"user_password", `{"user_password":"secret"}`, true},
		{"userPassword", `{"userPassword":"secret"}`, true},
		{"otp snake", `{"otp":"123456"}`, true},
		{"one_time_password", `{"one_time_password":"123456"}`, true},
		{"oneTimePassword", `{"oneTimePassword":"123456"}`, true},
		{"client_secret", `{"client_secret":"sec"}`, true},
		{"clientSecret", `{"clientSecret":"sec"}`, true},
		{"session_token", `{"session_token":"st"}`, true},
		{"sessionToken", `{"sessionToken":"st"}`, true},
		{"csrf_token", `{"csrf_token":"csrf"}`, true},
		{"csrfToken", `{"csrfToken":"csrf"}`, true},
		{"CSRF-Token kebab uppercase", `{"CSRF-Token":"csrf"}`, true},
		{"xsrf_token", `{"xsrf_token":"xsrf"}`, true},
		{"private_key", `{"private_key":"key"}`, true},
		{"privateKey", `{"privateKey":"key"}`, true},
		{"api_key", `{"api_key":"key"}`, true},
		{"cvv", `{"cvv":"123"}`, true},

		// Nested in objects
		{"nested in object", `{"data":{"auth":{"accessToken":"abc"}}}`, true},
		{"nested secret in array", `{"items":[{"id":1},{"id":2,"password":"p"}]}`, true},
		{"nested in array of objects", `[{"sessionToken":"xyz"}]`, true},

		// Value level checks
		{"pem private key in value", `{"key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`, true},

		// Fail-closed on invalid JSON
		{"invalid json", `{not valid json}`, true},
		{"truncated json", `{"key": `, true},

		// Empty body (safe)
		{"empty body", ``, false},

		// Ordinary financial JSON (MUST NOT trigger false positive)
		{
			"financial transaction item",
			`{
				"operationId": "op_987654",
				"amount": 1250.50,
				"currency": "RUB",
				"operationTime": "2024-03-15T12:30:00Z",
				"status": "SUCCESS",
				"description": "Supermarket purchase",
				"mcc": 5411,
				"merchant": {
					"name": "Supermarket OOO",
					"inn": "7701234567"
				},
				"accountNumber": "40817810000000001234",
				"cardNumber": "4276********1234"
			}`,
			false,
		},
		{
			"account list",
			`{
				"accounts": [
					{"id": "acc-1", "balance": 50000.0, "currency": "RUB", "type": "debit"},
					{"id": "acc-2", "balance": 120.5, "currency": "USD", "type": "savings"}
				],
				"totalBalance": 62000.0
			}`,
			false,
		},
		{
			"card list with pagination",
			`{
				"cards": [
					{"cardId": "c1", "status": "active", "paymentSystem": "MIR"}
				],
				"page": 1,
				"pageSize": 20,
				"totalCount": 1
			}`,
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capture.ContainsAuthSecret([]byte(tc.json))
			if got != tc.want {
				t.Errorf("ContainsAuthSecret() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterAuthPathsExtended(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})
	authURLs := []string{
		"https://www.tbank.ru/api/common/v1/authorize",
		"https://www.tbank.ru/api/common/v1/login",
		"https://www.tbank.ru/api/common/v1/logout",
		"https://www.tbank.ru/api/common/v1/token",
		"https://www.tbank.ru/api/common/v1/session",
		"https://www.tbank.ru/oauth/token",
		"https://www.tbank.ru/sso/callback",
		"https://www.tbank.ru/passport/login",
	}
	for _, u := range authURLs {
		if f.EligiblePath(u) {
			t.Errorf("expected %s to be filtered out as auth path", u)
		}
	}

	safeURLs := []string{
		"https://www.tbank.ru/api/v1/accounts",
		"https://www.tbank.ru/api/v1/accounts/123/operations",
		"https://www.tbank.ru/api/v1/cards",
		"https://www.tbank.ru/api/v1/payments/providers",
		"https://www.tbank.ru/api/v1/transfers/sbp",
	}
	for _, u := range safeURLs {
		if !f.EligiblePath(u) {
			t.Errorf("expected %s to be eligible path", u)
		}
	}
}

func TestSanitizeCredentials(t *testing.T) {
	t.Run("strips sensitive fields and preserves business fields", func(t *testing.T) {
		input := []byte(`{
			"accountNumber": "40817810000000001234",
			"balance": 15000.50,
			"accessToken": "secret-access-token-12345",
			"refreshToken": "secret-refresh-token-67890",
			"csrfToken": "csrf-secret-999",
			"pageToken": "next-page-cursor-token",
			"operationToken": "op-token-xyz",
			"nested": {
				"password": "my-secret-password",
				"status": "active"
			},
			"items": [
				{"id": 1, "otp": "123456", "name": "Item 1"},
				{"id": 2, "name": "Item 2"}
			]
		}`)

		sanitized, wasSanitized, fields, err := capture.SanitizeCredentials(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !wasSanitized {
			t.Fatal("expected wasSanitized to be true")
		}

		s := string(sanitized)
		// Sensitive values and keys must NOT exist in output
		for _, secret := range []string{
			"secret-access-token", "secret-refresh-token", "csrf-secret", "my-secret-password", "123456",
			`"accessToken"`, `"refreshToken"`, `"csrfToken"`, `"password"`, `"otp"`,
		} {
			if strings.Contains(s, secret) {
				t.Errorf("sanitized json should not contain %q, got: %s", secret, s)
			}
		}

		// Useful business fields MUST be preserved
		for _, business := range []string{
			"accountNumber", "40817810000000001234", "15000.5",
			"pageToken", "next-page-cursor-token",
			"operationToken", "op-token-xyz",
			"status", "active",
			"Item 1", "Item 2",
		} {
			if !strings.Contains(s, business) {
				t.Errorf("sanitized json must preserve business field %q, got: %s", business, s)
			}
		}

		if len(fields) == 0 {
			t.Error("expected non-empty sanitized fields list")
		}
	})

	t.Run("clean payload returns wasSanitized false", func(t *testing.T) {
		input := []byte(`{"accounts":[{"id":"acc-1","balance":100.0}],"nextPageToken":"p2"}`)
		sanitized, wasSanitized, fields, err := capture.SanitizeCredentials(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wasSanitized {
			t.Error("clean payload should not be flagged as sanitized")
		}
		if len(fields) > 0 {
			t.Errorf("clean payload should have no sanitized fields, got %v", fields)
		}
		if string(sanitized) != string(input) {
			t.Errorf("clean payload should be returned unchanged")
		}
	})

	t.Run("fails closed on invalid json", func(t *testing.T) {
		input := []byte(`{invalid-json`)
		_, _, _, err := capture.SanitizeCredentials(input)
		if err == nil {
			t.Fatal("expected error on invalid JSON")
		}
	})
}

func TestFilter_DomainMatching(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru", "tinkoff.ru"})

	cases := []struct {
		url   string
		valid bool
	}{
		// Exact allowed domain
		{"https://tbank.ru/api/v1", true},
		{"https://tinkoff.ru/api/v1", true},

		// Subdomains
		{"https://api.tbank.ru/api/v1", true},
		{"https://www.tbank.ru/accounts", true},
		{"https://api.tinkoff.ru/v1", true},
		{"https://sub.api.tbank.ru/data", true},

		// Case-insensitivity & trailing dot & port
		{"HTTPS://API.TBANK.RU/test", true},
		{"https://api.tbank.ru./test", true},
		{"https://api.tbank.ru:443/test", true},
		{"https://api.tbank.ru:8443/test", true},

		// Lookalikes & Disallowed domains (MUST FAIL)
		{"https://not-tbank.ru/api", false},
		{"https://faketbank.ru/api", false},
		{"https://tbank.ru.evil.com/api", false},
		{"https://tinkoff.ru.attacker.org/api", false},
		{"https://google.com/search", false},
		{"https://yandex.ru/api", false},

		// Malformed URLs
		{"not-a-url", false},
		{"://bad", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got := f.EligibleURL(tc.url)
			if got != tc.valid {
				t.Errorf("EligibleURL(%q) = %v, want %v", tc.url, got, tc.valid)
			}
		})
	}
}

func TestFilter_CheckEligiblePath_Detailed(t *testing.T) {
	f := capture.NewFilter(noopLogger(), 1024*1024, []string{"tbank.ru"})

	cases := []struct {
		url      string
		eligible bool
	}{
		// Auth endpoints: MUST be excluded
		{"https://tbank.ru/login", false},
		{"https://tbank.ru/signin", false},
		{"https://tbank.ru/sign-in", false},
		{"https://tbank.ru/logout", false},
		{"https://tbank.ru/signout", false},
		{"https://tbank.ru/oauth/token", false},
		{"https://tbank.ru/oauth/authorize", false},
		{"https://tbank.ru/api/v1/auth/login", false},
		{"https://tbank.ru/api/v1/auth/token", false},
		{"https://tbank.ru/api/v1/auth/otp", false},
		{"https://tbank.ru/api/v1/auth/sms", false},
		{"https://tbank.ru/api/v1/session/login", false},
		{"https://tbank.ru/api/v1/session/logout", false},
		{"https://tbank.ru/passport/login", false},
		{"https://tbank.ru/sso/callback", false},
		{"https://tbank.ru/2fa/verify", false},
		{"https://id.tbank.ru/auth/step", false},
		{"https://id.tbank.ru/auth/.well-known/openid-configuration", false},
		{"https://id.tbank.ru/preidentity/api/v1/user-info", false},
		{"https://passport.tbank.ru/auth/pin", false},
		{"https://tbank.ru/auth/step", false},
		{"https://tbank.ru/auth/pin", false},
		{"https://tbank.ru/auth/challenge", false},
		{"https://tbank.ru/api/common/v1/session/check_auth", false},
		{"https://tbank.ru/api/common/v3/navigation/auth/validate", false},

		// Business endpoints: MUST BE PRESERVED
		{"https://tbank.ru/api/v1/accounts", true},
		{"https://tbank.ru/api/v1/accounts/123/operations", true},
		{"https://tbank.ru/api/v1/cards", true},
		{"https://tbank.ru/api/v1/cards/authorizations", true}, // Plural: card auth holds!
		{"https://tbank.ru/api/v1/authorizations", true},       // Plural: card auth holds!
		{"https://tbank.ru/api/v1/session/accounts", true},     // Session accounts!
		{"https://tbank.ru/api/v1/session/user", true},         // Session user!
		{"https://tbank.ru/api/v1/session/products", true},     // Session products!
		{"https://tbank.ru/api/v1/session/cards", true},        // Session cards!
		{"https://tbank.ru/api/v1/session/balances", true},     // Session balances!
		{"https://tbank.ru/api/v1/session/limits", true},       // Session limits!
		{"https://tbank.ru/api/v1/security/limits", true},      // Security limits!
		{"https://tbank.ru/api/v1/operations/sign", true},      // Operation sign!
		{"https://tbank.ru/api/v1/payments/providers", true},
		{"https://tbank.ru/api/v1/transfers/sbp", true},
		{"https://tbank.ru/api/v1/statements/statement-1", true},
	}

	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got := f.EligiblePath(tc.url)
			if got != tc.eligible {
				t.Errorf("EligiblePath(%q) = %v, want %v", tc.url, got, tc.eligible)
			}
		})
	}
}

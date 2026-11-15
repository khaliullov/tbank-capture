package capture_test

import (
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

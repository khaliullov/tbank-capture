// Package config provides environment-based configuration and validation.
package config

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"
)

// LoadEnv loads environment variables from one or more .env files.
// If no filename is provided, it defaults to ".env" in the current directory.
// If a file does not exist, it is skipped without error.
// Existing environment variables are never overwritten.
func LoadEnv(filenames ...string) error {
	if len(filenames) == 0 {
		filenames = []string{".env"}
	}

	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		defer f.Close()

		if err := parseEnvReader(f); err != nil {
			return err
		}
	}
	return nil
}

// parseEnvReader parses .env content from an io.Reader and sets unset environment variables.
func parseEnvReader(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Support "export KEY=VAL" syntax
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export"))
		}

		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// Parse quoted values or strip inline comments for unquoted values
		val = parseEnvValue(val)

		// Set only if not already present in environment (12-factor precedence)
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

// ParseEnvBytes parses a byte slice representing .env file contents.
func ParseEnvBytes(data []byte) error {
	return parseEnvReader(bytes.NewReader(data))
}

// parseEnvValue extracts the actual string value, handling double and single quotes,
// escape sequences, and stripping unquoted inline comments.
func parseEnvValue(val string) string {
	if len(val) == 0 {
		return ""
	}

	// Double quotes
	if strings.HasPrefix(val, "\"") {
		endIdx := strings.LastIndex(val, "\"")
		if endIdx > 0 {
			inner := val[1:endIdx]
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			inner = strings.ReplaceAll(inner, `\t`, "\t")
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			return inner
		}
		return strings.TrimPrefix(val, "\"")
	}

	// Single quotes
	if strings.HasPrefix(val, "'") {
		endIdx := strings.LastIndex(val, "'")
		if endIdx > 0 {
			return val[1:endIdx]
		}
		return strings.TrimPrefix(val, "'")
	}

	// Unquoted: strip trailing comment if preceded by whitespace
	if idx := strings.Index(val, " #"); idx != -1 {
		val = strings.TrimSpace(val[:idx])
	} else if strings.HasPrefix(val, "#") {
		return ""
	}

	return strings.TrimSpace(val)
}

// Package config provides environment-based configuration and validation.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Telegram
	TelegramBotToken string
	TelegramChatID   int64

	// Browser
	UserDataDir string
	Headless    bool

	// Storage
	RawCaptureDir string
	DiscoveryDir  string

	// Discovery
	RawCaptureEnabled   bool
	MaxResponseBodySize int64
	CaptureQueueSize    int
	AllowedDomains      []string

	// Response Processing (bounded worker pool)
	ResponseWorkerCount int
	ResponseQueueSize   int

	// JSON analysis limits
	MaxJSONDepth  int
	MaxArrayElems int
	MaxJSONFields int

	// Logging
	LogLevel string
}

// Load reads configuration from environment variables and validates all fields.
// If a .env file exists in the current directory, it is loaded first.
// Secrets such as TELEGRAM_BOT_TOKEN are never included in error messages.
func Load() (*Config, error) {
	if err := LoadEnv(".env"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load .env: %w", err)
	}

	c := &Config{}
	var err error

	// Required: bot token. Never log or format its value into errors.
	c.TelegramBotToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if c.TelegramBotToken == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN is required")
	}

	// Required: chat ID.
	chatIDStr := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if chatIDStr == "" {
		return nil, errors.New("TELEGRAM_CHAT_ID is required")
	}
	c.TelegramChatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid integer for TELEGRAM_CHAT_ID: %q", chatIDStr)
	}
	if c.TelegramChatID == 0 {
		return nil, errors.New("TELEGRAM_CHAT_ID must be a non-zero integer")
	}

	// Paths
	c.UserDataDir = filepath.Clean(envStr("USER_DATA_DIR", "./data/browser-profile"))
	c.RawCaptureDir = filepath.Clean(envStr("RAW_CAPTURE_DIR", "./data/raw"))
	c.DiscoveryDir = filepath.Clean(envStr("DISCOVERY_DIR", "./data/discovery"))

	// Booleans
	c.Headless, err = envBool("HEADLESS", false)
	if err != nil {
		return nil, err
	}
	c.RawCaptureEnabled, err = envBool("DISCOVERY_RAW_CAPTURE", false)
	if err != nil {
		return nil, err
	}

	// Integers and limits
	c.MaxResponseBodySize, err = envInt64("MAX_RESPONSE_BODY_BYTES", 10*1024*1024)
	if err != nil {
		return nil, err
	}
	c.CaptureQueueSize, err = envInt("CAPTURE_QUEUE_SIZE", 128)
	if err != nil {
		return nil, err
	}
	c.ResponseWorkerCount, err = envInt("RESPONSE_WORKER_COUNT", 8)
	if err != nil {
		return nil, err
	}
	c.ResponseQueueSize, err = envInt("RESPONSE_QUEUE_SIZE", 256)
	if err != nil {
		return nil, err
	}
	c.MaxJSONDepth, err = envInt("MAX_JSON_DEPTH", 32)
	if err != nil {
		return nil, err
	}
	c.MaxArrayElems, err = envInt("MAX_ARRAY_ELEMENTS", 20)
	if err != nil {
		return nil, err
	}
	c.MaxJSONFields, err = envInt("MAX_JSON_FIELDS", 5000)
	if err != nil {
		return nil, err
	}

	// Allowed domains for capture
	c.AllowedDomains = parseAllowedDomains(envStr("CAPTURE_ALLOWED_DOMAINS", "tbank.ru,tinkoff.ru"))

	// Logging
	c.LogLevel = strings.ToLower(envStr("LOG_LEVEL", "info"))

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.UserDataDir == "" || (c.UserDataDir == "." && envIsSet("USER_DATA_DIR") && os.Getenv("USER_DATA_DIR") == "") {
		return errors.New("USER_DATA_DIR must not be empty")
	}
	if c.RawCaptureDir == "" {
		return errors.New("RAW_CAPTURE_DIR must not be empty")
	}
	if c.DiscoveryDir == "" {
		return errors.New("DISCOVERY_DIR must not be empty")
	}

	// Verify permissions of existing directories
	for _, dir := range []string{c.UserDataDir, c.RawCaptureDir, c.DiscoveryDir} {
		if err := CheckDirPermissions(dir); err != nil {
			return err
		}
	}

	if c.MaxResponseBodySize <= 0 {
		return errors.New("MAX_RESPONSE_BODY_BYTES must be positive")
	}
	if c.CaptureQueueSize <= 0 {
		return errors.New("CAPTURE_QUEUE_SIZE must be positive")
	}
	if c.ResponseWorkerCount <= 0 {
		return errors.New("RESPONSE_WORKER_COUNT must be positive")
	}
	if c.ResponseQueueSize <= 0 {
		return errors.New("RESPONSE_QUEUE_SIZE must be positive")
	}
	if c.MaxJSONDepth <= 0 {
		return errors.New("MAX_JSON_DEPTH must be positive")
	}
	if c.MaxArrayElems <= 0 {
		return errors.New("MAX_ARRAY_ELEMENTS must be positive")
	}
	if c.MaxJSONFields <= 0 {
		return errors.New("MAX_JSON_FIELDS must be positive")
	}

	if len(c.AllowedDomains) == 0 {
		return errors.New("CAPTURE_ALLOWED_DOMAINS must contain at least one valid domain")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.LogLevel] {
		return fmt.Errorf("LOG_LEVEL must be one of debug/info/warn/error, got: %q", c.LogLevel)
	}
	return nil
}

// CheckDirPermissions checks if an existing path is a directory and has appropriate access permissions.
// If the directory does not exist, it returns nil (directories may be created on demand).
// If the directory exists, it verifies that it is a directory and is writable.
func CheckDirPermissions(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat directory %s: %w", dir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path %s exists but is not a directory", dir)
	}

	// Verify directory permissions: test writability by attempting to create and remove a test file
	testFile := filepath.Join(dir, fmt.Sprintf(".perm_check_%d", time.Now().UnixNano()))
	if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
		return fmt.Errorf("directory %s is not writable: %w", dir, err)
	}
	_ = os.Remove(testFile)

	return nil
}

func envIsSet(key string) bool {
	_, ok := os.LookupEnv(key)
	return ok
}

func envStr(key, def string) string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	trimmed := strings.TrimSpace(v)
	b, err := strconv.ParseBool(trimmed)
	if err != nil {
		return false, fmt.Errorf("invalid boolean value for %s: %q", key, trimmed)
	}
	return b, nil
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	trimmed := strings.TrimSpace(v)
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid integer value for %s: %q", key, trimmed)
	}
	return n, nil
}

func envInt64(key string, def int64) (int64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	trimmed := strings.TrimSpace(v)
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer value for %s: %q", key, trimmed)
	}
	return n, nil
}

func parseAllowedDomains(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]bool, len(parts))
	var out []string
	for _, p := range parts {
		d := strings.ToLower(strings.TrimSpace(p))
		d = strings.TrimSuffix(d, ".")
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

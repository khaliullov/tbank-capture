// Package config provides environment-based configuration and validation.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	// JSON analysis limits
	MaxJSONDepth  int
	MaxArrayElems int
	MaxJSONFields int

	// Logging
	LogLevel string
}

// Load reads configuration from environment variables and validates required fields.
// Secrets are never logged.
func Load() (*Config, error) {
	c := &Config{
		UserDataDir:         envStr("USER_DATA_DIR", "./data/browser-profile"),
		RawCaptureDir:       envStr("RAW_CAPTURE_DIR", "./data/raw"),
		DiscoveryDir:        envStr("DISCOVERY_DIR", "./data/discovery"),
		Headless:            envBool("HEADLESS", false),
		RawCaptureEnabled:   envBool("DISCOVERY_RAW_CAPTURE", false),
		MaxResponseBodySize: envInt64("MAX_RESPONSE_BODY_BYTES", 10*1024*1024),
		CaptureQueueSize:    envInt("CAPTURE_QUEUE_SIZE", 128),
		MaxJSONDepth:        envInt("MAX_JSON_DEPTH", 32),
		MaxArrayElems:       envInt("MAX_ARRAY_ELEMENTS", 20),
		MaxJSONFields:       envInt("MAX_JSON_FIELDS", 5000),
		LogLevel:            strings.ToLower(envStr("LOG_LEVEL", "info")),
	}

	// Required: bot token
	c.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	if c.TelegramBotToken == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN is required")
	}

	// Required: chat ID
	chatIDStr := os.Getenv("TELEGRAM_CHAT_ID")
	if chatIDStr == "" {
		return nil, errors.New("TELEGRAM_CHAT_ID is required")
	}
	chatID, err := strconv.ParseInt(strings.TrimSpace(chatIDStr), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("TELEGRAM_CHAT_ID must be an integer: %w", err)
	}
	c.TelegramChatID = chatID

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.MaxResponseBodySize <= 0 {
		return errors.New("MAX_RESPONSE_BODY_BYTES must be positive")
	}
	if c.CaptureQueueSize <= 0 {
		return errors.New("CAPTURE_QUEUE_SIZE must be positive")
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
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.LogLevel] {
		return fmt.Errorf("LOG_LEVEL must be one of debug/info/warn/error, got: %q", c.LogLevel)
	}
	return nil
}

func envStr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

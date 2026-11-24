package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/config"
)

func setEnvMap(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func validBaseEnv() map[string]string {
	return map[string]string{
		"TELEGRAM_BOT_TOKEN": "123456:SECRET_BOT_TOKEN_VALUE",
		"TELEGRAM_CHAT_ID":   "987654321",
	}
}

func TestLoad_ValidDefaults(t *testing.T) {
	setEnvMap(t, validBaseEnv())
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected valid load, got error: %v", err)
	}

	if cfg.TelegramBotToken != "123456:SECRET_BOT_TOKEN_VALUE" {
		t.Errorf("unexpected token: %s", cfg.TelegramBotToken)
	}
	if cfg.TelegramChatID != 987654321 {
		t.Errorf("unexpected chat ID: %d", cfg.TelegramChatID)
	}
	if cfg.Headless != false {
		t.Errorf("default headless should be false, got true")
	}
	if cfg.RawCaptureEnabled != false {
		t.Errorf("default raw capture should be false, got true")
	}
	if cfg.MaxResponseBodySize != 10*1024*1024 {
		t.Errorf("unexpected max response size: %d", cfg.MaxResponseBodySize)
	}
	if cfg.CaptureQueueSize != 128 {
		t.Errorf("unexpected queue size: %d", cfg.CaptureQueueSize)
	}
	if cfg.ResponseWorkerCount != 8 {
		t.Errorf("unexpected response worker count: %d", cfg.ResponseWorkerCount)
	}
	if cfg.ResponseQueueSize != 256 {
		t.Errorf("unexpected response queue size: %d", cfg.ResponseQueueSize)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("unexpected log level: %s", cfg.LogLevel)
	}
	if len(cfg.AllowedDomains) != 2 || cfg.AllowedDomains[0] != "tbank.ru" || cfg.AllowedDomains[1] != "tinkoff.ru" {
		t.Errorf("unexpected allowed domains: %v", cfg.AllowedDomains)
	}
}

func TestLoad_CustomAllowedDomains(t *testing.T) {
	env := validBaseEnv()
	env["CAPTURE_ALLOWED_DOMAINS"] = " api.tbank.ru, TINKOFF.RU. , example.com "
	setEnvMap(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected valid load, got error: %v", err)
	}

	expected := []string{"api.tbank.ru", "tinkoff.ru", "example.com"}
	if len(cfg.AllowedDomains) != len(expected) {
		t.Fatalf("expected %d domains, got %d: %v", len(expected), len(cfg.AllowedDomains), cfg.AllowedDomains)
	}
	for i, d := range expected {
		if cfg.AllowedDomains[i] != d {
			t.Errorf("expected domain %d to be %q, got %q", i, d, cfg.AllowedDomains[i])
		}
	}
}

func TestLoad_EmptyAllowedDomains(t *testing.T) {
	env := validBaseEnv()
	env["CAPTURE_ALLOWED_DOMAINS"] = " , , . "
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for empty CAPTURE_ALLOWED_DOMAINS")
	}
}

func TestLoad_MissingToken(t *testing.T) {
	env := validBaseEnv()
	delete(env, "TELEGRAM_BOT_TOKEN")
	os.Unsetenv("TELEGRAM_BOT_TOKEN")
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing TELEGRAM_BOT_TOKEN")
	}
	if !strings.Contains(err.Error(), "TELEGRAM_BOT_TOKEN is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoad_MissingChatID(t *testing.T) {
	env := validBaseEnv()
	delete(env, "TELEGRAM_CHAT_ID")
	os.Unsetenv("TELEGRAM_CHAT_ID")
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing TELEGRAM_CHAT_ID")
	}
}

func TestLoad_InvalidChatID(t *testing.T) {
	env := validBaseEnv()
	env["TELEGRAM_CHAT_ID"] = "not-an-int"
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for invalid TELEGRAM_CHAT_ID")
	}
}

func TestLoad_ZeroChatID(t *testing.T) {
	env := validBaseEnv()
	env["TELEGRAM_CHAT_ID"] = "0"
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for zero TELEGRAM_CHAT_ID")
	}
}

func TestLoad_InvalidBool(t *testing.T) {
	cases := []struct {
		key string
		val string
	}{
		{"DISCOVERY_RAW_CAPTURE", "not-a-bool"},
		{"HEADLESS", "maybe"},
	}
	for _, tc := range cases {
		env := validBaseEnv()
		env[tc.key] = tc.val
		setEnvMap(t, env)

		_, err := config.Load()
		if err == nil {
			t.Errorf("expected error for invalid bool %s=%s", tc.key, tc.val)
		}
	}
}

func TestLoad_InvalidIntsAndLimits(t *testing.T) {
	cases := []struct {
		key string
		val string
	}{
		{"MAX_RESPONSE_BODY_BYTES", "not-a-number"},
		{"MAX_RESPONSE_BODY_BYTES", "0"},
		{"MAX_RESPONSE_BODY_BYTES", "-1"},
		{"CAPTURE_QUEUE_SIZE", "0"},
		{"CAPTURE_QUEUE_SIZE", "-10"},
		{"MAX_JSON_DEPTH", "0"},
		{"MAX_ARRAY_ELEMENTS", "-1"},
		{"MAX_JSON_FIELDS", "0"},
	}
	for _, tc := range cases {
		env := validBaseEnv()
		env[tc.key] = tc.val
		setEnvMap(t, env)

		_, err := config.Load()
		if err == nil {
			t.Errorf("expected error for %s=%s", tc.key, tc.val)
		}
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	env := validBaseEnv()
	env["LOG_LEVEL"] = "super-debug"
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for invalid LOG_LEVEL")
	}
}

func TestLoad_NeverExposesTokenInError(t *testing.T) {
	secretToken := "super-secret-token-value-xyz123"
	env := map[string]string{
		"TELEGRAM_BOT_TOKEN":    secretToken,
		"TELEGRAM_CHAT_ID":      "invalid",
		"DISCOVERY_RAW_CAPTURE": "invalid-bool",
	}
	setEnvMap(t, env)

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: secret bot token leaked in error message: %s", err.Error())
	}
}

func TestLoad_ResponseWorkerAndQueue(t *testing.T) {
	// Custom valid values
	env := validBaseEnv()
	env["RESPONSE_WORKER_COUNT"] = "16"
	env["RESPONSE_QUEUE_SIZE"] = "512"
	setEnvMap(t, env)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected valid load, got: %v", err)
	}
	if cfg.ResponseWorkerCount != 16 {
		t.Errorf("expected ResponseWorkerCount=16, got %d", cfg.ResponseWorkerCount)
	}
	if cfg.ResponseQueueSize != 512 {
		t.Errorf("expected ResponseQueueSize=512, got %d", cfg.ResponseQueueSize)
	}

	// Invalid worker count
	invalidWorkerCases := []string{"0", "-1", "abc"}
	for _, val := range invalidWorkerCases {
		env := validBaseEnv()
		env["RESPONSE_WORKER_COUNT"] = val
		setEnvMap(t, env)
		if _, err := config.Load(); err == nil {
			t.Errorf("expected error for RESPONSE_WORKER_COUNT=%q", val)
		}
	}

	// Invalid queue size
	invalidQueueCases := []string{"0", "-5", "xyz"}
	for _, val := range invalidQueueCases {
		env := validBaseEnv()
		env["RESPONSE_QUEUE_SIZE"] = val
		setEnvMap(t, env)
		if _, err := config.Load(); err == nil {
			t.Errorf("expected error for RESPONSE_QUEUE_SIZE=%q", val)
		}
	}
}

func TestCheckDirPermissions(t *testing.T) {
	// 1. Non-existent path should return nil (can be created later)
	nonExistent := "/tmp/test_dir_does_not_exist_987654321"
	if err := config.CheckDirPermissions(nonExistent); err != nil {
		t.Errorf("expected nil for non-existent dir, got: %v", err)
	}

	// 2. Existing writable directory should return nil
	tmpDir := t.TempDir()
	if err := config.CheckDirPermissions(tmpDir); err != nil {
		t.Errorf("expected nil for writable dir, got: %v", err)
	}

	// 3. Existing path that is a file, not a directory
	tmpFile := os.TempDir() + "/test_file_not_dir_" + t.Name()
	if err := os.WriteFile(tmpFile, []byte("content"), 0600); err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	if err := config.CheckDirPermissions(tmpFile); err == nil {
		t.Error("expected error for regular file, got nil")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %v", err)
	}

	// 4. Existing read-only directory (non-writable)
	readOnlyDir := t.TempDir() + "/readonly"
	if err := os.Mkdir(readOnlyDir, 0500); err != nil {
		t.Fatalf("mkdir read only: %v", err)
	}
	defer func() {
		_ = os.Chmod(readOnlyDir, 0700)
		_ = os.Remove(readOnlyDir)
	}()

	if err := config.CheckDirPermissions(readOnlyDir); err == nil {
		t.Error("expected error for read-only dir, got nil")
	} else if !strings.Contains(err.Error(), "not writable") {
		t.Errorf("expected 'not writable' error, got: %v", err)
	}
}

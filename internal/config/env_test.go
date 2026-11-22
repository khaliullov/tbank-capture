package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/config"
)

func TestLoadEnv_BasicAndQuoted(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := `
# Comment line
TEST_TBANK_VAR1=hello
TEST_TBANK_VAR2="world with spaces"
TEST_TBANK_VAR3='single quoted value'
TEST_TBANK_VAR4=unquoted_val # inline comment
export TEST_TBANK_VAR5=exported_val
TEST_TBANK_VAR6="escaped \"quotes\" and \n newline"
`
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write temp env: %v", err)
	}

	// Pre-set VAR1 in system environment to verify precedence
	_ = os.Setenv("TEST_TBANK_VAR1", "system_precedence")
	defer os.Unsetenv("TEST_TBANK_VAR1")
	defer os.Unsetenv("TEST_TBANK_VAR2")
	defer os.Unsetenv("TEST_TBANK_VAR3")
	defer os.Unsetenv("TEST_TBANK_VAR4")
	defer os.Unsetenv("TEST_TBANK_VAR5")
	defer os.Unsetenv("TEST_TBANK_VAR6")

	if err := config.LoadEnv(envPath); err != nil {
		t.Fatalf("LoadEnv failed: %v", err)
	}

	if got := os.Getenv("TEST_TBANK_VAR1"); got != "system_precedence" {
		t.Errorf("expected system env precedence, got %q", got)
	}
	if got := os.Getenv("TEST_TBANK_VAR2"); got != "world with spaces" {
		t.Errorf("expected 'world with spaces', got %q", got)
	}
	if got := os.Getenv("TEST_TBANK_VAR3"); got != "single quoted value" {
		t.Errorf("expected 'single quoted value', got %q", got)
	}
	if got := os.Getenv("TEST_TBANK_VAR4"); got != "unquoted_val" {
		t.Errorf("expected 'unquoted_val', got %q", got)
	}
	if got := os.Getenv("TEST_TBANK_VAR5"); got != "exported_val" {
		t.Errorf("expected 'exported_val', got %q", got)
	}
	if got := os.Getenv("TEST_TBANK_VAR6"); got != "escaped \"quotes\" and \n newline" {
		t.Errorf("expected escaped quotes and newline, got %q", got)
	}
}

func TestLoadEnv_NonExistentFile(t *testing.T) {
	// Should not fail if file doesn't exist
	if err := config.LoadEnv("/path/does/not/exist/.env.nonexistent"); err != nil {
		t.Errorf("expected nil error for missing env file, got: %v", err)
	}
}

func TestLoad_FromDotEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	envContent := `
TELEGRAM_BOT_TOKEN="auto-loaded-token"
TELEGRAM_CHAT_ID=12345678
HEADLESS=true
CAPTURE_ALLOWED_DOMAINS="tbank.ru,tinkoff.ru,custom.bank.ru"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Clear any inherited system env
	_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
	_ = os.Unsetenv("TELEGRAM_CHAT_ID")
	_ = os.Unsetenv("HEADLESS")
	_ = os.Unsetenv("CAPTURE_ALLOWED_DOMAINS")
	defer os.Unsetenv("TELEGRAM_BOT_TOKEN")
	defer os.Unsetenv("TELEGRAM_CHAT_ID")
	defer os.Unsetenv("HEADLESS")
	defer os.Unsetenv("CAPTURE_ALLOWED_DOMAINS")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() failed: %v", err)
	}

	if cfg.TelegramBotToken != "auto-loaded-token" {
		t.Errorf("expected token 'auto-loaded-token', got %q", cfg.TelegramBotToken)
	}
	if cfg.TelegramChatID != 12345678 {
		t.Errorf("expected chat id 12345678, got %d", cfg.TelegramChatID)
	}
	if !cfg.Headless {
		t.Error("expected Headless=true")
	}
	if len(cfg.AllowedDomains) != 3 || cfg.AllowedDomains[2] != "custom.bank.ru" {
		t.Errorf("expected 3 allowed domains with custom.bank.ru, got %v", cfg.AllowedDomains)
	}
}

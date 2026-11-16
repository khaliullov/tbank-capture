package browser_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/khaliullov/tbank-capture/internal/browser"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type mockChecker struct {
	status *browser.PreflightStatus
	err    error
}

func (m *mockChecker) Check() (*browser.PreflightStatus, error) {
	return m.status, m.err
}

// TestPreflight_MissingDriver verifies that when the driver is missing,
// Manager.Start returns an actionable error referencing make playwright-install.
func TestPreflight_MissingDriver(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := browser.NewManager(noopLogger(), tmpDir, true)

	requiredVer := browser.RequiredDriverVersion()
	errDriverMissing := fmt.Sprintf("Playwright initialization failed:\n  operation: preflight check\n  driver: not installed or incompatible\n  required version: v%s\n\nRun:\n  make playwright-install", requiredVer)

	mgr.SetPreflightChecker(&mockChecker{
		status: &browser.PreflightStatus{
			RequiredVersion: requiredVer,
			DriverInstalled: false,
		},
		err: errors.New(errDriverMissing),
	})

	err := mgr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on missing driver, got nil")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "%!w(<nil>)") {
		t.Errorf("error message contains bad formatting: %s", errMsg)
	}
	if !strings.Contains(errMsg, "driver: not installed or incompatible") {
		t.Errorf("expected missing driver diagnostic, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "make playwright-install") {
		t.Errorf("expected make playwright-install suggestion, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, fmt.Sprintf("v%s", requiredVer)) {
		t.Errorf("expected version v%s in error, got: %s", requiredVer, errMsg)
	}
}

// TestPreflight_MissingChromium verifies that when the driver exists but Chromium is missing,
// the diagnostic accurately pinpoints Chromium and recommends the installation command.
func TestPreflight_MissingChromium(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := browser.NewManager(noopLogger(), tmpDir, true)

	requiredVer := browser.RequiredDriverVersion()
	errBrowserMissing := fmt.Sprintf("Playwright initialization failed:\n  operation: preflight check\n  browser (Chromium): not installed\n  required version: v%s\n\nRun:\n  make playwright-install", requiredVer)

	mgr.SetPreflightChecker(&mockChecker{
		status: &browser.PreflightStatus{
			RequiredVersion:  requiredVer,
			DriverInstalled:  true,
			BrowserInstalled: false,
		},
		err: errors.New(errBrowserMissing),
	})

	err := mgr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on missing browser, got nil")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "%!w(<nil>)") {
		t.Errorf("error message contains bad formatting: %s", errMsg)
	}
	if !strings.Contains(errMsg, "browser (Chromium): not installed") {
		t.Errorf("expected missing Chromium diagnostic, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "make playwright-install") {
		t.Errorf("expected make playwright-install suggestion, got: %s", errMsg)
	}
}

// TestDefaultPreflightChecker_MissingDriver detects missing driver files on disk.
func TestDefaultPreflightChecker_MissingDriver(t *testing.T) {
	emptyDir := t.TempDir()
	checker := &browser.DefaultPreflightChecker{
		DriverDirOverride:  emptyDir,
		BrowserDirOverride: emptyDir,
	}

	status, err := checker.Check()
	if err == nil {
		t.Fatal("expected check to fail for empty driver directory")
	}
	if status == nil {
		t.Fatal("expected status struct, got nil")
	}
	if status.DriverInstalled {
		t.Error("expected DriverInstalled == false")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "driver: not installed or incompatible") {
		t.Errorf("unexpected error message: %s", errMsg)
	}
	if strings.Contains(errMsg, "%!w(<nil>)") {
		t.Errorf("error contains bad formatting artifact: %s", errMsg)
	}
}

// TestDefaultPreflightChecker_MissingBrowser detects when driver is present but Chromium is missing.
func TestDefaultPreflightChecker_MissingBrowser(t *testing.T) {
	driverDir := t.TempDir()
	emptyBrowserDir := t.TempDir()

	requiredVer := browser.RequiredDriverVersion()

	// Create fake driver package
	pkgDir := filepath.Join(driverDir, "package")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create dummy cli.js
	cliJs := filepath.Join(pkgDir, "cli.js")
	if err := os.WriteFile(cliJs, []byte("// fake cli"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create dummy browsers.json pointing to revision 9999
	browsersJson := filepath.Join(pkgDir, "browsers.json")
	browsersContent := `{"browsers":[{"name":"chromium","revision":"9999"}]}`
	if err := os.WriteFile(browsersJson, []byte(browsersContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dummy node script/binary that echoes "Version <requiredVer>" when called with --version
	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName = "node.cmd"
	}
	nodePath := filepath.Join(driverDir, nodeName)

	var nodeScript string
	if runtime.GOOS == "windows" {
		nodeScript = fmt.Sprintf("@echo Version %s\n", requiredVer)
	} else {
		nodeScript = fmt.Sprintf("#!/bin/sh\necho \"Version %s\"\n", requiredVer)
	}
	if err := os.WriteFile(nodePath, []byte(nodeScript), 0755); err != nil {
		t.Fatal(err)
	}

	checker := &browser.DefaultPreflightChecker{
		DriverDirOverride:  driverDir,
		BrowserDirOverride: emptyBrowserDir,
	}

	status, err := checker.Check()
	if err == nil {
		t.Fatal("expected error due to missing Chromium")
	}
	if !status.DriverInstalled {
		t.Errorf("expected driver to be reported installed, detail: %s", status.DetailError)
	}
	if status.BrowserInstalled {
		t.Error("expected BrowserInstalled == false")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "browser (Chromium): not installed") {
		t.Errorf("expected missing browser message, got: %s", errMsg)
	}
}

// TestDefaultPreflightChecker_Successful verifies that when both driver and Chromium are present,
// Check() returns nil without launching a browser.
func TestDefaultPreflightChecker_Successful(t *testing.T) {
	driverDir := t.TempDir()
	browserDir := t.TempDir()

	requiredVer := browser.RequiredDriverVersion()

	// 1. Setup fake driver
	pkgDir := filepath.Join(driverDir, "package")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	cliJs := filepath.Join(pkgDir, "cli.js")
	if err := os.WriteFile(cliJs, []byte("// fake cli"), 0644); err != nil {
		t.Fatal(err)
	}
	browsersJson := filepath.Join(pkgDir, "browsers.json")
	browsersContent := `{"browsers":[{"name":"chromium","revision":"1140"}]}`
	if err := os.WriteFile(browsersJson, []byte(browsersContent), 0644); err != nil {
		t.Fatal(err)
	}

	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName = "node.cmd"
	}
	nodePath := filepath.Join(driverDir, nodeName)
	var nodeScript string
	if runtime.GOOS == "windows" {
		nodeScript = fmt.Sprintf("@echo Version %s\n", requiredVer)
	} else {
		nodeScript = fmt.Sprintf("#!/bin/sh\necho \"Version %s\"\n", requiredVer)
	}
	if err := os.WriteFile(nodePath, []byte(nodeScript), 0755); err != nil {
		t.Fatal(err)
	}

	// 2. Setup fake Chromium binary
	var chromeRelPath string
	switch runtime.GOOS {
	case "darwin":
		chromeRelPath = filepath.Join("chromium-1140", "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium")
	case "windows":
		chromeRelPath = filepath.Join("chromium-1140", "chrome-win", "chrome.exe")
	default:
		chromeRelPath = filepath.Join("chromium-1140", "chrome-linux", "chrome")
	}

	chromeFull := filepath.Join(browserDir, chromeRelPath)
	if err := os.MkdirAll(filepath.Dir(chromeFull), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chromeFull, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	checker := &browser.DefaultPreflightChecker{
		DriverDirOverride:  driverDir,
		BrowserDirOverride: browserDir,
	}

	status, err := checker.Check()
	if err != nil {
		t.Fatalf("expected preflight check to pass, got err: %v", err)
	}
	if !status.DriverInstalled {
		t.Error("expected DriverInstalled == true")
	}
	if !status.BrowserInstalled {
		t.Error("expected BrowserInstalled == true")
	}
	if status.BrowserPath != chromeFull {
		t.Errorf("expected browser path %s, got %s", chromeFull, status.BrowserPath)
	}
}

// TestErrorWrapping verifies that errors from underlying operations are preserved and unwrap properly.
func TestErrorWrapping(t *testing.T) {
	origErr := errors.New("underlying socket timeout")
	tmpDir := t.TempDir()
	mgr := browser.NewManager(noopLogger(), tmpDir, true)

	mgr.SetPreflightChecker(&mockChecker{
		status: &browser.PreflightStatus{
			RequiredVersion: "1.48.2",
			DriverInstalled: false,
		},
		err: fmt.Errorf("preflight failed: %w", origErr),
	})

	err := mgr.Start(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, origErr) {
		t.Errorf("expected errors.Is to match original error, got: %v", err)
	}
}

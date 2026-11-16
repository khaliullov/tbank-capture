package browser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	pw "github.com/playwright-community/playwright-go"
)

// PreflightStatus contains the detected installation state of Playwright components.
type PreflightStatus struct {
	RequiredVersion  string
	DriverInstalled  bool
	DriverVersion    string
	DriverPath       string
	BrowserInstalled bool
	BrowserPath      string
	DetailError      string
}

// PreflightChecker defines the interface for verifying Playwright installation.
type PreflightChecker interface {
	Check() (*PreflightStatus, error)
}

// DefaultPreflightChecker inspects the local filesystem and driver runtime to verify readiness.
type DefaultPreflightChecker struct {
	DriverDirOverride  string
	BrowserDirOverride string
}

// NewPreflightChecker creates a DefaultPreflightChecker using standard system and environment paths.
func NewPreflightChecker() *DefaultPreflightChecker {
	return &DefaultPreflightChecker{}
}

// Check verifies that the required Playwright driver and Chromium browser are installed.
func (c *DefaultPreflightChecker) Check() (*PreflightStatus, error) {
	requiredVersion := RequiredDriverVersion()
	status := &PreflightStatus{
		RequiredVersion: requiredVersion,
	}

	driverDir := c.resolveDriverDir(requiredVersion)
	status.DriverPath = driverDir

	// 1. Verify Driver
	cliJsPath := filepath.Join(driverDir, "package", "cli.js")
	if _, err := os.Stat(cliJsPath); err != nil {
		status.DriverInstalled = false
		status.DetailError = fmt.Sprintf("driver package missing at %s", cliJsPath)
		return status, formatPreflightError(status, "preflight check", nil)
	}

	nodeBin := c.resolveNodeBin(driverDir)
	if nodeBin == "" {
		status.DriverInstalled = false
		status.DetailError = fmt.Sprintf("node executable not found in driver dir %s or PATH", driverDir)
		return status, formatPreflightError(status, "preflight check", nil)
	}

	// Verify driver version by executing node package/cli.js --version
	cmd := exec.Command(nodeBin, cliJsPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		status.DriverInstalled = false
		status.DetailError = fmt.Sprintf("failed executing driver version check: %v", err)
		return status, formatPreflightError(status, "preflight check", err)
	}

	trimmedOut := strings.TrimSpace(string(out))
	status.DriverVersion = trimmedOut
	if !bytes.Contains(out, []byte(requiredVersion)) {
		status.DriverInstalled = false
		status.DetailError = fmt.Sprintf("driver version mismatch: got %q, want %q", trimmedOut, requiredVersion)
		return status, formatPreflightError(status, "preflight check", nil)
	}
	status.DriverInstalled = true

	// 2. Verify Chromium Browser
	browserDir := c.resolveBrowserDir()
	browserPath, found := c.findChromiumExecutable(driverDir, browserDir)
	if !found {
		status.BrowserInstalled = false
		status.DetailError = fmt.Sprintf("Chromium executable not found in %s", browserDir)
		return status, formatPreflightError(status, "preflight check", nil)
	}

	status.BrowserInstalled = true
	status.BrowserPath = browserPath
	return status, nil
}

func (c *DefaultPreflightChecker) resolveDriverDir(requiredVersion string) string {
	if c.DriverDirOverride != "" {
		return c.DriverDirOverride
	}
	if env := os.Getenv("PLAYWRIGHT_DRIVER_PATH"); env != "" {
		return env
	}
	cacheDir := defaultCacheDir()
	return filepath.Join(cacheDir, "ms-playwright-go", requiredVersion)
}

func (c *DefaultPreflightChecker) resolveBrowserDir() string {
	if c.BrowserDirOverride != "" {
		return c.BrowserDirOverride
	}
	if env := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); env != "" {
		return env
	}
	cacheDir := defaultCacheDir()
	return filepath.Join(cacheDir, "ms-playwright")
}

func (c *DefaultPreflightChecker) resolveNodeBin(driverDir string) string {
	if env := os.Getenv("PLAYWRIGHT_NODEJS_PATH"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}

	nodeName := "node"
	if runtime.GOOS == "windows" {
		nodeName = "node.exe"
	}

	localNode := filepath.Join(driverDir, nodeName)
	if _, err := os.Stat(localNode); err == nil {
		return localNode
	}

	if sysNode, err := exec.LookPath(nodeName); err == nil {
		return sysNode
	}

	return ""
}

type browserEntry struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

type browsersFile struct {
	Browsers []browserEntry `json:"browsers"`
}

func (c *DefaultPreflightChecker) findChromiumExecutable(driverDir, browserDir string) (string, bool) {
	// 1. Try reading revision from package/browsers.json
	browsersJsonPath := filepath.Join(driverDir, "package", "browsers.json")
	var revisions []string
	if data, err := os.ReadFile(browsersJsonPath); err == nil {
		var bf browsersFile
		if err := json.Unmarshal(data, &bf); err == nil {
			for _, b := range bf.Browsers {
				if b.Name == "chromium" && b.Revision != "" {
					revisions = append(revisions, b.Revision)
				}
			}
		}
	}

	// 2. Check candidate paths for each discovered revision
	for _, rev := range revisions {
		targetDir := filepath.Join(browserDir, "chromium-"+rev)
		if p, ok := checkChromiumInDir(targetDir); ok {
			return p, true
		}
	}

	// 3. Fallback: check all chromium-* directories in browserDir
	matches, _ := filepath.Glob(filepath.Join(browserDir, "chromium-*"))
	for _, dir := range matches {
		if p, ok := checkChromiumInDir(dir); ok {
			return p, true
		}
	}

	return "", false
}

func checkChromiumInDir(dir string) (string, bool) {
	candidates := []string{
		filepath.Join(dir, "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium"),
		filepath.Join(dir, "chrome-linux", "chrome"),
		filepath.Join(dir, "chrome-win", "chrome.exe"),
		filepath.Join(dir, "chrome"),
		filepath.Join(dir, "Chromium"),
		filepath.Join(dir, "chrome.exe"),
	}

	for _, cand := range candidates {
		info, err := os.Stat(cand)
		if err != nil || info.IsDir() {
			continue
		}
		// On non-windows, verify execute permissions
		if runtime.GOOS != "windows" && (info.Mode().Perm()&0111) == 0 {
			continue
		}
		return cand, true
	}
	return "", false
}

func defaultCacheDir() string {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return os.TempDir()
	}
	switch runtime.GOOS {
	case "windows":
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return localAppData
		}
		return filepath.Join(userHomeDir, "AppData", "Local")
	case "darwin":
		return filepath.Join(userHomeDir, "Library", "Caches")
	default:
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			return xdg
		}
		return filepath.Join(userHomeDir, ".cache")
	}
}

// RequiredDriverVersion returns the version of Playwright driver expected by the pinned Go dependency.
func RequiredDriverVersion() string {
	d, err := pw.NewDriver()
	if err == nil && d != nil && d.Version != "" {
		return d.Version
	}
	return "1.48.2" // fallback matching v0.4802.0
}

func formatPreflightError(status *PreflightStatus, operation string, err error) error {
	var detail string
	if !status.DriverInstalled {
		detail = "driver: not installed or incompatible"
	} else if !status.BrowserInstalled {
		detail = "browser (Chromium): not installed"
	} else {
		detail = "installation incomplete"
	}

	msg := fmt.Sprintf("Playwright initialization failed:\n  operation: %s\n  %s\n  required version: v%s",
		operation, detail, status.RequiredVersion)

	if status.DetailError != "" {
		msg += fmt.Sprintf("\n  diagnostic: %s", status.DetailError)
	}

	msg += "\n\nRun:\n  make playwright-install"

	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return errors.New(msg)
}

func formatStartupError(operation, requiredVersion string, err error) error {
	var errStr string
	if err != nil {
		errStr = err.Error()
		// Clean up any "%!w(<nil>)" artifacts from third-party libraries
		errStr = strings.ReplaceAll(errStr, ": %!w(<nil>)", "")
		errStr = strings.ReplaceAll(errStr, "%!w(<nil>)", "")
		errStr = strings.TrimSpace(errStr)
	}

	msg := fmt.Sprintf("Playwright initialization failed:\n  operation: %s\n  required version: v%s", operation, requiredVersion)
	if errStr != "" {
		msg += fmt.Sprintf("\n  detail: %s", errStr)
	}
	msg += "\n\nRun:\n  make playwright-install"

	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return errors.New(msg)
}

// CheckPlaywright performs an immediate preflight verification of Playwright driver and Chromium.
func CheckPlaywright() error {
	_, err := NewPreflightChecker().Check()
	return err
}

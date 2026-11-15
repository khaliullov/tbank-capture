package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportVersion is the JSON report schema version.
const ReportVersion = "1"

// Report is the machine-readable discovery report.
type Report struct {
	Version     string                `json:"version"`
	SessionID   SessionID             `json:"session_id"`
	GeneratedAt time.Time             `json:"generated_at"`
	StartedAt   time.Time             `json:"started_at"`
	FinishedAt  time.Time             `json:"finished_at"`
	Summary     ReportSummary         `json:"summary"`
	Candidates  []EndpointFingerprint `json:"candidates"`
	Unknown     []EndpointFingerprint `json:"unknown"`
	Warnings    []string              `json:"warnings,omitempty"`
}

// ReportSummary holds aggregate telemetry and discovery candidate counts.
type ReportSummary struct {
	TotalObserved         int `json:"total_observed"`
	EligibleResponses     int `json:"eligible_responses"`
	UniqueFingerprints    int `json:"unique_fingerprints"`
	TransactionCandidates int `json:"transaction_candidates"`
	AccountCandidates     int `json:"account_candidates"`
	CardCandidates        int `json:"card_candidates"`
	BalanceCandidates     int `json:"balance_candidates"`
	PaymentCandidates     int `json:"payment_candidates"`
	TransferCandidates    int `json:"transfer_candidates"`
	StatementCandidates   int `json:"statement_candidates"`
	CaptureFailures       int `json:"capture_failures"`
	QueueOverflows        int `json:"queue_overflows"`
}

// Generator produces Markdown and JSON reports from collected fingerprints.
type Generator struct {
	reportDir string
}

// NewGenerator creates a report Generator.
func NewGenerator(reportDir string) *Generator {
	return &Generator{reportDir: reportDir}
}

// Generate writes both Markdown and JSON reports, returning their file paths.
// All files are created with restrictive 0600 permissions.
func (g *Generator) Generate(sess *Session, fps []*EndpointFingerprint, metrics Metrics) (mdPath, jsonPath string, err error) {
	if sess == nil {
		return "", "", fmt.Errorf("cannot generate report: session is nil")
	}

	if err := os.MkdirAll(g.reportDir, 0700); err != nil {
		return "", "", fmt.Errorf("create report dir: %w", err)
	}

	now := time.Now().UTC()
	stem := fmt.Sprintf("report-%s", sess.ID)
	mdPath = filepath.Join(g.reportDir, stem+".md")
	jsonPath = filepath.Join(g.reportDir, stem+".json")

	report := buildReport(sess, fps, metrics, now)

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal report: %w", err)
	}
	if err := atomicWriteFile(jsonPath, jsonData, 0600); err != nil {
		return "", "", fmt.Errorf("write json report: %w", err)
	}

	mdData := renderMarkdown(report)
	if err := atomicWriteFile(mdPath, []byte(mdData), 0600); err != nil {
		return "", "", fmt.Errorf("write markdown report: %w", err)
	}

	return mdPath, jsonPath, nil
}

func buildReport(sess *Session, fps []*EndpointFingerprint, metrics Metrics, now time.Time) Report {
	finished := sess.StoppedAt
	if finished.IsZero() {
		finished = now
	}

	summary := ReportSummary{
		TotalObserved:      metrics.TotalObserved,
		EligibleResponses:  metrics.EligibleResponses,
		UniqueFingerprints: len(fps),
		CaptureFailures:    metrics.CaptureFailures,
		QueueOverflows:     metrics.QueueOverflows,
	}

	var candidates, unknown []EndpointFingerprint
	var sessionWarnings []string

	if metrics.QueueOverflows > 0 {
		sessionWarnings = append(sessionWarnings, fmt.Sprintf("Capture queue overflowed %d time(s); some responses were dropped", metrics.QueueOverflows))
	}
	if metrics.CaptureFailures > 0 {
		sessionWarnings = append(sessionWarnings, fmt.Sprintf("%d response(s) failed body retrieval or exceeded size limit", metrics.CaptureFailures))
	}

	for _, fp := range fps {
		cloned := *cloneFingerprint(fp)

		for _, w := range cloned.CaptureWarnings {
			sessionWarnings = append(sessionWarnings, fmt.Sprintf("%s (%s): %s", cloned.NormalizedPath, cloned.Method, w))
		}

		// Use consistent threshold: confidence >= 0.6 to be counted as strong candidate.
		isStrong := cloned.Classification.Confidence >= 0.6 && cloned.Classification.Category != CategoryUnknown

		if isStrong {
			switch cloned.Classification.Category {
			case CategoryTransactions:
				summary.TransactionCandidates++
			case CategoryAccounts:
				summary.AccountCandidates++
			case CategoryCards:
				summary.CardCandidates++
			case CategoryBalances:
				summary.BalanceCandidates++
			case CategoryPayments:
				summary.PaymentCandidates++
			case CategoryTransfers:
				summary.TransferCandidates++
			case CategoryStatements:
				summary.StatementCandidates++
			}
			candidates = append(candidates, cloned)
		} else {
			unknown = append(unknown, cloned)
		}
	}

	// Deterministic sorting of candidates: confidence desc, path asc
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Classification.Confidence != candidates[j].Classification.Confidence {
			return candidates[i].Classification.Confidence > candidates[j].Classification.Confidence
		}
		return candidates[i].NormalizedPath < candidates[j].NormalizedPath
	})

	// Deterministic sorting of unknown: observations desc, path asc
	sort.Slice(unknown, func(i, j int) bool {
		if unknown[i].Observations != unknown[j].Observations {
			return unknown[i].Observations > unknown[j].Observations
		}
		return unknown[i].NormalizedPath < unknown[j].NormalizedPath
	})

	return Report{
		Version:     ReportVersion,
		SessionID:   sess.ID,
		GeneratedAt: now,
		StartedAt:   sess.StartedAt,
		FinishedAt:  finished,
		Summary:     summary,
		Candidates:  candidates,
		Unknown:     unknown,
		Warnings:    dedupStrings(sessionWarnings),
	}
}

func renderMarkdown(r Report) string {
	var sb strings.Builder

	sb.WriteString("# T-Bank Network Discovery Report\n\n")
	sb.WriteString(fmt.Sprintf("Session ID: `%s`  \n", r.SessionID))
	sb.WriteString(fmt.Sprintf("Started: %s  \n", r.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Finished: %s  \n", r.FinishedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Generated: %s  \n\n", r.GeneratedAt.Format(time.RFC3339)))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total observed responses: %d\n", r.Summary.TotalObserved))
	sb.WriteString(fmt.Sprintf("- Eligible JSON responses: %d\n", r.Summary.EligibleResponses))
	sb.WriteString(fmt.Sprintf("- Unique endpoint fingerprints: %d\n", r.Summary.UniqueFingerprints))
	sb.WriteString(fmt.Sprintf("- Transaction candidates: %d\n", r.Summary.TransactionCandidates))
	sb.WriteString(fmt.Sprintf("- Account candidates: %d\n", r.Summary.AccountCandidates))
	sb.WriteString(fmt.Sprintf("- Card candidates: %d\n", r.Summary.CardCandidates))
	sb.WriteString(fmt.Sprintf("- Balance candidates: %d\n", r.Summary.BalanceCandidates))
	sb.WriteString(fmt.Sprintf("- Payment candidates: %d\n", r.Summary.PaymentCandidates))
	sb.WriteString(fmt.Sprintf("- Transfer candidates: %d\n", r.Summary.TransferCandidates))
	sb.WriteString(fmt.Sprintf("- Statement candidates: %d\n", r.Summary.StatementCandidates))
	if r.Summary.CaptureFailures > 0 {
		sb.WriteString(fmt.Sprintf("- Capture failures: %d\n", r.Summary.CaptureFailures))
	}
	if r.Summary.QueueOverflows > 0 {
		sb.WriteString(fmt.Sprintf("- Queue overflows: %d\n", r.Summary.QueueOverflows))
	}
	sb.WriteString("\n")

	if len(r.Candidates) > 0 {
		sb.WriteString("## Endpoint Candidates\n\n")
		for i, fp := range r.Candidates {
			sb.WriteString(fmt.Sprintf("### Candidate %d\n\n", i+1))
			writeFingerprintMD(&sb, &fp)
		}
	}

	if len(r.Unknown) > 0 {
		sb.WriteString("## Unclassified / Low-Confidence Endpoints\n\n")
		for _, fp := range r.Unknown {
			sb.WriteString(fmt.Sprintf("- `%s` (%s) — %d observations (confidence: %.2f)\n",
				fp.NormalizedPath, fp.Method, fp.Observations, fp.Classification.Confidence))
		}
		sb.WriteString("\n")
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("## Capture Warnings\n\n")
		for _, w := range r.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", w))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func writeFingerprintMD(sb *strings.Builder, fp *EndpointFingerprint) {
	sb.WriteString(fmt.Sprintf("- **Category**: %s\n", fp.Classification.Category))
	sb.WriteString(fmt.Sprintf("- **Confidence**: %.2f\n", fp.Classification.Confidence))
	sb.WriteString(fmt.Sprintf("- **Normalized path**: `%s`\n", fp.NormalizedPath))
	sb.WriteString(fmt.Sprintf("- **HTTP method**: %s\n", fp.Method))
	sb.WriteString(fmt.Sprintf("- **Resource type**: %s\n", fp.ResourceType))
	sb.WriteString(fmt.Sprintf("- **Observations**: %d\n", fp.Observations))
	sb.WriteString(fmt.Sprintf("- **Unique bodies**: %d\n", fp.UniqueBodyCount))
	if fp.Observations > 0 {
		avg := fp.TotalBytes / int64(fp.Observations)
		sb.WriteString(fmt.Sprintf("- **Average response size**: %d bytes\n", avg))
	}
	sb.WriteString(fmt.Sprintf("- **Max response size**: %d bytes\n", fp.MaxResponseSize))
	sb.WriteString(fmt.Sprintf("- **Paginated**: %v\n", fp.IsPaginated))
	sb.WriteString(fmt.Sprintf("- **Date-range params**: %v\n", fp.HasDateParams))
	sb.WriteString(fmt.Sprintf("- **Returns list**: %v\n", fp.ReturnsList))
	sb.WriteString(fmt.Sprintf("- **First seen**: %s\n", fp.FirstSeen.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Last seen**: %s\n", fp.LastSeen.Format(time.RFC3339)))

	// Deterministic status distribution: sort status codes.
	var statusCodes []int
	for code := range fp.StatusDist {
		statusCodes = append(statusCodes, code)
	}
	sort.Ints(statusCodes)
	sb.WriteString("- **Status distribution**:")
	for _, code := range statusCodes {
		sb.WriteString(fmt.Sprintf(" %d×%d", code, fp.StatusDist[code]))
	}
	sb.WriteString("\n")

	// Endpoint-level capture warnings
	if len(fp.CaptureWarnings) > 0 {
		sb.WriteString("- **Warnings**:\n")
		for _, w := range fp.CaptureWarnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	// Classification reasons
	if len(fp.Classification.Reasons) > 0 {
		sb.WriteString("\n#### Classification reasons\n\n")
		for _, r := range fp.Classification.Reasons {
			sb.WriteString(fmt.Sprintf("- %s\n", r))
		}
	}

	// JSON schema table (only structure, never values!)
	if len(fp.SchemaFields) > 0 {
		sb.WriteString("\n#### JSON schema\n\n")
		sb.WriteString("| JSON path | Types | Optional | Classification |\n")
		sb.WriteString("|---|---|---|---|\n")
		for _, f := range fp.SchemaFields {
			types := strings.Join(f.ObservedTypes, ", ")
			cls := string(f.Classification)
			if cls == "" {
				cls = "-"
			}
			optStr := "no"
			if f.Optional {
				optStr = "yes"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n", f.Path, types, optStr, cls))
		}
	}

	sb.WriteString("\n")
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

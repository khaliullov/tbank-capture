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

// ReportSummary holds aggregate counts.
type ReportSummary struct {
	TotalObserved         int `json:"total_observed"`
	EligibleResponses     int `json:"eligible_responses"`
	UniqueFingerprints    int `json:"unique_fingerprints"`
	TransactionCandidates int `json:"transaction_candidates"`
	AccountCandidates     int `json:"account_candidates"`
	CardCandidates        int `json:"card_candidates"`
	BalanceCandidates     int `json:"balance_candidates"`
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
func (g *Generator) Generate(sess *Session, fps []*EndpointFingerprint, metrics Metrics) (mdPath, jsonPath string, err error) {
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
		UniqueFingerprints: metrics.UniqueFingerprints,
	}

	var candidates, unknown []EndpointFingerprint
	for _, fp := range fps {
		switch fp.Classification.Category {
		case CategoryTransactions:
			summary.TransactionCandidates++
			candidates = append(candidates, *fp)
		case CategoryAccounts:
			summary.AccountCandidates++
			candidates = append(candidates, *fp)
		case CategoryCards:
			summary.CardCandidates++
			candidates = append(candidates, *fp)
		case CategoryBalances:
			summary.BalanceCandidates++
			candidates = append(candidates, *fp)
		case CategoryUnknown:
			unknown = append(unknown, *fp)
		default:
			candidates = append(candidates, *fp)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Classification.Confidence > candidates[j].Classification.Confidence
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
	sb.WriteString(fmt.Sprintf("- Strong transaction candidates: %d\n", r.Summary.TransactionCandidates))
	sb.WriteString(fmt.Sprintf("- Account candidates: %d\n", r.Summary.AccountCandidates))
	sb.WriteString(fmt.Sprintf("- Card candidates: %d\n", r.Summary.CardCandidates))
	sb.WriteString(fmt.Sprintf("- Balance candidates: %d\n\n", r.Summary.BalanceCandidates))

	if len(r.Candidates) > 0 {
		sb.WriteString("## Endpoint Candidates\n\n")
		for i, fp := range r.Candidates {
			sb.WriteString(fmt.Sprintf("### Candidate %d\n\n", i+1))
			writeFingerprintMD(&sb, &fp)
		}
	}

	if len(r.Unknown) > 0 {
		sb.WriteString("## Unknown Endpoints\n\n")
		for _, fp := range r.Unknown {
			sb.WriteString(fmt.Sprintf("- `%s` (%s) — %d observations\n",
				fp.NormalizedPath, fp.Method, fp.Observations))
		}
		sb.WriteString("\n")
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("## Capture Warnings\n\n")
		for _, w := range r.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", w))
		}
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

	// Status distribution.
	sb.WriteString("- **Status distribution**:")
	for code, count := range fp.StatusDist {
		sb.WriteString(fmt.Sprintf(" %d×%d", code, count))
	}
	sb.WriteString("\n")

	// Classification reasons.
	if len(fp.Classification.Reasons) > 0 {
		sb.WriteString("\n#### Classification reasons\n\n")
		for _, r := range fp.Classification.Reasons {
			sb.WriteString(fmt.Sprintf("- %s\n", r))
		}
	}

	// Schema table.
	if len(fp.SchemaFields) > 0 {
		sb.WriteString("\n#### JSON schema\n\n")
		sb.WriteString("| JSON path | Types | Classification |\n")
		sb.WriteString("|---|---|---|\n")
		for _, f := range fp.SchemaFields {
			types := strings.Join(f.ObservedTypes, ", ")
			cls := string(f.Classification)
			if cls == "" {
				cls = "-"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", f.Path, types, cls))
		}
	}

	sb.WriteString("\n")
}

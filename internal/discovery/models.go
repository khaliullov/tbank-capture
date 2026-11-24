// Package discovery implements endpoint fingerprinting, JSON schema analysis,
// classification, and report generation for the network discovery mode.
package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// SessionID is a unique identifier for a discovery session.
type SessionID string

// NewSessionID generates a collision-resistant SessionID combining a UTC timestamp
// with a cryptographic random hex suffix, preserving readable filenames.
func NewSessionID() SessionID {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return SessionID(fmt.Sprintf("sess-%s-%s",
		time.Now().UTC().Format("20060102T150405Z"),
		hex.EncodeToString(b[:]),
	))
}

// FingerprintID is a stable identifier for an endpoint family.
type FingerprintID string

// Category describes the inferred purpose of an endpoint.
type Category string

const (
	CategoryAccounts     Category = "accounts"
	CategoryCards        Category = "cards"
	CategoryBalances     Category = "balances"
	CategoryTransactions Category = "transactions"
	CategoryPayments     Category = "payments"
	CategoryTransfers    Category = "transfers"
	CategoryStatements   Category = "statements"
	CategoryUnknown      Category = "unknown"
)

// JSONKind represents a JSON top-level type.
type JSONKind string

const (
	JSONKindObject  JSONKind = "object"
	JSONKindArray   JSONKind = "array"
	JSONKindString  JSONKind = "string"
	JSONKindNumber  JSONKind = "number"
	JSONKindBool    JSONKind = "bool"
	JSONKindNull    JSONKind = "null"
	JSONKindUnknown JSONKind = "unknown"
)

// FieldClassification describes the semantic role of a JSON field.
type FieldClassification string

const (
	FieldClassNone       FieldClassification = ""
	FieldClassIdentifier FieldClassification = "identifier"
	FieldClassTimestamp  FieldClassification = "timestamp"
	FieldClassMonetary   FieldClassification = "monetary_candidate"
	FieldClassCurrency   FieldClassification = "currency_candidate"
	FieldClassStatus     FieldClassification = "status_candidate"
	FieldClassMCC        FieldClassification = "mcc_candidate"
	FieldClassMerchant   FieldClassification = "merchant_candidate"
	FieldClassCollection FieldClassification = "collection"
)

// RejectionReason specifies why a response was rejected or dropped in the capture pipeline.
type RejectionReason string

const (
	ReasonHandlerInactive         RejectionReason = "handler_inactive"
	ReasonNoActiveSession         RejectionReason = "no_active_session"
	ReasonMalformedURL            RejectionReason = "malformed_url"
	ReasonNonAllowedDomain        RejectionReason = "non_allowed_domain"
	ReasonExcludedAuthPath        RejectionReason = "excluded_auth_path"
	ReasonUnsupportedResourceType RejectionReason = "unsupported_resource_type"
	ReasonUnsupportedContentType  RejectionReason = "unsupported_content_type"
	ReasonCredentialDetected      RejectionReason = "credential_detected"
	ReasonBodyTooLarge            RejectionReason = "body_too_large"
	ReasonBodyReadError           RejectionReason = "body_read_error"
	ReasonQueueFull               RejectionReason = "queue_full"
	ReasonSuccessfullyEnqueued    RejectionReason = "successfully_enqueued"
	ReasonSuccessfullyProcessed   RejectionReason = "successfully_processed"
	ReasonProcessingFailed        RejectionReason = "processing_failed"
)

// HostnameStats maintains safe aggregate telemetry for an observed hostname.
// Query parameters, credentials, and sensitive headers are never stored.
type HostnameStats struct {
	Hostname     string         `json:"hostname"`
	TotalCount   int            `json:"total_count"`
	Allowed      bool           `json:"allowed"`
	ResourceDist map[string]int `json:"resource_dist"`
	ContentDist  map[string]int `json:"content_dist"`
	StatusDist   map[int]int    `json:"status_dist"`
}

// DiagnosticsSnapshot provides thread-safe runtime telemetry for status reporting.
type DiagnosticsSnapshot struct {
	TotalObserved       int                     `json:"total_observed"`
	UniqueHostnames     int                     `json:"unique_hostnames"`
	Hostnames           []HostnameStats         `json:"hostnames"`
	ResourceDist        map[string]int          `json:"resource_dist"`
	ContentDist         map[string]int          `json:"content_dist"`
	StatusDist          map[int]int             `json:"status_dist"`
	Rejections          map[RejectionReason]int `json:"rejections"`
	Eligible            int                     `json:"eligible"`
	Enqueued            int                     `json:"enqueued"`
	QueueOverflow       int                     `json:"queue_overflow"`
	Processed           int                     `json:"processed"`
	ProcessingFailed    int                     `json:"processing_failed"`
	UniqueFingerprints  int                     `json:"unique_fingerprints"`
	HasEligibleEnqueued bool                    `json:"has_eligible_enqueued"`
}

// FieldSchema describes the structure of a single JSON field across observations.
type FieldSchema struct {
	Path           string              `json:"path"`
	ObservedTypes  []string            `json:"observed_types"`
	Count          int                 `json:"count"`
	Optional       bool                `json:"optional"`
	InArray        bool                `json:"in_array"`
	Nested         bool                `json:"nested"`
	Classification FieldClassification `json:"classification,omitempty"`
}

// StatusDist maps HTTP status codes to observation counts.
type StatusDist map[int]int

// EndpointFingerprint aggregates metadata about a family of structurally similar responses.
type EndpointFingerprint struct {
	ID              FingerprintID  `json:"id"`
	SessionID       SessionID      `json:"session_id"`
	Method          string         `json:"method"`
	NormalizedPath  string         `json:"normalized_path"`
	ExampleURL      string         `json:"example_url"`
	ContentType     string         `json:"content_type"`
	ResourceType    string         `json:"resource_type"`
	TopLevelKind    JSONKind       `json:"top_level_kind"`
	StructureHash   string         `json:"structure_hash"`
	SchemaFields    []FieldSchema  `json:"schema_fields"`
	StatusDist      StatusDist     `json:"status_dist"`
	Observations    int            `json:"observations"`
	UniqueBodyCount int            `json:"unique_body_count"`
	TotalBytes      int64          `json:"total_bytes"`
	MaxResponseSize int64          `json:"max_response_size"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	IsPaginated     bool           `json:"is_paginated"`
	HasDateParams   bool           `json:"has_date_params"`
	ReturnsList     bool           `json:"returns_list"`
	Classification  Classification `json:"classification"`
	Sanitized       bool           `json:"sanitized,omitempty"`
	CaptureWarnings []string       `json:"capture_warnings,omitempty"`
}

// Classification is the output of the scoring classifier.
type Classification struct {
	Category   Category `json:"category"`
	Confidence float64  `json:"confidence"`
	Score      float64  `json:"score"`
	Reasons    []string `json:"reasons"`
}

// CaptureJob is a unit of work for the capture worker.
type CaptureJob struct {
	SessionID       SessionID
	Method          string
	URL             string
	Status          int
	ContentType     string
	ResourceType    string
	Body            []byte // nil if metadata-only
	BodySize        int64  // sanitized body size (or raw size if not sanitized)
	RawBodySize     int64  // original un-sanitized response body size
	BodyError       string // set if body retrieval failed
	HasDateParam    bool
	Sanitized       bool      // true if credentials were stripped from body
	SanitizedFields []string  // names of sanitized sensitive fields (no values)
	CapturedAt      time.Time // timestamp when event was captured

	// Barrier coordination
	IsBarrier   bool
	BarrierDone chan struct{}
}

// SessionState indicates the lifecycle phase of a discovery session.
type SessionState string

const (
	SessionStateActive   SessionState = "active"
	SessionStateStopping SessionState = "stopping"
	SessionStateStopped  SessionState = "stopped"
)

// Session describes a single discovery session.
type Session struct {
	ID        SessionID    `json:"id"`
	StartedAt time.Time    `json:"started_at"`
	StoppedAt time.Time    `json:"stopped_at,omitempty"`
	State     SessionState `json:"state"`
	Active    bool         `json:"active"`
}

// Metrics holds unified counters for discovery runtime telemetry.
//
// Invariants:
//
//	Observed == Filtered + Eligible
//	Eligible == Enqueued + QueueOverflow
//	Enqueued == Processed + DroppedInQueue
//	Dropped == QueueOverflow + DroppedInQueue
//	Observed == Filtered + Processed + Dropped
type Metrics struct {
	Observed              int `json:"observed"`
	Filtered              int `json:"filtered"`
	Eligible              int `json:"eligible"`
	Enqueued              int `json:"enqueued"`
	Processed             int `json:"processed"`
	Dropped               int `json:"dropped"`
	CaptureFailed         int `json:"capture_failed"`
	QueueOverflow         int `json:"queue_overflow"`
	UniqueFingerprints    int `json:"unique_fingerprints"`
	TransactionCandidates int `json:"transaction_candidates"`
	AccountCandidates     int `json:"account_candidates"`
	CardCandidates        int `json:"card_candidates"`
	BalanceCandidates     int `json:"balance_candidates"`
	PaymentCandidates     int `json:"payment_candidates"`
	TransferCandidates    int `json:"transfer_candidates"`
	StatementCandidates   int `json:"statement_candidates"`

	// Legacy aliases for backward compatibility with older consumers
	TotalObserved     int `json:"total_observed"`
	EligibleResponses int `json:"eligible_responses"`
	IgnoredResponses  int `json:"ignored_responses"`
	CaptureFailures   int `json:"capture_failures"`
	QueueOverflows    int `json:"queue_overflows"`
}

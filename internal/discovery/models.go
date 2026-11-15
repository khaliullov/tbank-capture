// Package discovery implements endpoint fingerprinting, JSON schema analysis,
// classification, and report generation for the network discovery mode.
package discovery

import "time"

// SessionID is a unique identifier for a discovery session.
type SessionID string

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
	FieldClassStatus     FieldClassification = "status_candidate"
	FieldClassMCC        FieldClassification = "mcc_candidate"
	FieldClassMerchant   FieldClassification = "merchant_candidate"
	FieldClassCollection FieldClassification = "collection"
)

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
	SessionID    SessionID
	Method       string
	URL          string
	Status       int
	ContentType  string
	ResourceType string
	Body         []byte // nil if metadata-only
	BodySize     int64
	BodyError    string // set if body retrieval failed
	HasDateParam bool
}

// Session describes a single discovery session.
type Session struct {
	ID        SessionID `json:"id"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at,omitempty"`
	Active    bool      `json:"active"`
}

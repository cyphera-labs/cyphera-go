// Package ops provides operational concerns for the Cyphera SDK: audit logging,
// policy enforcement, and structured observability.
//
// Audit logging is optional but first-class. Every SDK operation generates an
// Event; whether it is logged depends on whether a Logger is configured.
// In regulated environments (finance, healthcare), every encrypt/decrypt operation
// must be attributable — the Event struct is designed for that.
package ops

import (
	"context"
	"time"
)

// OperationType identifies what kind of protection operation occurred.
type OperationType string

const (
	// OperationEncrypt indicates a format-preserving or AES encryption operation.
	OperationEncrypt OperationType = "encrypt"
	// OperationDecrypt indicates a decryption operation.
	OperationDecrypt OperationType = "decrypt"
	// OperationMask indicates a masking (irreversible redaction) operation.
	OperationMask OperationType = "mask"
	// OperationHash indicates a hashing (irreversible tokenization) operation.
	OperationHash OperationType = "hash"
	// OperationProtect indicates a generic protect operation (engine chosen by policy).
	OperationProtect OperationType = "protect"
	// OperationUnprotect indicates a generic unprotect operation.
	OperationUnprotect OperationType = "unprotect"
)

// Event is an audit record emitted for every Cyphera SDK operation.
// It contains no plaintext, ciphertext, or key material — only metadata.
type Event struct {
	// Operation is the type of operation performed.
	Operation OperationType

	// Domain is the domain name used for this operation, e.g. "ssn", "pan".
	Domain string

	// KeyRef is the logical key reference used, e.g. "customer-primary".
	// Empty for keyless operations (masking, unkeyed hashing).
	KeyRef string

	// KeyVersion is the resolved key version used for this operation.
	// 0 if no key was involved.
	KeyVersion int

	// Engine is the name of the protection engine used, e.g. "adf1", "mask".
	Engine string

	// Success reports whether the operation completed without error.
	Success bool

	// Error is the error message if Success is false. Empty on success.
	Error string

	// Timestamp is when the operation occurred.
	Timestamp time.Time

	// Context is caller-provided metadata attached to the request.
	// Typical keys: "user", "service", "reason", "request_id".
	// Never include plaintext or sensitive data here.
	Context map[string]string
}

// Logger receives audit events from the Cyphera SDK.
// Implementations must be safe for concurrent use.
type Logger interface {
	// Log records an audit event. The context.Context carries request-scoped
	// values (e.g. trace IDs) that the logger may include in the record.
	// Log must not block the calling goroutine for an extended period.
	Log(ctx context.Context, ev Event) error
}

// Package keys defines the key management abstractions for Cyphera.
//
// Key management is the hard part of any encryption system. This package
// provides a pluggable Provider interface that separates key resolution from
// the crypto operations that use keys.
//
// The Provider interface is intentionally minimal: two methods, one for
// getting the active key (for encryption) and one for getting a specific
// version (for decryption of older ciphertext).
//
// Built-in providers cover development and simple production scenarios:
//   - MemoryProvider: in-memory records, ideal for testing
//   - EnvProvider: keys from environment variables
//   - FileProvider: keys from a local file
//
// For production deployments, KMS and HSM providers (AWS KMS, GCP KMS,
// HashiCorp Vault Transit, PKCS#11) will be provided as separate packages.
package keys

import (
	"context"
	"time"
)

// Status represents the lifecycle state of a key version.
type Status string

const (
	// StatusActive means the key version is valid for both encryption and decryption.
	StatusActive Status = "active"

	// StatusDeprecated means the key version is valid for decryption only.
	// New encryption with a deprecated key is rejected when
	// Policy.RejectDeprecatedForEncrypt is true.
	StatusDeprecated Status = "deprecated"

	// StatusDisabled means the key version is not valid for any operation.
	StatusDisabled Status = "disabled"
)

// Record holds all information about a specific key version.
type Record struct {
	// Ref is the logical name used to look up this key, e.g. "customer-primary".
	Ref string

	// Version is the monotonically increasing version number for this key ref.
	// Higher versions are preferred for new encryption.
	Version int

	// Status is the current lifecycle state of this key version.
	Status Status

	// Algorithm is a hint for which engine this key is intended for.
	// Examples: "adf1", "ff1", "ff3", "aes-256-gcm".
	// This is advisory — the domain/engine selection governs actual usage.
	Algorithm string

	// Material is the raw key bytes. Treat this field as sensitive.
	// In memory it should be zeroed when no longer needed.
	Material []byte

	// Tweak is the per-key default tweak for FPE operations.
	// Individual operations may override this with a per-call tweak.
	Tweak []byte

	// Metadata is arbitrary key-value data attached to this key version
	// for audit and governance purposes. It must not contain plaintext or key material.
	Metadata map[string]string

	// CreatedAt is when this key version was created.
	CreatedAt time.Time
}

// Provider resolves key references to key material.
//
// Implementations must be safe for concurrent use.
type Provider interface {
	// Resolve returns the highest-version active Record for the given ref.
	// This is the key used for new encryption operations.
	// Returns an error if the ref is not found or has no active versions.
	Resolve(ctx context.Context, ref string) (Record, error)

	// ResolveVersion returns the Record for a specific ref and version number.
	// This is used for decryption, where the version is known from the request context.
	// Returns an error if the ref+version combination does not exist or is disabled.
	ResolveVersion(ctx context.Context, ref string, version int) (Record, error)
}

// ErrKeyNotFound is returned when a key reference cannot be resolved.
type ErrKeyNotFound struct {
	Ref     string
	Version int // 0 means any version was requested
}

func (e *ErrKeyNotFound) Error() string {
	if e.Version == 0 {
		return "keys: key not found: " + e.Ref
	}
	return "keys: key not found: " + e.Ref + " version " + itoa(e.Version)
}

// ErrKeyDisabled is returned when the requested key version has StatusDisabled.
type ErrKeyDisabled struct {
	Ref     string
	Version int
}

func (e *ErrKeyDisabled) Error() string {
	return "keys: key is disabled: " + e.Ref + " version " + itoa(e.Version)
}

// ErrNoActiveKey is returned when a ref exists but has no active version.
type ErrNoActiveKey struct {
	Ref string
}

func (e *ErrNoActiveKey) Error() string {
	return "keys: no active version for key: " + e.Ref
}

// itoa converts an int to a decimal string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Package hash implements the Hash protection engine — an irreversible,
// deterministic tokenization engine for deduplication, analytics joins,
// and indexing without exposing PII.
//
// Unlike encryption, hashing is one-way: the original value cannot be recovered
// from the hash. But unlike random tokens, keyed hashing is deterministic:
// the same input always produces the same output under the same key.
// This makes it suitable for:
//   - Deduplication: detect duplicate SSNs without storing them
//   - Analytics joins: link records across services using the token
//   - Indexing: build a lookup index on hashed values
//
// Two algorithms are supported:
//   - HMAC-SHA256 (recommended): keyed, requires a key — output is binding to the key
//   - SHA-256 (unkeyed): deterministic without a key — use only when a key is unavailable
//
// This package satisfies the engine.Protector interface.
// Calling Unprotect on a Hash engine always returns ErrIrreversible.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "hash"
	engineType = "hash"

	// AlgorithmHMACSHA256 is the recommended keyed algorithm.
	AlgorithmHMACSHA256 = "hmac-sha256"
	// AlgorithmSHA256 is the unkeyed fallback.
	AlgorithmSHA256 = "sha256"
)

// ErrKeyRequired is returned when HMAC-SHA256 is requested but no key is provided.
var ErrKeyRequired = errors.New("hash: HMAC-SHA256 requires a key")

// Engine is the Hash engine. Safe for concurrent use.
type Engine struct {
	defaultAlgorithm string
}

// New returns a Hash Engine defaulting to HMAC-SHA256.
func New() *Engine {
	return &Engine{defaultAlgorithm: AlgorithmHMACSHA256}
}

// NewWithAlgorithm returns a Hash Engine with the specified default algorithm.
func NewWithAlgorithm(algorithm string) *Engine {
	return &Engine{defaultAlgorithm: algorithm}
}

// HMAC computes an HMAC-SHA256 of input using key and returns a hex-encoded digest.
func HMAC(input string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// SHA256Hash computes a SHA-256 hash of input and returns a hex-encoded digest.
func SHA256Hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// Name returns "hash".
func (e *Engine) Name() string { return engineName }

// Type returns "hash".
func (e *Engine) Type() string { return engineType }

// IsReversible returns false — hashing is irreversible.
func (e *Engine) IsReversible() bool { return false }

// Protect applies the hash algorithm specified in params.Algorithm (or the engine default).
// For HMAC-SHA256, params.Key must be provided.
func (e *Engine) Protect(plaintext string, params engine.Params) (string, error) {
	algorithm := params.Algorithm
	if algorithm == "" {
		algorithm = e.defaultAlgorithm
	}

	switch algorithm {
	case AlgorithmHMACSHA256:
		if len(params.Key) == 0 {
			return "", ErrKeyRequired
		}
		return HMAC(plaintext, params.Key), nil
	case AlgorithmSHA256:
		return SHA256Hash(plaintext), nil
	default:
		return "", errors.New("hash: unknown algorithm: " + algorithm)
	}
}

// Unprotect always returns ErrIrreversible — hashes cannot be reversed.
func (e *Engine) Unprotect(_ string, _ engine.Params) (string, error) {
	return "", &engine.ErrIrreversible{EngineName: engineName}
}

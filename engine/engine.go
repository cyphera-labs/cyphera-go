// Package engine defines the common interfaces implemented by all Cyphera protection engines.
//
// Cyphera ships the following protection engines:
//   - FPE engines (FF1, FF3-1): reversible, format-preserving, NIST SP 800-38G
//   - AES-GCM: reversible, non-format-preserving general encryption
//   - Mask: irreversible pattern-based redaction
//   - Hash: irreversible deterministic tokenization
//
// The Engine interface hierarchy is:
//
//	Engine (base: Name, Type, IsReversible)
//	  └── Encryptor (adds Encrypt/Decrypt — FPE and AES engines)
//	  └── Protector (adds Protect — all engines including irreversible)
//
// Application code should not select engines directly. The domain/policy layer
// selects the appropriate engine based on configuration.
package engine

import (
	"github.com/cyphera-labs/cyphera-go/alphabet"
)

// Engine is the base interface all protection engines implement.
type Engine interface {
	// Name returns the unique identifier for this engine (e.g. "adf1", "ff1", "mask").
	Name() string

	// Type returns the broad category: "fpe", "aes", "mask", or "hash".
	Type() string

	// IsReversible reports whether the engine can decrypt its own output.
	// FPE and AES engines return true; Mask and Hash engines return false.
	IsReversible() bool
}

// Encryptor is implemented by reversible engines (FPE and AES).
// These engines can both encrypt and decrypt.
type Encryptor interface {
	Engine

	// Encrypt protects plaintext using the provided key and tweak.
	// For FPE engines the output preserves the format of the input.
	Encrypt(plaintext string, key, tweak []byte) (string, error)

	// Decrypt reverses encryption to recover the original plaintext.
	Decrypt(ciphertext string, key, tweak []byte) (string, error)
}

// Protector is the broader interface satisfied by all engines, including irreversible ones.
// It provides a uniform protect/unprotect API that the SDK dispatches through.
type Protector interface {
	Engine

	// Protect applies the engine's protection operation to plaintext.
	// For reversible engines this is equivalent to Encrypt.
	// For irreversible engines (Mask, Hash) this is a one-way transformation.
	Protect(plaintext string, params Params) (string, error)

	// Unprotect reverses a protection operation.
	// Returns ErrIrreversible if the engine does not support reversal.
	Unprotect(protected string, params Params) (string, error)
}

// Params carries engine-specific configuration for a single operation.
// Not all fields are used by every engine — see individual engine docs.
type Params struct {
	// Key is the raw key material for this operation.
	Key []byte

	// Tweak is the per-operation tweak (context) for FPE engines.
	// A nil tweak is valid — the engine will use its default.
	Tweak []byte

	// Alphabet restricts the character set for FPE operations.
	// If nil the engine uses its configured default alphabet.
	Alphabet *alphabet.Alphabet

	// Pattern specifies the masking strategy for the Mask engine.
	// Examples: "last_4", "first_6", "email", "full".
	Pattern string

	// MaskChar is the replacement character used by the Mask engine.
	// Defaults to '*' if zero.
	MaskChar rune

	// Algorithm specifies the sub-algorithm for engines that support multiple.
	// For Hash: "hmac-sha256", "sha256". For AES: "aes-256-gcm".
	Algorithm string
}

// ErrIrreversible is returned when Unprotect is called on an irreversible engine
// such as Mask or Hash.
type ErrIrreversible struct {
	EngineName string
}

func (e *ErrIrreversible) Error() string {
	return "engine " + e.EngineName + " is irreversible: unprotect is not supported"
}

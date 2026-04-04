// Package ff1 implements the FF1 format-preserving encryption algorithm
// as specified in NIST SP 800-38G and its revision.
//
// FF1 uses a balanced Feistel network with an AES-CBC-based pseudorandom function.
// It is the primary NIST-standardized FPE algorithm and is required in many
// regulated environments (PCI-DSS, HIPAA).
//
// This package satisfies the engine.Encryptor and engine.Protector interfaces.
//
// Usage (primitive face):
//
//	cipher, err := ff1.NewCipher(10, key, tweak)
//	ct, err := cipher.Encrypt("123456789", nil)
//	pt, err := cipher.Decrypt(ct, nil)
//
// For production use, prefer the SDK face via cyphera.Client.
package ff1

import (
	"errors"

	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "ff1"
	engineType = "fpe"

	// MinLength is the minimum plaintext length supported by FF1.
	MinLength = 2
	// MaxLength is the maximum plaintext length supported by FF1.
	MaxLength = 1 << 32

	// MinKeySize is the minimum key size in bytes (128-bit).
	MinKeySize = 16
	// MaxKeySize is the maximum key size in bytes (256-bit).
	MaxKeySize = 32
)

// ErrInvalidKey is returned when the key size is not 16, 24, or 32 bytes.
var ErrInvalidKey = errors.New("ff1: key must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)")

// ErrInputTooShort is returned when the plaintext is shorter than MinLength.
var ErrInputTooShort = errors.New("ff1: input must be at least 2 characters")

// ErrRadixTooSmall is returned when radix is less than 2.
var ErrRadixTooSmall = errors.New("ff1: radix must be at least 2")

// Cipher is an FF1 cipher instance for a specific radix and key/tweak combination.
// Create one with NewCipher and reuse it across operations.
type Cipher struct {
	radix int
	key   []byte
	tweak []byte
}

// NewCipher creates a new FF1 Cipher with the given radix, key, and optional default tweak.
//
// radix must be in [2, 2^16). key must be 16, 24, or 32 bytes.
// The tweak can be nil or empty; individual operations can supply per-call tweaks.
func NewCipher(radix int, key, tweak []byte) (*Cipher, error) {
	if radix < 2 {
		return nil, ErrRadixTooSmall
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKey
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	var tweakCopy []byte
	if len(tweak) > 0 {
		tweakCopy = make([]byte, len(tweak))
		copy(tweakCopy, tweak)
	}

	return &Cipher{
		radix: radix,
		key:   keyCopy,
		tweak: tweakCopy,
	}, nil
}

// Encrypt encrypts plaintext using FF1. The per-call tweak overrides the default;
// pass nil to use the tweak provided to NewCipher.
//
// Input must consist entirely of characters within the radix (0 to radix-1 mapped to digits).
// For alphabetic inputs use EncryptWithAlphabet.
func (c *Cipher) Encrypt(plaintext string, tweak []byte) (string, error) {
	return "", errors.New("ff1: Encrypt not yet implemented")
}

// Decrypt decrypts ciphertext produced by Encrypt. The per-call tweak must match
// the one used during encryption.
func (c *Cipher) Decrypt(ciphertext string, tweak []byte) (string, error) {
	return "", errors.New("ff1: Decrypt not yet implemented")
}

// Radix returns the radix this cipher was initialized with.
func (c *Cipher) Radix() int {
	return c.radix
}

// Engine interface implementations — allows Cipher to be used as engine.Encryptor.

// Name returns "ff1".
func (c *Cipher) Name() string { return engineName }

// Type returns "fpe".
func (c *Cipher) Type() string { return engineType }

// IsReversible returns true — FF1 is a symmetric cipher.
func (c *Cipher) IsReversible() bool { return true }

// Protect implements engine.Protector. It encrypts using the key and tweak in params.
func (c *Cipher) Protect(plaintext string, params engine.Params) (string, error) {
	cipher, err := NewCipher(c.radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return cipher.Encrypt(plaintext, nil)
}

// Unprotect implements engine.Protector. It decrypts using the key and tweak in params.
func (c *Cipher) Unprotect(protected string, params engine.Params) (string, error) {
	cipher, err := NewCipher(c.radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return cipher.Decrypt(protected, nil)
}

// New creates a default FF1 engine with radix 10 for use in engine registries.
// The actual key and tweak are provided per-operation via engine.Params.
func New() *Cipher {
	return &Cipher{radix: 10}
}

// NewWithRadix creates a default FF1 engine with the specified radix.
func NewWithRadix(radix int) (*Cipher, error) {
	if radix < 2 {
		return nil, ErrRadixTooSmall
	}
	return &Cipher{radix: radix}, nil
}

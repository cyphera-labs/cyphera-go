// Package son1 implements the SoN1 (Swap-or-Not 1) format-preserving encryption algorithm.
//
// SoN1 is a Cyphera Labs original based on the Hoang-Morris-Rogaway (2012) Swap-or-Not
// shuffle construction. It is patent-clean and heading toward IETF standardization.
//
// SoN1 is best suited for small or irregular domains where Feistel networks are less
// efficient — for example, short strings, non-power-of-two domain sizes, or cases
// where the input length varies widely.
//
// For large, regular domains (digits, alphanumeric) use ADF1 instead.
//
// This package satisfies the engine.Encryptor and engine.Protector interfaces.
package son1

import (
	"errors"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "son1"
	engineType = "fpe"
)

// ErrInvalidKey is returned for unsupported key lengths.
var ErrInvalidKey = errors.New("son1: key must be 16, 24, or 32 bytes")

// ErrNilAlphabet is returned when no alphabet is provided.
var ErrNilAlphabet = errors.New("son1: alphabet must not be nil")

// Engine is the SoN1 engine. It holds no mutable state and is safe for concurrent use.
type Engine struct{}

// New returns a new SoN1 Engine.
func New() *Engine {
	return &Engine{}
}

// EncryptSoN1 encrypts plaintext using the SoN1 algorithm.
// key must be 16, 24, or 32 bytes. tweak may be nil.
// alpha defines the symbol space; all characters in plaintext must be in the alphabet.
func EncryptSoN1(plaintext string, key, tweak []byte, alpha *alphabet.Alphabet) (string, error) {
	if alpha == nil {
		return "", ErrNilAlphabet
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKey
	}
	return "", errors.New("son1: EncryptSoN1 not yet implemented")
}

// DecryptSoN1 decrypts ciphertext produced by EncryptSoN1.
func DecryptSoN1(ciphertext string, key, tweak []byte, alpha *alphabet.Alphabet) (string, error) {
	if alpha == nil {
		return "", ErrNilAlphabet
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKey
	}
	return "", errors.New("son1: DecryptSoN1 not yet implemented")
}

// Encrypt implements engine.Encryptor using the default digits alphabet.
func (e *Engine) Encrypt(plaintext string, key, tweak []byte) (string, error) {
	return EncryptSoN1(plaintext, key, tweak, alphabet.DigitsAlphabet)
}

// Decrypt implements engine.Encryptor.
func (e *Engine) Decrypt(ciphertext string, key, tweak []byte) (string, error) {
	return DecryptSoN1(ciphertext, key, tweak, alphabet.DigitsAlphabet)
}

// Name returns "son1".
func (e *Engine) Name() string { return engineName }

// Type returns "fpe".
func (e *Engine) Type() string { return engineType }

// IsReversible returns true.
func (e *Engine) IsReversible() bool { return true }

// Protect implements engine.Protector.
func (e *Engine) Protect(plaintext string, params engine.Params) (string, error) {
	alpha := params.Alphabet
	if alpha == nil {
		alpha = alphabet.DigitsAlphabet
	}
	return EncryptSoN1(plaintext, params.Key, params.Tweak, alpha)
}

// Unprotect implements engine.Protector.
func (e *Engine) Unprotect(protected string, params engine.Params) (string, error) {
	alpha := params.Alphabet
	if alpha == nil {
		alpha = alphabet.DigitsAlphabet
	}
	return DecryptSoN1(protected, params.Key, params.Tweak, alpha)
}

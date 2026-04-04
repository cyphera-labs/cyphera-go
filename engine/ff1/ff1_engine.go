package ff1

import "github.com/cyphera-labs/cyphera-go/engine"

// New returns an FF1 engine with default radix 10.
// The key and radix are provided per-operation via engine.Params when used through
// the Protector interface. Use NewCipher directly for the primitive API.
func New() *Cipher {
	return &Cipher{radix: 10}
}

// Name returns "ff1".
func (c *Cipher) Name() string { return "ff1" }

// Type returns "fpe".
func (c *Cipher) Type() string { return "fpe" }

// IsReversible returns true.
func (c *Cipher) IsReversible() bool { return true }

// Protect implements engine.Protector.
// Uses params.Alphabet.Radix() if set, otherwise falls back to the cipher's configured radix.
// params.Key and params.Tweak are used to derive a fresh cipher for this operation.
func (c *Cipher) Protect(plaintext string, params engine.Params) (string, error) {
	radix := c.radix
	if params.Alphabet != nil {
		radix = params.Alphabet.Radix()
	}
	op, err := NewCipher(radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return op.Encrypt(plaintext, nil)
}

// Unprotect implements engine.Protector.
func (c *Cipher) Unprotect(protected string, params engine.Params) (string, error) {
	radix := c.radix
	if params.Alphabet != nil {
		radix = params.Alphabet.Radix()
	}
	op, err := NewCipher(radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return op.Decrypt(protected, nil)
}

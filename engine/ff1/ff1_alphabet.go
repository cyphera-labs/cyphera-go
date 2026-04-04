package ff1

import (
	"fmt"

	"github.com/cyphera-labs/cyphera-go/alphabet"
)

// EncryptStringWithAlphabet encrypts only chars in 'a'; others are left intact.
// This provides pass-through behavior where punctuation, spaces, and other
// non-alphabet characters remain in their original positions untouched.
//
// Example:
//
//	input: "4111-1111-1111-1111" with digits alphabet
//	output: "8239-4456-7891-2345" (dashes preserved)
func (c *Cipher) EncryptStringWithAlphabet(s string, tweak []byte, a *alphabet.Alphabet) (string, error) {
	digits, pos, orig := a.Encode(s)

	if err := alphabet.EnsureDomain(a.Radix(), len(digits)); err != nil {
		return "", fmt.Errorf("alphabet domain validation failed: %w", err)
	}

	if len(digits) == 0 {
		return s, nil
	}

	alphaCipher, err := NewCipher(a.Radix(), c.key, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create alphabet cipher: %w", err)
	}

	ctDigits, err := alphaCipher.ff1Encrypt(digits, tweak)
	if err != nil {
		return "", fmt.Errorf("ff1 encrypt failed: %w", err)
	}

	return a.Decode(ctDigits, pos, orig)
}

// DecryptStringWithAlphabet decrypts only chars in 'a'; others are left intact.
// This is the inverse operation of EncryptStringWithAlphabet.
func (c *Cipher) DecryptStringWithAlphabet(s string, tweak []byte, a *alphabet.Alphabet) (string, error) {
	digits, pos, orig := a.Encode(s)

	if err := alphabet.EnsureDomain(a.Radix(), len(digits)); err != nil {
		return "", fmt.Errorf("alphabet domain validation failed: %w", err)
	}

	if len(digits) == 0 {
		return s, nil
	}

	alphaCipher, err := NewCipher(a.Radix(), c.key, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create alphabet cipher: %w", err)
	}

	ptDigits, err := alphaCipher.ff1Decrypt(digits, tweak)
	if err != nil {
		return "", fmt.Errorf("ff1 decrypt failed: %w", err)
	}

	return a.Decode(ptDigits, pos, orig)
}

// EncryptDigitsOnly encrypts only 0-9 digits, preserving punctuation.
func (c *Cipher) EncryptDigitsOnly(s string, tweak []byte) (string, error) {
	return c.EncryptStringWithAlphabet(s, tweak, alphabet.DigitsAlphabet)
}

// DecryptDigitsOnly decrypts only 0-9 digits, preserving punctuation.
func (c *Cipher) DecryptDigitsOnly(s string, tweak []byte) (string, error) {
	return c.DecryptStringWithAlphabet(s, tweak, alphabet.DigitsAlphabet)
}

// EncryptAlphanumeric encrypts letters and digits, preserving punctuation.
func (c *Cipher) EncryptAlphanumeric(s string, tweak []byte) (string, error) {
	return c.EncryptStringWithAlphabet(s, tweak, alphabet.AlphanumericAlphabet)
}

// DecryptAlphanumeric decrypts letters and digits, preserving punctuation.
func (c *Cipher) DecryptAlphanumeric(s string, tweak []byte) (string, error) {
	return c.DecryptStringWithAlphabet(s, tweak, alphabet.AlphanumericAlphabet)
}

// EncryptBase36 encrypts using base36 (0-9, A-Z), preserving punctuation.
func (c *Cipher) EncryptBase36(s string, tweak []byte) (string, error) {
	return c.EncryptStringWithAlphabet(s, tweak, alphabet.Base36Alphabet)
}

// DecryptBase36 decrypts using base36 (0-9, A-Z), preserving punctuation.
func (c *Cipher) DecryptBase36(s string, tweak []byte) (string, error) {
	return c.DecryptStringWithAlphabet(s, tweak, alphabet.Base36Alphabet)
}

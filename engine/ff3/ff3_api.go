package ff3

import (
	"fmt"

	"github.com/cyphera-labs/cyphera-go/engine"
)

// FF3 is the public string API wrapping FF3Cipher with alphabet support.
type FF3 struct {
	core  *FF3Cipher
	spec  AlphabetSpec
	alpha []rune
	index map[rune]int
}

// FromSpec creates a new FF3-1 cipher from an alphabet specification.
// key must be 16, 24, or 32 bytes. tweak must be exactly 8 bytes.
func FromSpec(key, tweak []byte, spec AlphabetSpec) (*FF3, error) {
	alphaRunes := []rune(spec.Charset)
	if len(alphaRunes) < 2 {
		return nil, fmt.Errorf("alphabet must have >=2 chars")
	}
	radix := len(alphaRunes)

	core, err := NewFF3Cipher(radix, key, tweak)
	if err != nil {
		return nil, err
	}

	idx := make(map[rune]int, radix)
	for i, r := range alphaRunes {
		idx[r] = i
	}

	return &FF3{core: core, spec: spec, alpha: alphaRunes, index: idx}, nil
}

// Convenience constructors for standard alphabets.

func Digits(key, tweak []byte) (*FF3, error)    { return FromSpec(key, tweak, SpecDigits) }
func HexLower(key, tweak []byte) (*FF3, error)  { return FromSpec(key, tweak, SpecHexLower) }
func HexUpper(key, tweak []byte) (*FF3, error)  { return FromSpec(key, tweak, SpecHexUpper) }
func Base36Lower(key, tweak []byte) (*FF3, error) { return FromSpec(key, tweak, SpecBase36Low) }
func Base36Upper(key, tweak []byte) (*FF3, error) { return FromSpec(key, tweak, SpecBase36Up) }
func Base62(key, tweak []byte) (*FF3, error)    { return FromSpec(key, tweak, SpecBase62) }

// Backward compatibility aliases.
func Hex(key, tweak []byte) (*FF3, error)    { return HexLower(key, tweak) }
func Base36(key, tweak []byte) (*FF3, error) { return Base36Lower(key, tweak) }

func (c *FF3) toDigits(s string) ([]int, error) {
	rs := []rune(s)
	out := make([]int, len(rs))
	for i, r := range rs {
		v, ok := c.index[r]
		if !ok {
			return nil, fmt.Errorf("invalid char %q at pos %d for this alphabet", r, i)
		}
		out[i] = v
	}
	return out, nil
}

func (c *FF3) fromDigits(d []int) (string, error) {
	out := make([]rune, len(d))
	for i, v := range d {
		if v < 0 || v >= len(c.alpha) {
			return "", fmt.Errorf("digit %d out of range for radix %d", v, len(c.alpha))
		}
		out[i] = c.alpha[v]
	}
	return string(out), nil
}

// Encrypt encrypts plaintext. additionalTweak is XORed into the base tweak for domain separation.
func (c *FF3) Encrypt(plaintext string, additionalTweak []byte) (string, error) {
	nums, err := c.toDigits(plaintext)
	if err != nil {
		return "", err
	}
	n := len(nums)
	if n < c.core.GetMinLen() || n > c.core.GetMaxLen() {
		return "", fmt.Errorf("length %d out of bounds [%d,%d]", n, c.core.GetMinLen(), c.core.GetMaxLen())
	}
	out := c.core.EncryptDigits(nums, additionalTweak)
	return c.fromDigits(out)
}

// Decrypt decrypts ciphertext produced by Encrypt.
func (c *FF3) Decrypt(ciphertext string, additionalTweak []byte) (string, error) {
	nums, err := c.toDigits(ciphertext)
	if err != nil {
		return "", err
	}
	n := len(nums)
	if n < c.core.GetMinLen() || n > c.core.GetMaxLen() {
		return "", fmt.Errorf("length %d out of bounds [%d,%d]", n, c.core.GetMinLen(), c.core.GetMaxLen())
	}
	out := c.core.DecryptDigits(nums, additionalTweak)
	return c.fromDigits(out)
}

// engine.Encryptor and engine.Protector interface implementations.

// Name returns "ff3".
func (c *FF3) Name() string { return "ff3" }

// Type returns "fpe".
func (c *FF3) Type() string { return "fpe" }

// IsReversible returns true.
func (c *FF3) IsReversible() bool { return true }

// Protect implements engine.Protector — encrypts using params.Key and params.Tweak.
func (c *FF3) Protect(plaintext string, params engine.Params) (string, error) {
	f, err := FromSpec(params.Key, params.Tweak, c.spec)
	if err != nil {
		return "", err
	}
	return f.Encrypt(plaintext, nil)
}

// Unprotect implements engine.Protector — decrypts using params.Key and params.Tweak.
func (c *FF3) Unprotect(protected string, params engine.Params) (string, error) {
	f, err := FromSpec(params.Key, params.Tweak, c.spec)
	if err != nil {
		return "", err
	}
	return f.Decrypt(protected, nil)
}

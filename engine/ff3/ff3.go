// String-alphabet API over the FF3 core. See ff3_core.go for the package doc.
package ff3

import (
	"fmt"
)

// Cipher wraps FF3Cipher with alphabet-string API matching the spec contract.
type Cipher struct {
	core    *FF3Cipher
	alphabet string
	charMap map[rune]int
}

// New creates a new FF3 cipher.
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - tweak: must be exactly 8 bytes
//   - alphabet: the character set
func New(key, tweak []byte, alphabet string) (*Cipher, error) {
	if len(alphabet) < 2 {
		return nil, fmt.Errorf("alphabet must have >= 2 characters")
	}

	charMap := make(map[rune]int, len(alphabet))
	for i, c := range alphabet {
		if _, exists := charMap[c]; exists {
			return nil, fmt.Errorf("duplicate character '%c' in alphabet", c)
		}
		charMap[c] = i
	}

	core, err := NewFF3Cipher(len(alphabet), key, tweak)
	if err != nil {
		return nil, err
	}

	return &Cipher{
		core:    core,
		alphabet: alphabet,
		charMap: charMap,
	}, nil
}

// NewFF31 creates a new FF3-1 cipher (NIST SP 800-38G Rev 1).
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - tweak: must be exactly 7 bytes (56 bits)
//   - alphabet: the character set
//
// FF3-1 is FF3 with a 56-bit tweak. The tweak is expanded into the 64-bit
// form the FF3 core consumes; everything downstream is identical FF3.
func NewFF31(key, tweak []byte, alphabet string) (*Cipher, error) {
	if len(tweak) != 7 {
		return nil, fmt.Errorf("invalid tweak length: %d (expected 7)", len(tweak))
	}
	return New(key, expandFF31Tweak(tweak), alphabet)
}

// expandFF31Tweak expands the 56-bit FF3-1 tweak into the 64-bit tweak the
// FF3 round function consumes (NIST SP 800-38G Rev 1), with bytes[0:4] = T_L
// and bytes[4:8] = T_R.
func expandFF31Tweak(t []byte) []byte {
	return []byte{
		t[0], t[1], t[2], t[3] & 0xF0,
		t[4], t[5], t[6], (t[3] & 0x0F) << 4,
	}
}

// Encrypt encrypts the plaintext using FF3.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nums, err := c.toDigits(plaintext)
	if err != nil {
		return "", err
	}
	if err := c.core.checkLength(len(nums)); err != nil {
		return "", err
	}
	result := c.core.ff3Encrypt(nums, c.core.tweak)
	return c.fromDigits(result), nil
}

// Decrypt decrypts the ciphertext using FF3.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	nums, err := c.toDigits(ciphertext)
	if err != nil {
		return "", err
	}
	if err := c.core.checkLength(len(nums)); err != nil {
		return "", err
	}
	result := c.core.ff3Decrypt(nums, c.core.tweak)
	return c.fromDigits(result), nil
}

func (c *Cipher) toDigits(s string) ([]int, error) {
	digits := make([]int, 0, len(s))
	pos := 0
	for _, r := range s {
		idx, ok := c.charMap[r]
		if !ok {
			return nil, fmt.Errorf("invalid char '%c' at position %d", r, pos)
		}
		digits = append(digits, idx)
		pos++
	}
	return digits, nil
}

func (c *Cipher) fromDigits(nums []int) string {
	runes := make([]rune, len(nums))
	alpha := []rune(c.alphabet)
	for i, n := range nums {
		runes[i] = alpha[n]
	}
	return string(runes)
}

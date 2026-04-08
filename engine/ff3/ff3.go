// Package ff3 implements NIST SP 800-38G Rev 1 FF3-1 Format Preserving Encryption.
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

// Encrypt encrypts the plaintext using FF3.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nums, err := c.toDigits(plaintext)
	if err != nil {
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
	result := c.core.ff3Decrypt(nums, c.core.tweak)
	return c.fromDigits(result), nil
}

func (c *Cipher) toDigits(s string) ([]int, error) {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		idx, ok := c.charMap[r]
		if !ok {
			return nil, fmt.Errorf("invalid character '%c' not in alphabet", r)
		}
		digits = append(digits, idx)
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

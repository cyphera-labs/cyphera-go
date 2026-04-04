// Package ff3 implements the FF3-1 format-preserving encryption algorithm
// as specified in NIST SP 800-38G Revision 1.
//
// This implementation follows the same 3-file architecture used in fpe-arena:
// ff3_core.go — pure cryptographic implementation
// ff3_api.go  — string interface with alphabet support
// ff3_alphabets.go — predefined character sets
package ff3

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"
)

// FF3Cipher represents the core FF3-1 cipher implementation.
type FF3Cipher struct {
	radix  int
	aes    cipher.Block
	tweak  []byte
	minLen int
	maxLen int
}

// NewFF3Cipher creates a new FF3-1 cipher with the specified radix, key, and tweak.
//
// radix must be between 2 and 62.
// key must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256).
// tweak must be exactly 8 bytes (64 bits) per the FF3 specification.
func NewFF3Cipher(radix int, key, tweak []byte) (*FF3Cipher, error) {
	if radix < 2 || radix > 62 {
		return nil, fmt.Errorf("radix must be between 2 and 62, got %d", radix)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key length must be 16, 24, or 32 bytes, got %d", len(key))
	}
	if len(tweak) != 8 {
		return nil, fmt.Errorf("tweak must be exactly 8 bytes (64 bits) for FF3, got %d", len(tweak))
	}

	aesCipher, err := createAESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	tweakCopy := make([]byte, len(tweak))
	copy(tweakCopy, tweak)

	maxLen := 32
	if radix > 36 {
		maxLen = 56
	}

	return &FF3Cipher{
		radix:  radix,
		aes:    aesCipher,
		tweak:  tweakCopy,
		minLen: 2,
		maxLen: maxLen,
	}, nil
}

// ff3Encrypt performs the core FF3-1 encryption algorithm.
func (c *FF3Cipher) ff3Encrypt(plaintext []int, tweak []byte) []int {
	n := len(plaintext)
	u := (n + 1) / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, plaintext[:u])
	copy(B, plaintext[u:])

	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			W := c.calculateW(tweak, i, B)
			P := c.calculateP(i, W, B)
			m := c.calculateModulus(u)
			reversedA := c.reverseDigits(A)
			aNum := c.numArrayToBigInt(reversedA)
			Y := new(big.Int).Add(aNum, P)
			Y.Mod(Y, m)
			newDigits := c.bigIntToNumArray(Y, u)
			A = c.reverseDigits(newDigits)
		} else {
			W := c.calculateW(tweak, i, A)
			P := c.calculateP(i, W, A)
			m := c.calculateModulus(v)
			reversedB := c.reverseDigits(B)
			bNum := c.numArrayToBigInt(reversedB)
			Y := new(big.Int).Add(bNum, P)
			Y.Mod(Y, m)
			newDigits := c.bigIntToNumArray(Y, v)
			B = c.reverseDigits(newDigits)
		}
	}

	result := make([]int, n)
	copy(result, A)
	copy(result[u:], B)
	return result
}

// ff3Decrypt performs the core FF3-1 decryption algorithm.
func (c *FF3Cipher) ff3Decrypt(ciphertext []int, tweak []byte) []int {
	n := len(ciphertext)
	u := (n + 1) / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, ciphertext[:u])
	copy(B, ciphertext[u:])

	for i := 7; i >= 0; i-- {
		if i%2 == 0 {
			W := c.calculateW(tweak, i, B)
			P := c.calculateP(i, W, B)
			m := c.calculateModulus(u)
			reversedA := c.reverseDigits(A)
			aNum := c.numArrayToBigInt(reversedA)
			Y := new(big.Int).Sub(aNum, P)
			Y.Mod(Y, m)
			newDigits := c.bigIntToNumArray(Y, u)
			A = c.reverseDigits(newDigits)
		} else {
			W := c.calculateW(tweak, i, A)
			P := c.calculateP(i, W, A)
			m := c.calculateModulus(v)
			reversedB := c.reverseDigits(B)
			bNum := c.numArrayToBigInt(reversedB)
			Y := new(big.Int).Sub(bNum, P)
			Y.Mod(Y, m)
			newDigits := c.bigIntToNumArray(Y, v)
			B = c.reverseDigits(newDigits)
		}
	}

	result := make([]int, n)
	copy(result, A)
	copy(result[u:], B)
	return result
}

func (c *FF3Cipher) calculateW(tweak []byte, round int, _ []int) []byte {
	W := make([]byte, 4)
	if round%2 == 0 {
		copy(W, tweak[4:8])
	} else {
		copy(W, tweak[:4])
	}
	return W
}

func (c *FF3Cipher) calculateP(round int, W []byte, B []int) *big.Int {
	input := make([]byte, 16)
	copy(input[:4], W)
	input[3] ^= byte(round)

	reversedB := c.reverseDigits(B)
	bBigInt := c.numArrayToBigInt(reversedB)
	bBytes := bBigInt.Bytes()

	bPadded := make([]byte, 12)
	if len(bBytes) > 0 {
		copy(bPadded[12-len(bBytes):], bBytes)
	}
	copy(input[4:], bPadded)

	reversedInput := c.reverseBytes(input)
	aesOutput := make([]byte, 16)
	c.aes.Encrypt(aesOutput, reversedInput)
	output := c.reverseBytes(aesOutput)

	return new(big.Int).SetBytes(output)
}

func (c *FF3Cipher) calculateModulus(length int) *big.Int {
	return new(big.Int).Exp(big.NewInt(int64(c.radix)), big.NewInt(int64(length)), nil)
}

func (c *FF3Cipher) numArrayToBigInt(nums []int) *big.Int {
	result := big.NewInt(0)
	radixBig := big.NewInt(int64(c.radix))
	for _, num := range nums {
		result.Mul(result, radixBig)
		result.Add(result, big.NewInt(int64(num)))
	}
	return result
}

func (c *FF3Cipher) bigIntToNumArray(num *big.Int, length int) []int {
	result := make([]int, length)
	radixBig := big.NewInt(int64(c.radix))
	temp := new(big.Int).Set(num)
	for i := length - 1; i >= 0; i-- {
		remainder := new(big.Int)
		temp.DivMod(temp, radixBig, remainder)
		result[i] = int(remainder.Int64())
	}
	return result
}

func (c *FF3Cipher) combineTweaks(additionalTweak []byte) []byte {
	if len(additionalTweak) == 0 {
		return c.tweak
	}
	combined := make([]byte, 8)
	copy(combined, c.tweak)
	for i := 0; i < len(additionalTweak) && i < 8; i++ {
		combined[i] ^= additionalTweak[i]
	}
	return combined
}

// EncryptDigits runs core FF3-1 encryption over base-radix digits.
func (c *FF3Cipher) EncryptDigits(nums []int, additionalTweak []byte) []int {
	return c.ff3Encrypt(nums, c.combineTweaks(additionalTweak))
}

// DecryptDigits runs core FF3-1 decryption over base-radix digits.
func (c *FF3Cipher) DecryptDigits(nums []int, additionalTweak []byte) []int {
	return c.ff3Decrypt(nums, c.combineTweaks(additionalTweak))
}

// GetMinLen returns the minimum plaintext length constraint.
func (c *FF3Cipher) GetMinLen() int { return c.minLen }

// GetMaxLen returns the maximum plaintext length constraint.
func (c *FF3Cipher) GetMaxLen() int { return c.maxLen }

// createAESCipher creates an AES cipher with the FF3 byte-reversal convention
// (reversed key per the NIST spec).
func createAESCipher(key []byte) (cipher.Block, error) {
	reversedKey := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		reversedKey[i] = key[len(key)-1-i]
	}
	return aes.NewCipher(reversedKey)
}

func (c *FF3Cipher) reverseDigits(digits []int) []int {
	reversed := make([]int, len(digits))
	for i := 0; i < len(digits); i++ {
		reversed[i] = digits[len(digits)-1-i]
	}
	return reversed
}

func (c *FF3Cipher) reverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return reversed
}

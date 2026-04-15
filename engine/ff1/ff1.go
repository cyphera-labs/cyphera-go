// Package ff1 implements NIST SP 800-38G FF1 Format Preserving Encryption.
package ff1

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Cipher represents an FF1 format-preserving encryption cipher.
type Cipher struct {
	radix    int
	alphabet string
	charMap  map[rune]int
	tweak    []byte
	cipher   cipher.Block
}

// New creates a new FF1 cipher.
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - tweak: optional tweak data (can be nil/empty)
//   - alphabet: the character set (e.g. "0123456789" for digits)
func New(key, tweak []byte, alphabet string) (*Cipher, error) {
	if len(alphabet) < 2 {
		return nil, errors.New("alphabet must have >= 2 characters")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}

	// NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
	// This is single-block encryption used as a building block, not ECB mode applied to user data.
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	charMap := make(map[rune]int, len(alphabet))
	for i, c := range alphabet {
		if _, exists := charMap[c]; exists {
			return nil, fmt.Errorf("duplicate character '%c' in alphabet", c)
		}
		charMap[c] = i
	}

	tweakCopy := make([]byte, len(tweak))
	copy(tweakCopy, tweak)

	return &Cipher{
		radix:    len(alphabet),
		alphabet: alphabet,
		charMap:  charMap,
		tweak:    tweakCopy,
		cipher:   aesCipher,
	}, nil
}

// Encrypt encrypts the plaintext using FF1.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nums, err := c.toDigits(plaintext)
	if err != nil {
		return "", err
	}
	result, err := c.ff1Encrypt(nums, c.tweak)
	if err != nil {
		return "", err
	}
	return c.fromDigits(result), nil
}

// Decrypt decrypts the ciphertext using FF1.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	nums, err := c.toDigits(ciphertext)
	if err != nil {
		return "", err
	}
	result, err := c.ff1Decrypt(nums, c.tweak)
	if err != nil {
		return "", err
	}
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

// ff1Encrypt performs FF1 encryption per NIST SP 800-38G Algorithm 1.
func (c *Cipher) ff1Encrypt(plaintext []int, tweak []byte) ([]int, error) {
	n := len(plaintext)
	if n < 2 {
		return nil, errors.New("plaintext too short (min 2 characters)")
	}
	radix := c.radix

	u := n / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, plaintext[:u])
	copy(B, plaintext[u:])

	T := tweak
	if T == nil {
		T = []byte{}
	}

	b := c.computeB(v, radix)
	d := 4*((b+3)/4) + 4
	P := c.buildP(radix, u, n, len(T))

	for i := 0; i < 10; i++ {
		numB := c.numRadix(B, radix)
		numBBytes := c.bigIntToBytes(numB, b)
		Q := c.buildQ(T, i, numBBytes, b)
		R := c.prf(append(P, Q...))
		S := c.expandS(R, d)
		y := new(big.Int).SetBytes(S)

		m := u
		if i%2 == 1 {
			m = v
		}

		cVal := new(big.Int).Add(c.numRadix(A, radix), y)
		cVal.Mod(cVal, new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil))
		A, B = B, c.strRadix(cVal, radix, m)
	}

	result := make([]int, n)
	copy(result[:len(A)], A)
	copy(result[len(A):], B)
	return result, nil
}

// ff1Decrypt performs FF1 decryption per NIST SP 800-38G Algorithm 2.
func (c *Cipher) ff1Decrypt(ciphertext []int, tweak []byte) ([]int, error) {
	n := len(ciphertext)
	if n < 2 {
		return nil, errors.New("ciphertext too short (min 2 characters)")
	}
	radix := c.radix

	u := n / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, ciphertext[:u])
	copy(B, ciphertext[u:])

	T := tweak
	if T == nil {
		T = []byte{}
	}

	b := c.computeB(v, radix)
	d := 4*((b+3)/4) + 4
	P := c.buildP(radix, u, n, len(T))

	for i := 9; i >= 0; i-- {
		numA := c.numRadix(A, radix)
		numABytes := c.bigIntToBytes(numA, b)
		Q := c.buildQ(T, i, numABytes, b)
		R := c.prf(append(P, Q...))
		S := c.expandS(R, d)
		y := new(big.Int).SetBytes(S)

		m := u
		if i%2 == 1 {
			m = v
		}

		modulus := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
		cVal := new(big.Int).Sub(c.numRadix(B, radix), y)
		cVal.Mod(cVal, modulus)
		if cVal.Sign() < 0 {
			cVal.Add(cVal, modulus)
		}
		B, A = A, c.strRadix(cVal, radix, m)
	}

	result := make([]int, n)
	copy(result[:len(A)], A)
	copy(result[len(A):], B)
	return result, nil
}

func (c *Cipher) computeB(v, radix int) int {
	pow := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(v)), nil)
	pow.Sub(pow, big.NewInt(1))
	return (pow.BitLen() + 7) / 8
}

func (c *Cipher) buildP(radix, u, n, t int) []byte {
	P := make([]byte, 16)
	P[0] = 1
	P[1] = 2
	P[2] = 1
	P[3] = byte(radix >> 16)
	P[4] = byte(radix >> 8)
	P[5] = byte(radix)
	P[6] = 10
	P[7] = byte(u)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(t))
	return P
}

func (c *Cipher) buildQ(T []byte, i int, numBytes []byte, b int) []byte {
	t := len(T)
	pad := (16 - ((t + 1 + b) % 16)) % 16
	Q := make([]byte, 0, t+pad+1+b)
	Q = append(Q, T...)
	Q = append(Q, make([]byte, pad)...)
	Q = append(Q, byte(i))
	if len(numBytes) < b {
		Q = append(Q, make([]byte, b-len(numBytes))...)
	}
	start := 0
	if len(numBytes) > b {
		start = len(numBytes) - b
	}
	Q = append(Q, numBytes[start:]...)
	return Q
}

func (c *Cipher) prf(data []byte) [16]byte {
	var y [16]byte
	var tmp [16]byte
	for off := 0; off < len(data); off += 16 {
		for j := 0; j < 16; j++ {
			tmp[j] = y[j] ^ data[off+j]
		}
		c.cipher.Encrypt(y[:], tmp[:])
	}
	return y
}

func (c *Cipher) expandS(R [16]byte, d int) []byte {
	needBlocks := (d + 15) / 16
	out := make([]byte, 0, needBlocks*16)
	out = append(out, R[:]...)
	for j := 1; len(out) < needBlocks*16; j++ {
		var x [16]byte
		binary.BigEndian.PutUint64(x[8:], uint64(j))
		// XOR with R (not previous block) per NIST SP 800-38G
		for k := 0; k < 16; k++ {
			x[k] ^= R[k]
		}
		var nxt [16]byte
		c.cipher.Encrypt(nxt[:], x[:])
		out = append(out, nxt[:]...)
	}
	return out[:d]
}

func (c *Cipher) bigIntToBytes(x *big.Int, b int) []byte {
	bytes := x.Bytes()
	if len(bytes) >= b {
		return bytes[len(bytes)-b:]
	}
	result := make([]byte, b)
	copy(result[b-len(bytes):], bytes)
	return result
}

func (c *Cipher) numRadix(x []int, radix int) *big.Int {
	result := big.NewInt(0)
	base := big.NewInt(int64(radix))
	for _, digit := range x {
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(digit)))
	}
	return result
}

func (c *Cipher) strRadix(x *big.Int, radix, length int) []int {
	result := make([]int, length)
	base := big.NewInt(int64(radix))
	temp := new(big.Int).Set(x)
	for i := length - 1; i >= 0; i-- {
		remainder := new(big.Int)
		temp.DivMod(temp, base, remainder)
		result[i] = int(remainder.Int64())
	}
	return result
}

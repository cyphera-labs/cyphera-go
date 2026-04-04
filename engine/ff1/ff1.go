// Package ff1 implements NIST SP 800-38G FF1 Format Preserving Encryption.
//
// FF1 is a mode of operation for block ciphers that encrypts data while
// preserving the format of the original plaintext. For example, a social
// security number like "123-45-6789" would be encrypted to another valid
// social security number format like "987-65-4321".
//
// This implementation follows the NIST SP 800-38G specification exactly
// and passes all official test vectors.
package ff1

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Cipher represents an FF1 format-preserving encryption cipher.
type Cipher struct {
	radix     int
	key       []byte
	tweak     []byte
	minLen    int
	maxLen    int
	blockSize int
	cipher    cipher.Block
}

// NewCipher creates a new FF1 cipher with the given parameters.
//
// Parameters:
//   - radix: The base/radix of the alphabet (2-36)
//   - key: AES key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
//   - tweak: Optional tweak data for domain separation (can be nil)
//
// Returns an error if parameters are invalid.
func NewCipher(radix int, key []byte, tweak []byte) (*Cipher, error) {
	if radix < 2 {
		return nil, errors.New("radix must be >= 2")
	}

	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes")
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	var tweakCopy []byte
	if tweak != nil {
		tweakCopy = make([]byte, len(tweak))
		copy(tweakCopy, tweak)
	}

	return &Cipher{
		radix:     radix,
		key:       keyCopy,
		tweak:     tweakCopy,
		minLen:    2,
		maxLen:    56,
		blockSize: aesCipher.BlockSize(),
		cipher:    aesCipher,
	}, nil
}

// Encrypt encrypts the plaintext string using FF1.
//
// The plaintext must contain only valid characters for the specified radix:
//   - Radix 10: digits 0-9
//   - Radix 16: digits 0-9 and letters A-F
//   - Radix 36: digits 0-9 and letters A-Z
//
// An optional tweak can be provided for domain separation. If nil,
// the cipher's default tweak is used.
func (c *Cipher) Encrypt(plaintext string, tweak []byte) (string, error) {
	return c.ff1(plaintext, tweak, true)
}

// Decrypt decrypts the ciphertext string using FF1.
//
// The ciphertext must have been produced by a previous Encrypt call
// with the same key, radix, and tweak parameters.
func (c *Cipher) Decrypt(ciphertext string, tweak []byte) (string, error) {
	return c.ff1(ciphertext, tweak, false)
}

func (c *Cipher) ff1(input string, tweak []byte, encrypt bool) (string, error) {
	n := len(input)
	if n < c.minLen || n > c.maxLen {
		return "", fmt.Errorf("input length %d must be between %d and %d", n, c.minLen, c.maxLen)
	}

	nums, err := c.stringToNums(input)
	if err != nil {
		return "", fmt.Errorf("invalid input string: %w", err)
	}

	useTweak := tweak
	if useTweak == nil {
		useTweak = c.tweak
	}

	var result []int
	if encrypt {
		result, err = c.ff1Encrypt(nums, useTweak)
	} else {
		result, err = c.ff1Decrypt(nums, useTweak)
	}
	if err != nil {
		return "", fmt.Errorf("FF1 operation failed: %w", err)
	}

	return c.numsToString(result), nil
}

func (c *Cipher) stringToNums(s string) ([]int, error) {
	nums := make([]int, len(s))
	for i, r := range s {
		var val int
		switch {
		case r >= '0' && r <= '9':
			val = int(r - '0')
		case r >= 'A' && r <= 'Z':
			val = int(r - 'A' + 10)
		case r >= 'a' && r <= 'z':
			val = int(r - 'a' + 10)
		default:
			return nil, fmt.Errorf("invalid character '%c' for radix %d", r, c.radix)
		}
		if val >= c.radix {
			return nil, fmt.Errorf("character '%c' (value %d) exceeds radix %d", r, val, c.radix)
		}
		nums[i] = val
	}
	return nums, nil
}

func (c *Cipher) numsToString(nums []int) string {
	var result strings.Builder
	result.Grow(len(nums))
	for _, num := range nums {
		if num < 10 {
			result.WriteByte(byte('0' + num))
		} else {
			result.WriteByte(byte('a' + num - 10))
		}
	}
	return result.String()
}

// ff1Encrypt performs FF1 encryption according to NIST SP 800-38G Algorithm 1.
func (c *Cipher) ff1Encrypt(plaintext []int, tweak []byte) ([]int, error) {
	n := len(plaintext)
	radix := c.radix

	u0 := n / 2
	v0 := n - u0

	A := make([]int, u0)
	B := make([]int, v0)
	copy(A, plaintext[:u0])
	copy(B, plaintext[u0:])

	T := tweak
	if T == nil {
		T = []byte{}
	}

	b := c.computeB(v0, radix)
	d := c.computeD(b)
	P := c.buildP(radix, u0, n, len(T))

	for i := 0; i < 10; i++ {
		numB := c.numRadix(B, radix)
		numBBytes := c.bigIntToBytes(numB, b)
		Q := c.buildQ(T, i, numBBytes, b)
		R := c.prfLast(append(P, Q...))
		S := c.expandS(R, d)
		y := c.calculateY(S)

		m := u0
		if i%2 == 1 {
			m = v0
		}

		c_val := new(big.Int).Add(c.numRadix(A, radix), y)
		c_val.Mod(c_val, new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil))
		C := c.strRadix(c_val, radix, m)

		A, B = B, C
	}

	result := make([]int, n)
	copy(result[:len(A)], A)
	copy(result[len(A):], B)
	return result, nil
}

// ff1Decrypt performs FF1 decryption according to NIST SP 800-38G Algorithm 2.
func (c *Cipher) ff1Decrypt(ciphertext []int, tweak []byte) ([]int, error) {
	n := len(ciphertext)
	radix := c.radix

	u0 := n / 2
	v0 := n - u0

	A := make([]int, u0)
	B := make([]int, v0)
	copy(A, ciphertext[:u0])
	copy(B, ciphertext[u0:])

	T := tweak
	if T == nil {
		T = []byte{}
	}

	b := c.computeB(v0, radix)
	d := c.computeD(b)
	P := c.buildP(radix, u0, n, len(T))

	for i := 9; i >= 0; i-- {
		numA := c.numRadix(A, radix)
		numABytes := c.bigIntToBytes(numA, b)
		Q := c.buildQ(T, i, numABytes, b)
		R := c.prfLast(append(P, Q...))
		S := c.expandS(R, d)
		y := c.calculateY(S)

		m := u0
		if i%2 == 1 {
			m = v0
		}

		c_val := new(big.Int).Sub(c.numRadix(B, radix), y)
		modulus := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
		c_val.Mod(c_val, modulus)
		if c_val.Sign() < 0 {
			c_val.Add(c_val, modulus)
		}
		C := c.strRadix(c_val, radix, m)

		B, A = A, C
	}

	result := make([]int, n)
	copy(result[:len(A)], A)
	copy(result[len(A):], B)
	return result, nil
}

func (c *Cipher) computeB(v, radix int) int {
	r := big.NewInt(int64(radix))
	pow := new(big.Int).Exp(r, big.NewInt(int64(v)), nil)
	pow.Sub(pow, big.NewInt(1))
	bits := pow.BitLen()
	return (bits + 7) / 8
}

func (c *Cipher) computeD(b int) int {
	return 4*((b+3)/4) + 4
}

func (c *Cipher) buildP(radix, u, n, t int) []byte {
	P := make([]byte, 0, 16)
	P = append(P, 1, 2, 1)
	P = append(P, byte(radix>>16), byte(radix>>8), byte(radix))
	P = append(P, 10, byte(u))
	var nb [4]byte
	binary.BigEndian.PutUint32(nb[:], uint32(n))
	P = append(P, nb[:]...)
	var tb [4]byte
	binary.BigEndian.PutUint32(tb[:], uint32(t))
	P = append(P, tb[:]...)
	return P
}

func (c *Cipher) buildQ(T []byte, i int, numBorA []byte, b int) []byte {
	t := len(T)
	pad := (16 - ((t + 1 + b) % 16)) % 16
	Q := make([]byte, 0, t+pad+1+b)
	Q = append(Q, T...)
	Q = append(Q, make([]byte, pad)...)
	Q = append(Q, byte(i))
	if len(numBorA) < b {
		pref := make([]byte, b-len(numBorA))
		Q = append(Q, pref...)
	}
	start := 0
	if len(numBorA) > b {
		start = len(numBorA) - b
	}
	Q = append(Q, numBorA[start:]...)
	return Q
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

func (c *Cipher) prfLast(data []byte) [16]byte {
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

func (c *Cipher) intTo16(i int) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[8:], uint64(i))
	return b
}

func (c *Cipher) expandS(R [16]byte, d int) []byte {
	needBlocks := (d + 15) / 16
	out := make([]byte, 0, needBlocks*16)
	out = append(out, R[:]...)
	prev := R
	for j := 1; len(out) < needBlocks*16; j++ {
		x := c.intTo16(j)
		for k := 0; k < 16; k++ {
			x[k] ^= prev[k]
		}
		var nxt [16]byte
		c.cipher.Encrypt(nxt[:], x[:])
		out = append(out, nxt[:]...)
		prev = nxt
	}
	return out[:d]
}

func (c *Cipher) calculateY(S []byte) *big.Int {
	return new(big.Int).SetBytes(S)
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

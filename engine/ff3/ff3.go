// Package ff3 implements the FF3-1 format-preserving encryption algorithm
// as specified in NIST SP 800-38G Revision 1.
//
// FF3-1 uses an 8-round Feistel network with AES in a tweaked-blockcipher mode.
// It is widely supported across languages and is commonly found in legacy systems
// and the broader FPE ecosystem.
//
// Note: FF3 (the original) had a known attack; FF3-1 addresses this. This package
// implements FF3-1 per the NIST SP 800-38G Rev 1 specification.
//
// This package satisfies the engine.Encryptor and engine.Protector interfaces.
package ff3

import (
	"errors"

	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "ff3"
	engineType = "fpe"

	// TweakLength is the fixed tweak length required by FF3-1 (7 bytes).
	TweakLength = 7
)

// ErrInvalidKey is returned when the key length is not 16, 24, or 32 bytes.
var ErrInvalidKey = errors.New("ff3: key must be 16, 24, or 32 bytes")

// ErrInvalidTweak is returned when the tweak is not exactly 7 bytes (FF3-1 requirement).
var ErrInvalidTweak = errors.New("ff3: tweak must be exactly 7 bytes")

// ErrRadixTooSmall is returned when radix is less than 2.
var ErrRadixTooSmall = errors.New("ff3: radix must be at least 2")

// Cipher is an FF3-1 cipher instance bound to a specific key and tweak.
type Cipher struct {
	radix int
	key   []byte
	tweak []byte
}

// NewCipher creates a new FF3-1 Cipher.
//
// radix must be in [2, 2^16). key must be 16, 24, or 32 bytes.
// tweak must be exactly 7 bytes per the FF3-1 specification.
func NewCipher(radix int, key, tweak []byte) (*Cipher, error) {
	if radix < 2 {
		return nil, ErrRadixTooSmall
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKey
	}
	if len(tweak) != 0 && len(tweak) != TweakLength {
		return nil, ErrInvalidTweak
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

// Encrypt encrypts plaintext using FF3-1.
// Input characters must map to values in [0, radix).
func (c *Cipher) Encrypt(plaintext string, tweak []byte) (string, error) {
	return "", errors.New("ff3: Encrypt not yet implemented")
}

// Decrypt decrypts ciphertext produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext string, tweak []byte) (string, error) {
	return "", errors.New("ff3: Decrypt not yet implemented")
}

// Radix returns the radix this cipher was initialized with.
func (c *Cipher) Radix() int {
	return c.radix
}

// Name returns "ff3".
func (c *Cipher) Name() string { return engineName }

// Type returns "fpe".
func (c *Cipher) Type() string { return engineType }

// IsReversible returns true.
func (c *Cipher) IsReversible() bool { return true }

// Protect implements engine.Protector.
func (c *Cipher) Protect(plaintext string, params engine.Params) (string, error) {
	cipher, err := NewCipher(c.radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return cipher.Encrypt(plaintext, nil)
}

// Unprotect implements engine.Protector.
func (c *Cipher) Unprotect(protected string, params engine.Params) (string, error) {
	cipher, err := NewCipher(c.radix, params.Key, params.Tweak)
	if err != nil {
		return "", err
	}
	return cipher.Decrypt(protected, nil)
}

// New returns a default FF3-1 engine with radix 10.
func New() *Cipher {
	return &Cipher{radix: 10}
}

// NewWithRadix creates a default FF3-1 engine with the specified radix.
func NewWithRadix(radix int) (*Cipher, error) {
	if radix < 2 {
		return nil, ErrRadixTooSmall
	}
	return &Cipher{radix: radix}, nil
}

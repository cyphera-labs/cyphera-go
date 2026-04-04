// Package aesgcm implements AES-256-GCM authenticated encryption.
//
// Unlike FPE engines, AES-GCM does not preserve the format or length of the
// input. Use this engine for arbitrary data, files, and blobs where format
// preservation is not required.
//
// The output is base64-encoded ciphertext with an authenticated tag, prefixed
// by the random nonce used for encryption. This is not format-preserving.
//
// This package satisfies the engine.Encryptor and engine.Protector interfaces.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "aes-gcm"
	engineType = "aes"

	// NonceSize is the GCM nonce length in bytes.
	NonceSize = 12
)

// ErrInvalidKey is returned for unsupported key lengths.
var ErrInvalidKey = errors.New("aesgcm: key must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)")

// ErrDecryptFailed is returned when authenticated decryption fails (wrong key or corrupted data).
var ErrDecryptFailed = errors.New("aesgcm: decryption failed — wrong key or corrupted ciphertext")

// Engine is the AES-GCM engine. Safe for concurrent use.
type Engine struct{}

// New returns a new AES-GCM Engine.
func New() *Engine {
	return &Engine{}
}

// Encrypt encrypts plaintext with AES-GCM using key as the key and tweak as additional data.
// Returns base64-encoded output containing the random nonce prepended to the ciphertext+tag.
func (e *Engine) Encrypt(plaintext string, key, tweak []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), tweak)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded AES-GCM ciphertext produced by Encrypt.
// tweak must match the value used during encryption.
func (e *Engine) Decrypt(ciphertext string, key, tweak []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKey
	}

	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(raw) < NonceSize {
		return "", ErrDecryptFailed
	}

	nonce, ct := raw[:NonceSize], raw[NonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, tweak)
	if err != nil {
		return "", ErrDecryptFailed
	}

	return string(pt), nil
}

// Name returns "aes-gcm".
func (e *Engine) Name() string { return engineName }

// Type returns "aes".
func (e *Engine) Type() string { return engineType }

// IsReversible returns true.
func (e *Engine) IsReversible() bool { return true }

// Protect implements engine.Protector.
func (e *Engine) Protect(plaintext string, params engine.Params) (string, error) {
	return e.Encrypt(plaintext, params.Key, params.Tweak)
}

// Unprotect implements engine.Protector.
func (e *Engine) Unprotect(protected string, params engine.Params) (string, error) {
	return e.Decrypt(protected, params.Key, params.Tweak)
}

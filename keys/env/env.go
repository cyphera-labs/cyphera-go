// Package env provides an environment-variable-based key provider for Cyphera.
//
// The env provider resolves keys from environment variables, making it suitable
// for twelve-factor app deployments and container environments.
//
// Key material is read from environment variables using a configurable prefix.
// For a key ref "customer-primary", the provider looks for:
//
//	<PREFIX>_CUSTOMER_PRIMARY_KEY   — hex or base64 encoded key bytes
//	<PREFIX>_CUSTOMER_PRIMARY_TWEAK — hex or base64 encoded tweak (optional)
//
// All keys resolved from environment variables are treated as version 1, StatusActive.
// For multi-version key management, use the memory provider or a KMS-backed provider.
//
// This provider is suitable for simple production deployments where key rotation
// is handled by redeploying with new environment variables.
package env

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/cyphera-labs/cyphera-go/keys"
)

// ErrNoEnvKey is returned when the expected environment variable is not set.
type ErrNoEnvKey struct {
	VarName string
}

func (e *ErrNoEnvKey) Error() string {
	return "env: environment variable not set: " + e.VarName
}

// ErrInvalidEncoding is returned when a key variable cannot be decoded.
type ErrInvalidEncoding struct {
	VarName string
	Cause   error
}

func (e *ErrInvalidEncoding) Error() string {
	return "env: failed to decode " + e.VarName + ": " + e.Cause.Error()
}

// Provider resolves keys from environment variables.
// Safe for concurrent use (environment variables are read-only after process start).
type Provider struct {
	prefix string
}

// New returns a Provider that reads keys from environment variables with the given prefix.
// prefix is case-insensitive — it will be uppercased when looking up variables.
// Example: prefix "CYPHERA" causes the provider to look for "CYPHERA_<REF>_KEY".
func New(prefix string) *Provider {
	return &Provider{prefix: strings.ToUpper(prefix)}
}

// Resolve returns a key Record constructed from environment variables for the given ref.
// The ref is normalized (uppercased, dashes replaced with underscores) to form the variable name.
func (p *Provider) Resolve(_ context.Context, ref string) (keys.Record, error) {
	return p.resolveVersion(ref, 1)
}

// ResolveVersion resolves a specific version. The env provider only supports version 1.
func (p *Provider) ResolveVersion(_ context.Context, ref string, version int) (keys.Record, error) {
	if version != 1 {
		return keys.Record{}, &keys.ErrKeyNotFound{Ref: ref, Version: version}
	}
	return p.resolveVersion(ref, version)
}

func (p *Provider) resolveVersion(ref string, version int) (keys.Record, error) {
	keyVar := p.varName(ref, "KEY")
	keyVal := os.Getenv(keyVar)
	if keyVal == "" {
		return keys.Record{}, &keys.ErrKeyNotFound{Ref: ref}
	}

	material, err := decodeBytes(keyVal)
	if err != nil {
		return keys.Record{}, &ErrInvalidEncoding{VarName: keyVar, Cause: err}
	}

	var tweak []byte
	tweakVar := p.varName(ref, "TWEAK")
	if tweakVal := os.Getenv(tweakVar); tweakVal != "" {
		tweak, err = decodeBytes(tweakVal)
		if err != nil {
			return keys.Record{}, &ErrInvalidEncoding{VarName: tweakVar, Cause: err}
		}
	}

	return keys.Record{
		Ref:       ref,
		Version:   version,
		Status:    keys.StatusActive,
		Material:  material,
		Tweak:     tweak,
		CreatedAt: time.Time{}, // unknown
	}, nil
}

// varName constructs the environment variable name for a given ref and suffix.
// e.g. prefix="CYPHERA", ref="customer-primary", suffix="KEY" → "CYPHERA_CUSTOMER_PRIMARY_KEY"
func (p *Provider) varName(ref, suffix string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(ref, "-", "_"))
	if p.prefix == "" {
		return normalized + "_" + suffix
	}
	return p.prefix + "_" + normalized + "_" + suffix
}

// decodeBytes attempts to decode a string as hex, then base64.
func decodeBytes(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("value is not valid hex or base64")
}

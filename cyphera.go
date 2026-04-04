// Package cyphera is the Cyphera SDK — format-preserving encryption for everyone.
//
// Cyphera makes FPE usable the way Tink makes AEAD usable: by separating the
// crypto engine from key lifecycle, domain logic, and operational concerns.
// A credit card number stays a credit card number. An SSN stays an SSN.
// A phone number stays a phone number.
//
// # Two faces
//
// Face 1 — Primitive (for implementers, testing, advanced use):
//
//	import "github.com/cyphera-labs/cyphera-go/engine/ff1"
//	cipher, _ := ff1.NewCipher(10, key, tweak)
//	ct, _ := cipher.Encrypt("123456789", nil)
//
// Face 2 — SDK (recommended for application developers):
//
//	client, _ := cyphera.New(
//	    cyphera.WithKeyProvider(keys.NewMemoryProvider(...)),
//	)
//	result, _ := client.Encrypt(ctx, cyphera.Request{
//	    Domain:    "ssn",
//	    KeyRef:    "customer-primary",
//	    Plaintext: "123-45-6789",
//	})
//
// # Engines
//
// Cyphera ships the following protection engines:
//   - FF1: NIST SP 800-38G compliant FPE (default)
//   - FF3-1: NIST SP 800-38G Rev 1 compliant FPE
//   - AES-GCM: general authenticated encryption
//   - Mask: irreversible pattern-based redaction
//   - Hash: irreversible deterministic tokenization
//
// # Domains
//
// Built-in domains handle common PII types: SSN, PAN (credit card), Phone, Email, TaxID.
// Custom domains can be defined for any application-specific data type.
//
// # Key management
//
// Keys are resolved by reference, not passed as raw bytes. Built-in providers:
// memory (dev/testing), env (twelve-factor), file (secrets-manager integration).
// KMS/HSM providers are separate packages.
package cyphera

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cyphera-labs/cyphera-go/domains"
	domainEmail "github.com/cyphera-labs/cyphera-go/domains/email"
	domainPAN "github.com/cyphera-labs/cyphera-go/domains/pan"
	domainPhone "github.com/cyphera-labs/cyphera-go/domains/phone"
	domainSSN "github.com/cyphera-labs/cyphera-go/domains/ssn"
	domainTaxID "github.com/cyphera-labs/cyphera-go/domains/taxid"
	"github.com/cyphera-labs/cyphera-go/engine"
	engineAESGCM "github.com/cyphera-labs/cyphera-go/engine/aesgcm"
	engineFF1 "github.com/cyphera-labs/cyphera-go/engine/ff1"
	engineHash "github.com/cyphera-labs/cyphera-go/engine/hash"
	engineMask "github.com/cyphera-labs/cyphera-go/engine/mask"
	"github.com/cyphera-labs/cyphera-go/keys"
	"github.com/cyphera-labs/cyphera-go/ops"
)

// Request is the input to all Client operations.
type Request struct {
	// Domain identifies the data type, e.g. "ssn", "pan", "phone".
	// The domain determines format handling, validation, and alphabet selection.
	Domain string

	// KeyRef is the logical key reference used to resolve key material,
	// e.g. "customer-primary". Not required for keyless operations (masking,
	// unkeyed hashing). Falls back to WithDefaultKeyRef if empty.
	KeyRef string

	// KeyVersion specifies the exact key version for decryption.
	// Leave 0 to use the active version (for encryption) or auto-detect.
	KeyVersion int

	// Plaintext is the raw input value. For Decrypt operations, this is the
	// ciphertext to be decrypted.
	Plaintext string

	// Context is caller-provided metadata attached to the audit record.
	// Typical keys: "user", "service", "reason", "request_id".
	// Never include plaintext or sensitive data here.
	Context map[string]string
}

// Result is the output from all Client operations.
type Result struct {
	// Output is the protected value: ciphertext, masked value, or hash token.
	Output string

	// KeyRef is the logical key reference that was used. Empty if no key was involved.
	KeyRef string

	// KeyVersion is the resolved key version that was used. 0 if no key was involved.
	KeyVersion int

	// Domain is the domain name used for this operation.
	Domain string

	// Engine is the name of the protection engine used, e.g. "ff1", "mask".
	Engine string

	// Reversible reports whether the output can be reversed to recover the original value.
	Reversible bool
}

// Client is the Cyphera SDK entry point. Create one with New and reuse it across operations.
// All methods are safe for concurrent use.
type Client interface {
	// Encrypt applies format-preserving or AES encryption to the request value.
	// The output format matches the input format for FPE engines.
	Encrypt(ctx context.Context, req Request) (Result, error)

	// Decrypt reverses an Encrypt operation to recover the original plaintext.
	Decrypt(ctx context.Context, req Request) (Result, error)

	// EncryptBatch encrypts multiple values in a single call.
	// Results are returned in the same order as the requests.
	// If any operation fails the entire batch returns an error.
	EncryptBatch(ctx context.Context, reqs []Request) ([]Result, error)

	// DecryptBatch decrypts multiple values in a single call.
	DecryptBatch(ctx context.Context, reqs []Request) ([]Result, error)

	// Mask applies irreversible pattern-based redaction to the request value.
	// The domain's masking configuration determines the pattern.
	Mask(ctx context.Context, req Request) (Result, error)

	// Hash applies irreversible deterministic tokenization to the request value.
	// The same input always produces the same output under the same key.
	Hash(ctx context.Context, req Request) (Result, error)

	// Protect applies the default protection for the domain as configured by policy.
	// The engine is chosen by: policy → domain default → client default → FF1.
	Protect(ctx context.Context, req Request) (Result, error)

	// Unprotect reverses a Protect operation.
	// Returns an error if the domain's protection engine is irreversible.
	Unprotect(ctx context.Context, req Request) (Result, error)
}

// New creates a Cyphera Client with the provided options.
//
//	client, err := cyphera.New(
//	    cyphera.WithKeyProvider(provider),
//	    cyphera.WithLogger(ops.NewJSONLogger(os.Stdout)),
//	)
func New(opts ...Option) (Client, error) {
	cfg := &config{
		domainRegistry: domains.NewRegistry().
			Register(domainSSN.New()).
			Register(domainPAN.New()).
			Register(domainPhone.New()).
			Register(domainEmail.New()).
			Register(domainTaxID.New()),
		engines:       buildDefaultEngines(),
		defaultEngine: "ff1",
	}

	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.logger == nil {
		cfg.logger = ops.NewNoopLogger()
	}

	return &client{cfg: cfg}, nil
}

func buildDefaultEngines() map[string]engine.Engine {
	return map[string]engine.Engine{
		"ff1":     engineFF1.New(),
		"aes-gcm": engineAESGCM.New(),
		"mask":    engineMask.New("", 0),
		"hash":    engineHash.New(),
	}
}

// client is the concrete implementation of Client.
type client struct {
	cfg *config
}

// Encrypt encrypts the request value using the domain's FPE or AES engine.
func (c *client) Encrypt(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationEncrypt)
}

// Decrypt decrypts a value produced by Encrypt.
func (c *client) Decrypt(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationDecrypt)
}

// EncryptBatch encrypts multiple values sequentially.
func (c *client) EncryptBatch(ctx context.Context, reqs []Request) ([]Result, error) {
	results := make([]Result, len(reqs))
	for i, req := range reqs {
		r, err := c.Encrypt(ctx, req)
		if err != nil {
			return nil, err
		}
		results[i] = r
	}
	return results, nil
}

// DecryptBatch decrypts multiple values sequentially.
func (c *client) DecryptBatch(ctx context.Context, reqs []Request) ([]Result, error) {
	results := make([]Result, len(reqs))
	for i, req := range reqs {
		r, err := c.Decrypt(ctx, req)
		if err != nil {
			return nil, err
		}
		results[i] = r
	}
	return results, nil
}

// Mask applies irreversible masking to the request value.
func (c *client) Mask(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationMask)
}

// Hash applies irreversible deterministic hashing to the request value.
func (c *client) Hash(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationHash)
}

// Protect applies the domain's default protection operation.
func (c *client) Protect(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationProtect)
}

// Unprotect reverses a Protect operation.
func (c *client) Unprotect(ctx context.Context, req Request) (Result, error) {
	return c.dispatch(ctx, req, ops.OperationUnprotect)
}

// dispatch is the central dispatch point for all operations.
// It enforces policy, resolves keys, looks up the domain, and routes to the engine.
func (c *client) dispatch(ctx context.Context, req Request, op ops.OperationType) (Result, error) {
	// Apply defaults
	if req.KeyRef == "" {
		req.KeyRef = c.cfg.defaultKeyRef
	}

	// Policy: check context requirement
	if err := c.cfg.policy.CheckContext(req.Context); err != nil {
		return Result{}, err
	}

	// Policy: check domain restriction for this key
	if req.KeyRef != "" {
		if err := c.cfg.policy.CheckDomain(req.KeyRef, req.Domain); err != nil {
			return Result{}, err
		}
	}

	// Resolve key if needed
	var keyRecord keys.Record
	if req.KeyRef != "" && c.cfg.keyProvider != nil {
		var keyErr error
		if req.KeyVersion > 0 {
			keyRecord, keyErr = c.cfg.keyProvider.ResolveVersion(ctx, req.KeyRef, req.KeyVersion)
		} else {
			keyRecord, keyErr = c.cfg.keyProvider.Resolve(ctx, req.KeyRef)
		}
		if keyErr != nil {
			c.emitEvent(ctx, req, op, "", 0, false, keyErr.Error())
			return Result{}, keyErr
		}

		// Policy: check deprecated key for encryption
		if (op == ops.OperationEncrypt || op == ops.OperationProtect) &&
			c.cfg.policy.RejectDeprecatedForEncrypt &&
			keyRecord.Status == keys.StatusDeprecated {
			err := &ops.ErrDeprecatedKeyForEncrypt{Ref: keyRecord.Ref, Version: keyRecord.Version}
			c.emitEvent(ctx, req, op, "", keyRecord.Version, false, err.Error())
			return Result{}, err
		}
	}

	// Look up domain
	dom := c.cfg.domainRegistry.Get(req.Domain)
	if dom == nil {
		err := fmt.Errorf("cyphera: unknown domain %q", req.Domain)
		c.emitEvent(ctx, req, op, c.cfg.defaultEngine, keyRecord.Version, false, err.Error())
		return Result{}, err
	}

	// Validate and normalize
	if err := dom.Validate(req.Plaintext); err != nil {
		c.emitEvent(ctx, req, op, c.cfg.defaultEngine, keyRecord.Version, false, err.Error())
		return Result{}, err
	}
	normalized, err := dom.Normalize(req.Plaintext)
	if err != nil {
		c.emitEvent(ctx, req, op, c.cfg.defaultEngine, keyRecord.Version, false, err.Error())
		return Result{}, err
	}

	// Route to the appropriate engine
	switch op {
	case ops.OperationMask:
		return c.execMask(ctx, req, dom, normalized)
	case ops.OperationHash:
		return c.execHash(ctx, req, dom, normalized, keyRecord)
	default:
		return c.execFPE(ctx, req, op, dom, normalized, keyRecord)
	}
}

// execFPE handles Encrypt, Decrypt, Protect, and Unprotect via the FF1 engine.
func (c *client) execFPE(ctx context.Context, req Request, op ops.OperationType, dom domains.Domain, normalized string, keyRecord keys.Record) (Result, error) {
	engName := c.cfg.defaultEngine

	if len(keyRecord.Material) == 0 {
		err := errors.New("cyphera: key material required for FPE operation")
		c.emitEvent(ctx, req, op, engName, 0, false, err.Error())
		return Result{}, err
	}

	chars, positions, template := dom.Extract(normalized)
	if len(chars) == 0 {
		// Nothing to encrypt — return normalized form as-is.
		c.emitEvent(ctx, req, op, engName, keyRecord.Version, true, "")
		return Result{
			Output:     normalized,
			KeyRef:     keyRecord.Ref,
			KeyVersion: keyRecord.Version,
			Domain:     req.Domain,
			Engine:     engName,
			Reversible: true,
		}, nil
	}

	alpha := dom.Alphabet()
	cipher, err := engineFF1.NewCipher(alpha.Radix(), keyRecord.Material, keyRecord.Tweak)
	if err != nil {
		c.emitEvent(ctx, req, op, engName, keyRecord.Version, false, err.Error())
		return Result{}, fmt.Errorf("cyphera: failed to create FF1 cipher: %w", err)
	}

	var processed string
	switch op {
	case ops.OperationEncrypt, ops.OperationProtect:
		processed, err = cipher.Encrypt(chars, nil)
	case ops.OperationDecrypt, ops.OperationUnprotect:
		processed, err = cipher.Decrypt(chars, nil)
	default:
		err = fmt.Errorf("cyphera: unsupported FPE operation %q", op)
	}
	if err != nil {
		c.emitEvent(ctx, req, op, engName, keyRecord.Version, false, err.Error())
		return Result{}, err
	}

	output := dom.Reconstruct(processed, positions, template)
	c.emitEvent(ctx, req, op, engName, keyRecord.Version, true, "")
	return Result{
		Output:     output,
		KeyRef:     keyRecord.Ref,
		KeyVersion: keyRecord.Version,
		Domain:     req.Domain,
		Engine:     engName,
		Reversible: true,
	}, nil
}

// execMask handles Mask operations.
// The masking pattern can be passed in req.Context["pattern"]; defaults to "last_4".
func (c *client) execMask(ctx context.Context, req Request, dom domains.Domain, normalized string) (Result, error) {
	const engName = "mask"

	pattern := req.Context["pattern"]
	if pattern == "" {
		pattern = engineMask.PatternLast4
	}

	output, err := engineMask.Apply(normalized, pattern, 0)
	if err != nil {
		c.emitEvent(ctx, req, ops.OperationMask, engName, 0, false, err.Error())
		return Result{}, err
	}

	c.emitEvent(ctx, req, ops.OperationMask, engName, 0, true, "")
	return Result{
		Output:     output,
		Domain:     req.Domain,
		Engine:     engName,
		Reversible: false,
	}, nil
}

// execHash handles Hash operations.
// Uses HMAC-SHA256 if key material is available, otherwise SHA-256.
func (c *client) execHash(ctx context.Context, req Request, dom domains.Domain, normalized string, keyRecord keys.Record) (Result, error) {
	const engName = "hash"

	// Hash the extracted characters only (the semantically meaningful part).
	chars, _, _ := dom.Extract(normalized)
	if chars == "" {
		chars = normalized
	}

	var output string
	if len(keyRecord.Material) > 0 {
		output = engineHash.HMAC(chars, keyRecord.Material)
	} else {
		output = engineHash.SHA256Hash(chars)
	}

	c.emitEvent(ctx, req, ops.OperationHash, engName, keyRecord.Version, true, "")
	return Result{
		Output:     output,
		KeyRef:     keyRecord.Ref,
		KeyVersion: keyRecord.Version,
		Domain:     req.Domain,
		Engine:     engName,
		Reversible: false,
	}, nil
}

func (c *client) emitEvent(ctx context.Context, req Request, op ops.OperationType, eng string, keyVer int, success bool, errMsg string) {
	ev := ops.Event{
		Operation:  op,
		Domain:     req.Domain,
		KeyRef:     req.KeyRef,
		KeyVersion: keyVer,
		Engine:     eng,
		Success:    success,
		Error:      errMsg,
		Timestamp:  time.Now().UTC(),
		Context:    req.Context,
	}
	_ = c.cfg.logger.Log(ctx, ev)
}

# Cyphera

**Format-Preserving Encryption for Everyone.**
A cross-compatible data protection library — easy enough for a startup, powerful enough for an enterprise.

A credit card number stays a credit card number. An SSN stays an SSN. A phone number stays a phone number. The data is protected, the keys are managed, the operations are audited — and developers never touch raw key material unless they explicitly choose to.

---

## Quick Start

```go
import (
    "context"
    "github.com/cyphera-labs/cyphera-go"
    "github.com/cyphera-labs/cyphera-go/keys/memory"
    "github.com/cyphera-labs/cyphera-go/keys"
)

client, err := cyphera.New(
    cyphera.WithKeyProvider(memory.New(
        keys.Record{
            Ref:      "customer-primary",
            Version:  1,
            Status:   keys.StatusActive,
            Material: []byte("0123456789ABCDEF"),
            Tweak:    []byte("cust-ssn"),
        },
    )),
)

ctx := context.Background()

result, err := client.Encrypt(ctx, cyphera.Request{
    Domain:    "ssn",
    KeyRef:    "customer-primary",
    Plaintext: "123-45-6789",
})

fmt.Println(result.Output)      // "987-65-4321" (format preserved)
fmt.Println(result.KeyVersion)  // 1
```

### With audit logging

```go
import "github.com/cyphera-labs/cyphera-go/ops"

client, _ := cyphera.New(
    cyphera.WithKeyProvider(provider),
    cyphera.WithLogger(ops.NewJSONLogger(os.Stdout)),
)
// Every operation emits a structured JSON audit event — no plaintext, no key material.
```

### Masking (irreversible)

```go
result, _ := client.Mask(ctx, cyphera.Request{
    Domain:    "ssn_display_partial",
    Plaintext: "123-45-6789",
})
fmt.Println(result.Output) // "***-**-6789"
```

### Direct primitive access (advanced)

```go
import "github.com/cyphera-labs/cyphera-go/engine/ff1"

cipher, _ := ff1.NewCipher(10, key, tweak)
ct, _ := cipher.Encrypt("123456789", nil)

// With alphabet pass-through (preserves dashes):
ct, _ = cipher.EncryptDigitsOnly("123-45-6789", nil)
// → "987-65-4321"
```

```go
import "github.com/cyphera-labs/cyphera-go/engine/ff3"

f, _ := ff3.Digits(key, tweak8) // tweak must be exactly 8 bytes
ct, _ := f.Encrypt("123456789", nil)
```

---

## Package Structure

```
cyphera.go          SDK entry point — Client interface, New(), Request, Result
config.go           Functional options — WithKeyProvider, WithDomain, WithEngine, etc.

engine/
  engine.go         Engine, Encryptor, Protector interfaces + Params
  ff1/              FF1 — NIST SP 800-38G (full implementation)
  ff3/              FF3-1 — NIST SP 800-38G Rev 1 (full implementation)
  aesgcm/           AES-256-GCM — general authenticated encryption
  mask/             Mask — irreversible pattern-based redaction
  hash/             Hash — irreversible deterministic tokenization

domains/
  domain.go         Domain interface + Registry
  ssn/              Social Security Number (XXX-XX-XXXX)
  pan/              Payment card number (PAN/credit card)
  phone/            Phone number (international + domestic)
  email/            Email address
  taxid/            Tax ID / EIN (XX-XXXXXXX)
  custom/           Custom domain builder

keys/
  provider.go       Provider interface, Record, Status, error types
  memory/           In-memory provider (dev/testing)
  env/              Environment variable provider (twelve-factor)
  file/             File-based provider (secrets manager integration)

ops/
  audit.go          Event struct, Logger interface, OperationType
  logger.go         NewNoopLogger, NewStdLogger, NewJSONLogger
  policy.go         Policy struct — domain restrictions, deprecated key rules

alphabet/
  alphabet.go       Alphabet type — character sets for FPE engines
```

---

## Engines

| Engine | Type | Reversible | Description |
|--------|------|-----------|-------------|
| **FF1** | FPE | Yes | NIST SP 800-38G — default engine |
| **FF3-1** | FPE | Yes | NIST SP 800-38G Rev 1 |
| **AES-GCM** | AES | Yes | General authenticated encryption |
| **Mask** | Mask | No | Pattern-based redaction |
| **Hash** | Hash | No | Deterministic tokenization |

Engine selection hierarchy: policy → domain default → client default → **FF1**.

---

## Status

**Early development — FF1 and FF3-1 fully implemented. SDK dispatch in progress.**

- [x] Package structure and interfaces
- [x] Domain: SSN, PAN, Phone, Email, TaxID, Custom
- [x] Key providers: Memory, Env, File
- [x] Audit: Event, Logger, JSON/Std loggers
- [x] Policy enforcement
- [x] FF1 engine — NIST SP 800-38G (full implementation + alphabet pass-through)
- [x] FF3-1 engine — NIST SP 800-38G Rev 1 (full implementation)
- [x] AES-GCM engine
- [x] Mask engine (last_4, first_6, full, email patterns)
- [x] Hash engine (HMAC-SHA256, SHA-256)
- [ ] SDK dispatch (wires engines to domains — in progress)

---

## License

Apache 2.0

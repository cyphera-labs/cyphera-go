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
            Material: []byte("0123456789ABCDEF0123456789ABCDEF"),
            Tweak:    []byte("customer-ssn"),
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
```

---

## Package Structure

```
cyphera.go          SDK entry point — Client interface, New(), Request, Result
config.go           Functional options — WithKeyProvider, WithDomain, WithEngine, etc.

engine/
  engine.go         Engine, Encryptor, Protector interfaces + Params
  adf1/             ADF1 — patent-clean FPE, recommended default
  son1/             SoN1 — FPE for small/irregular domains
  ff1/              FF1 — NIST SP 800-38G compliant
  ff3/              FF3-1 — NIST SP 800-38G Rev 1 compliant
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
| **ADF1** | FPE | Yes | Patent-clean, recommended default |
| **SoN1** | FPE | Yes | Small/irregular domains |
| **FF1** | FPE | Yes | NIST SP 800-38G compliant |
| **FF3-1** | FPE | Yes | NIST SP 800-38G Rev 1 compliant |
| **AES-GCM** | AES | Yes | General authenticated encryption |
| **Mask** | Mask | No | Pattern-based redaction |
| **Hash** | Hash | No | Deterministic tokenization |

Engine selection hierarchy: policy → domain default → client default → **ADF1**.

---

## Status

**Early development — interfaces defined, implementations in progress.**

- [x] Package structure and interfaces
- [x] Domain: SSN, PAN, Phone, Email, TaxID, Custom
- [x] Key providers: Memory, Env, File
- [x] Audit: Event, Logger, JSON/Std loggers
- [x] Policy enforcement
- [x] AES-GCM engine (implemented)
- [x] Mask engine (implemented)
- [x] Hash engine (implemented)
- [ ] ADF1 engine (stub — implementation in progress)
- [ ] SoN1 engine (stub — implementation in progress)
- [ ] FF1 engine (stub — implementation in progress)
- [ ] FF3-1 engine (stub — implementation in progress)
- [ ] SDK dispatch (stub — wires up when engines are ready)

---

## License

Apache 2.0

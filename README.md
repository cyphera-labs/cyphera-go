# cyphera-go

[![CI](https://github.com/cyphera-labs/cyphera-go/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyphera-labs/cyphera-go.svg)](https://pkg.go.dev/github.com/cyphera-labs/cyphera-go)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Go — format-preserving encryption (FF1/FF3), data masking, and hashing.

```
go get github.com/cyphera-labs/cyphera-go
```

## Usage

```go
import "github.com/cyphera-labs/cyphera-go"

// Auto-discover: checks CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json
c, err := cyphera.Load()

// Or load from a specific file
c, err := cyphera.FromFile("./config/cyphera.json")

// Protect
encrypted, err := c.Protect("123-45-6789", "ssn")
// → "T01i6J-xF-07pX" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
decrypted, err := c.Access(encrypted)
// → "123-45-6789"
```

## Engines

| Engine | Reversible | Description |
|--------|-----------|-------------|
| `ff1`  | Yes | NIST SP 800-38G FF1 format-preserving encryption |
| `ff3`  | Yes | NIST SP 800-38G Rev 1 FF3-1 format-preserving encryption |
| `mask` | No  | Simple pattern masking (last4, first1, full, etc.) |
| `hash` | No  | SHA-256/384/512, HMAC when key provided |

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "tag": "T01" },
    "cc": { "engine": "ff1", "key_ref": "my-key", "tag": "T02" },
    "ssn_mask": { "engine": "mask", "pattern": "last4", "tag_enabled": false }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Cross-Language Compatible

All six SDKs produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Go:          T01i6J-xF-07pX
.NET:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Java, Rust, Node, Python, and .NET implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC

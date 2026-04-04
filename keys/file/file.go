// Package file provides a file-based key provider for Cyphera.
//
// The file provider reads key records from a local JSON file. This is suitable
// for environments where keys are provisioned via secrets management tools
// (e.g. HashiCorp Vault, Kubernetes secrets) that write files to the filesystem.
//
// Key file format (JSON):
//
//	{
//	  "keys": [
//	    {
//	      "ref": "customer-primary",
//	      "version": 1,
//	      "status": "active",
//	      "algorithm": "adf1",
//	      "material": "<hex or base64 encoded>",
//	      "tweak": "<hex or base64 encoded>",
//	      "created_at": "2026-01-01T00:00:00Z"
//	    }
//	  ]
//	}
//
// The file is read once at construction time. To reload keys from an updated file,
// create a new Provider.
package file

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cyphera-labs/cyphera-go/keys"
)

// keyFileRecord is the JSON representation of a key record in the key file.
type keyFileRecord struct {
	Ref       string            `json:"ref"`
	Version   int               `json:"version"`
	Status    string            `json:"status"`
	Algorithm string            `json:"algorithm"`
	Material  string            `json:"material"`  // hex or base64
	Tweak     string            `json:"tweak"`     // hex or base64, optional
	Metadata  map[string]string `json:"metadata"`
	CreatedAt string            `json:"created_at"` // RFC3339
}

// keyFile is the top-level structure of the JSON key file.
type keyFile struct {
	Keys []keyFileRecord `json:"keys"`
}

// Provider reads key records from a JSON file on disk.
// Safe for concurrent use after construction.
type Provider struct {
	records map[string][]keys.Record // ref → sorted by version descending
}

// New reads and parses the key file at path, returning a ready-to-use Provider.
func New(path string) (*Provider, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("file: failed to open key file: %w", err)
	}
	defer f.Close()

	var kf keyFile
	if err := json.NewDecoder(f).Decode(&kf); err != nil {
		return nil, fmt.Errorf("file: failed to parse key file: %w", err)
	}

	p := &Provider{records: make(map[string][]keys.Record)}
	for _, r := range kf.Keys {
		rec, err := convertRecord(r)
		if err != nil {
			return nil, fmt.Errorf("file: invalid record for ref %q: %w", r.Ref, err)
		}
		p.records[rec.Ref] = append(p.records[rec.Ref], rec)
	}

	// Sort each ref's versions descending
	for ref := range p.records {
		sort.Slice(p.records[ref], func(i, j int) bool {
			return p.records[ref][i].Version > p.records[ref][j].Version
		})
	}

	return p, nil
}

// Resolve returns the highest-version active Record for the given ref.
func (p *Provider) Resolve(_ context.Context, ref string) (keys.Record, error) {
	versions, ok := p.records[ref]
	if !ok || len(versions) == 0 {
		return keys.Record{}, &keys.ErrKeyNotFound{Ref: ref}
	}
	for _, r := range versions {
		if r.Status == keys.StatusActive {
			return r, nil
		}
	}
	return keys.Record{}, &keys.ErrNoActiveKey{Ref: ref}
}

// ResolveVersion returns the Record for a specific ref and version.
func (p *Provider) ResolveVersion(_ context.Context, ref string, version int) (keys.Record, error) {
	versions, ok := p.records[ref]
	if !ok || len(versions) == 0 {
		return keys.Record{}, &keys.ErrKeyNotFound{Ref: ref, Version: version}
	}
	for _, r := range versions {
		if r.Version == version {
			if r.Status == keys.StatusDisabled {
				return keys.Record{}, &keys.ErrKeyDisabled{Ref: ref, Version: version}
			}
			return r, nil
		}
	}
	return keys.Record{}, &keys.ErrKeyNotFound{Ref: ref, Version: version}
}

func convertRecord(r keyFileRecord) (keys.Record, error) {
	material, err := decodeBytes(r.Material)
	if err != nil {
		return keys.Record{}, fmt.Errorf("material: %w", err)
	}

	var tweak []byte
	if r.Tweak != "" {
		tweak, err = decodeBytes(r.Tweak)
		if err != nil {
			return keys.Record{}, fmt.Errorf("tweak: %w", err)
		}
	}

	var createdAt time.Time
	if r.CreatedAt != "" {
		createdAt, err = time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			return keys.Record{}, fmt.Errorf("created_at: %w", err)
		}
	}

	status := keys.Status(r.Status)
	if status == "" {
		status = keys.StatusActive
	}

	return keys.Record{
		Ref:       r.Ref,
		Version:   r.Version,
		Status:    status,
		Algorithm: r.Algorithm,
		Material:  material,
		Tweak:     tweak,
		Metadata:  r.Metadata,
		CreatedAt: createdAt,
	}, nil
}

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

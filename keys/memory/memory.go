// Package memory provides an in-memory key provider for Cyphera.
//
// The memory provider is intended for development, testing, and simple
// demonstrations. Key material exists only in process memory and is lost
// when the process exits. It is not suitable for production use.
//
// Usage:
//
//	provider := memory.New(
//	    keys.Record{
//	        Ref:      "customer-primary",
//	        Version:  1,
//	        Status:   keys.StatusActive,
//	        Material: []byte("0123456789ABCDEF0123456789ABCDEF"),
//	        Tweak:    []byte("customer-ssn"),
//	    },
//	)
//
//	client, _ := cyphera.New(cyphera.WithKeyProvider(provider))
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/cyphera-labs/cyphera-go/keys"
)

// Provider is an in-memory implementation of keys.Provider.
// Safe for concurrent use.
type Provider struct {
	mu      sync.RWMutex
	records map[string][]keys.Record // ref → sorted by version descending
}

// New creates a memory Provider pre-loaded with the given records.
func New(records ...keys.Record) *Provider {
	p := &Provider{
		records: make(map[string][]keys.Record),
	}
	for _, r := range records {
		p.add(r)
	}
	return p
}

// Add inserts or updates a key record in the provider.
// Useful for adding keys after construction (e.g. in rotation tests).
func (p *Provider) Add(record keys.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.add(record)
}

func (p *Provider) add(record keys.Record) {
	ref := record.Ref
	versions := p.records[ref]

	// Replace existing version if present
	for i, r := range versions {
		if r.Version == record.Version {
			versions[i] = record
			p.records[ref] = versions
			return
		}
	}

	versions = append(versions, record)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version > versions[j].Version // descending
	})
	p.records[ref] = versions
}

// Resolve returns the highest-version active Record for the given ref.
func (p *Provider) Resolve(_ context.Context, ref string) (keys.Record, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

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
	p.mu.RLock()
	defer p.mu.RUnlock()

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

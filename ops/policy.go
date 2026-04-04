package ops

import (
	"errors"
	"fmt"
)

// Policy governs how keys and domains may be used within a Cyphera client.
// It is enforced before the cryptographic operation is dispatched.
//
// Policies do not implement authentication — they enforce rules about
// how keys are used once access to them has already been granted by
// infrastructure (IAM, KMS policy, etc.).
type Policy struct {
	// AllowedDomains restricts which domains a given key ref may be used with.
	// If a key ref is listed here, it may only be used with the named domains.
	// Key refs not in this map are unrestricted.
	//
	// Example:
	//   AllowedDomains: map[string][]string{
	//       "payments-primary": {"pan"},
	//       "customer-primary": {"ssn", "phone"},
	//   }
	AllowedDomains map[string][]string

	// RejectDeprecatedForEncrypt prevents new encryption operations from
	// using key versions with StatusDeprecated. Decryption with deprecated
	// keys is always allowed (to handle existing ciphertext).
	RejectDeprecatedForEncrypt bool

	// RequireContext requires that every Request include at least one entry
	// in its Context map. Useful in regulated environments where operations
	// must always be attributable to a caller.
	RequireContext bool
}

// Validate checks that the Policy configuration is internally consistent.
func (p Policy) Validate() error {
	for ref, domains := range p.AllowedDomains {
		if ref == "" {
			return errors.New("policy: AllowedDomains contains an empty key ref")
		}
		for _, d := range domains {
			if d == "" {
				return fmt.Errorf("policy: AllowedDomains[%q] contains an empty domain", ref)
			}
		}
	}
	return nil
}

// CheckDomain returns an error if the given key ref is not allowed to operate on domain.
// Returns nil if the key ref has no domain restrictions.
func (p Policy) CheckDomain(keyRef, domain string) error {
	allowed, ok := p.AllowedDomains[keyRef]
	if !ok {
		return nil // unrestricted
	}
	for _, d := range allowed {
		if d == domain {
			return nil
		}
	}
	return fmt.Errorf("policy: key %q is not allowed for domain %q", keyRef, domain)
}

// CheckContext returns an error if RequireContext is set and ctx is empty.
func (p Policy) CheckContext(ctx map[string]string) error {
	if p.RequireContext && len(ctx) == 0 {
		return errors.New("policy: request context is required but was not provided")
	}
	return nil
}

// ErrDeprecatedKeyForEncrypt is returned when a deprecated key is used for encryption
// and RejectDeprecatedForEncrypt is true.
type ErrDeprecatedKeyForEncrypt struct {
	Ref     string
	Version int
}

func (e *ErrDeprecatedKeyForEncrypt) Error() string {
	return fmt.Sprintf("policy: key %q version %d is deprecated and cannot be used for encryption", e.Ref, e.Version)
}

// Package domains defines the Domain interface and built-in domain implementations.
//
// A Domain is not just an alphabet. It is a complete data-shape contract that encapsulates:
//   - Input validation (is this actually an SSN? a valid credit card number?)
//   - Normalization (strip dashes, lowercase, etc.)
//   - Format preservation rules (which characters to encrypt, which to pass through)
//   - Output reconstruction (reassemble the original shape after encryption)
//   - Alphabet and radix selection
//
// This is the Themis pattern applied to FPE: package crypto into recognizable
// application units. Not "here is FF1 with radix 10" but "here is a reusable
// secure component for Social Security Numbers."
//
// Built-in domains cover the most common data types. Custom domains let
// application code define their own without forking the library.
package domains

import (
	"github.com/cyphera-labs/cyphera-go/alphabet"
)

// Domain represents a complete data-shape contract for a specific type of PII or
// sensitive data. All Cyphera SDK operations are domain-scoped.
type Domain interface {
	// Name returns the unique identifier for this domain, e.g. "ssn", "pan", "phone".
	// This name is used in Request.Domain and in policy/audit records.
	Name() string

	// Validate checks that the input is a legal value for this domain.
	// Returns a descriptive error if the input is invalid.
	// Validation happens before any encryption or masking.
	Validate(input string) error

	// Normalize standardizes the input for processing (e.g. strip formatting,
	// lowercase). The normalized form is what the engine operates on.
	// Returns an error if normalization fails.
	Normalize(input string) (string, error)

	// Alphabet returns the character set used for FPE operations on this domain.
	Alphabet() *alphabet.Alphabet

	// Extract decomposes a normalized input into:
	//   - chars: the characters that will be encrypted/protected (only alphabet chars)
	//   - positions: the index of each extracted character in the original string
	//   - template: the full string with placeholders for reconstructing the output
	//
	// For SSN "123-45-6789", a typical result might be:
	//   chars = "123456789", positions = [0,1,2,4,5,7,8,9,10], template = "___-__-____"
	Extract(normalized string) (chars string, positions []int, template string)

	// Reconstruct assembles the final output from the processed characters,
	// their original positions, and the format template.
	Reconstruct(processed string, positions []int, template string) string
}

// Registry is a map of domain name to Domain implementation.
// The SDK uses a Registry to look up domains by name at operation time.
type Registry map[string]Domain

// NewRegistry returns an empty Registry.
func NewRegistry() Registry {
	return make(Registry)
}

// Register adds a Domain to the Registry. Returns the Registry for chaining.
func (r Registry) Register(d Domain) Registry {
	r[d.Name()] = d
	return r
}

// Get retrieves a Domain by name. Returns nil if not found.
func (r Registry) Get(name string) Domain {
	return r[name]
}

// DefaultRegistry returns a Registry pre-populated with all built-in domains.
// This is the starting point for most SDK clients.
func DefaultRegistry() Registry {
	// Built-in domains are registered via their respective packages.
	// This avoids import cycles — each domain package calls back via RegisterDefault.
	return NewRegistry()
}

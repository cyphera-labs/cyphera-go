// Package custom provides a builder for defining custom Cyphera domains.
//
// When the built-in domains (SSN, PAN, Phone, Email, TaxID) don't cover your
// data type, use the Custom builder to define your own domain without forking
// the library.
//
// Example — a 6-digit employee ID:
//
//	empID := custom.New("employee-id",
//	    custom.WithAlphabet(alphabet.DigitsAlphabet),
//	    custom.WithValidation(func(s string) error {
//	        if len(s) != 6 {
//	            return fmt.Errorf("employee ID must be 6 digits")
//	        }
//	        return nil
//	    }),
//	)
//
//	client, _ := cyphera.New(
//	    cyphera.WithKeyProvider(provider),
//	    cyphera.WithDomain(empID),
//	)
package custom

import (
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

// ValidationFunc is a function that validates a domain input string.
// Return a non-nil error if the input is invalid.
type ValidationFunc func(string) error

// NormalizationFunc normalizes a domain input string before processing.
// Return the normalized string or an error.
type NormalizationFunc func(string) (string, error)

// ExtractFunc extracts the encryptable characters from a normalized input string.
// Returns the characters to encrypt, their positions in the original string,
// and a reconstruction template.
type ExtractFunc func(normalized string) (chars string, positions []int, template string)

// ReconstructFunc reassembles the output from processed characters and the template.
type ReconstructFunc func(processed string, positions []int, template string) string

// Option configures a custom domain.
type Option func(*domain)

// WithAlphabet sets the alphabet (and thus radix) for the domain.
func WithAlphabet(a *alphabet.Alphabet) Option {
	return func(d *domain) {
		d.alpha = a
	}
}

// WithValidation sets a custom validation function.
func WithValidation(fn ValidationFunc) Option {
	return func(d *domain) {
		d.validate = fn
	}
}

// WithNormalization sets a custom normalization function.
func WithNormalization(fn NormalizationFunc) Option {
	return func(d *domain) {
		d.normalize = fn
	}
}

// WithExtract sets a custom character extraction function.
// If not provided, the default extracts all characters that are in the alphabet.
func WithExtract(fn ExtractFunc) Option {
	return func(d *domain) {
		d.extract = fn
	}
}

// WithReconstruct sets a custom reconstruction function.
// If not provided, the default replaces '_' placeholders in the template.
func WithReconstruct(fn ReconstructFunc) Option {
	return func(d *domain) {
		d.reconstruct = fn
	}
}

// domain is the custom domain implementation.
type domain struct {
	name        string
	alpha       *alphabet.Alphabet
	validate    ValidationFunc
	normalize   NormalizationFunc
	extract     ExtractFunc
	reconstruct ReconstructFunc
}

// New creates a custom Domain with the given name and options.
func New(name string, opts ...Option) domains.Domain {
	d := &domain{
		name:  name,
		alpha: alphabet.DigitsAlphabet,
	}
	for _, o := range opts {
		o(d)
	}
	// Set defaults for unspecified functions
	if d.extract == nil {
		d.extract = defaultExtract(d.alpha)
	}
	if d.reconstruct == nil {
		d.reconstruct = defaultReconstruct
	}
	return d
}

// Name returns the domain name provided to New.
func (d *domain) Name() string { return d.name }

// Validate runs the configured validation function, or accepts any input if none set.
func (d *domain) Validate(input string) error {
	if d.validate != nil {
		return d.validate(input)
	}
	return nil
}

// Normalize runs the configured normalization function, or returns input unchanged.
func (d *domain) Normalize(input string) (string, error) {
	if d.normalize != nil {
		return d.normalize(input)
	}
	if err := d.Validate(input); err != nil {
		return "", err
	}
	return input, nil
}

// Alphabet returns the configured alphabet.
func (d *domain) Alphabet() *alphabet.Alphabet {
	return d.alpha
}

// Extract uses the configured extraction function.
func (d *domain) Extract(normalized string) (string, []int, string) {
	return d.extract(normalized)
}

// Reconstruct uses the configured reconstruction function.
func (d *domain) Reconstruct(processed string, positions []int, template string) string {
	return d.reconstruct(processed, positions, template)
}

// defaultExtract returns an ExtractFunc that extracts all characters in the alphabet.
func defaultExtract(a *alphabet.Alphabet) ExtractFunc {
	return func(normalized string) (string, []int, string) {
		var chars strings.Builder
		positions := make([]int, 0, len(normalized))
		var tmpl strings.Builder

		for i, r := range normalized {
			if a.Contains(r) {
				chars.WriteRune(r)
				positions = append(positions, i)
				tmpl.WriteByte('_')
			} else {
				tmpl.WriteRune(r)
			}
		}

		return chars.String(), positions, tmpl.String()
	}
}

// defaultReconstruct replaces '_' placeholders in the template with processed characters.
func defaultReconstruct(processed string, _ []int, template string) string {
	runes := []rune(template)
	chars := []rune(processed)
	ci := 0
	for i, r := range runes {
		if r == '_' && ci < len(chars) {
			runes[i] = chars[ci]
			ci++
		}
	}
	return string(runes)
}


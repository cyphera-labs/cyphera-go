// Package pan provides the PAN (Primary Account Number / credit card) domain for Cyphera.
//
// The PAN domain handles payment card numbers in standard formats, preserving
// the visual structure (dashes, spaces) while encrypting the digits.
//
// Example:
//
//	"4111-1111-1111-1111" → "4532-8765-1234-5678"
//
// Options allow control over prefix preservation (for BIN-preserving FPE, where
// the first 6 digits — the Bank Identification Number — must be retained to allow
// routing to the correct card network).
package pan

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

const domainName = "pan"

var (
	// panPattern matches 13-19 digit card numbers, optionally separated by dashes or spaces.
	panPattern = regexp.MustCompile(`^[\d\- ]{13,24}$`)
)

// ErrInvalidPAN is returned when the input is not a recognizable card number format.
var ErrInvalidPAN = errors.New("pan: input must be a 13–19 digit card number")

// PANOption configures the PAN domain.
type PANOption func(*domain)

// WithPreserveBIN causes the first 6 digits (Bank Identification Number) to be
// passed through unencrypted, preserving card network routing information.
func WithPreserveBIN() PANOption {
	return func(d *domain) {
		d.preserveBIN = true
	}
}

// domain implements domains.Domain for payment card numbers.
type domain struct {
	preserveBIN bool
}

// New returns a PAN Domain with the provided options.
func New(opts ...PANOption) domains.Domain {
	d := &domain{}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name returns "pan".
func (d *domain) Name() string { return domainName }

// Validate checks that input is a recognizable card number format.
func (d *domain) Validate(input string) error {
	if !panPattern.MatchString(input) {
		return ErrInvalidPAN
	}
	digits := extractDigits(input)
	if len(digits) < 13 || len(digits) > 19 {
		return ErrInvalidPAN
	}
	return nil
}

// Normalize strips whitespace and returns the input as-is (preserving dashes).
func (d *domain) Normalize(input string) (string, error) {
	if err := d.Validate(input); err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// Alphabet returns the digit alphabet (radix 10).
func (d *domain) Alphabet() *alphabet.Alphabet {
	return alphabet.DigitsAlphabet
}

// Extract separates digit characters from formatting characters.
// When WithPreserveBIN is set, the first 6 digits are included in the template
// verbatim and not returned in the chars slice.
func (d *domain) Extract(normalized string) (string, []int, string) {
	var chars strings.Builder
	positions := make([]int, 0, 16)
	var tmpl strings.Builder

	digitCount := 0
	for i, r := range normalized {
		if r >= '0' && r <= '9' {
			if d.preserveBIN && digitCount < 6 {
				tmpl.WriteRune(r) // preserve BIN digit as-is
			} else {
				chars.WriteRune(r)
				positions = append(positions, i)
				tmpl.WriteByte('_')
			}
			digitCount++
		} else {
			tmpl.WriteRune(r)
		}
	}

	return chars.String(), positions, tmpl.String()
}

// Reconstruct reassembles the PAN from encrypted digits and the template.
func (d *domain) Reconstruct(processed string, positions []int, template string) string {
	runes := []rune(template)
	digits := []rune(processed)
	di := 0
	for i, r := range runes {
		if r == '_' && di < len(digits) {
			runes[i] = digits[di]
			di++
		}
	}
	return string(runes)
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

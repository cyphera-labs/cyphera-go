// Package taxid provides the Tax ID (EIN — Employer Identification Number) domain for Cyphera.
//
// The Tax ID domain handles US Employer Identification Numbers in the standard
// XX-XXXXXXX format. The dash at position 2 is preserved; the 9 digits are encrypted.
//
// Example:
//
//	"12-3456789" → "98-7654321"
//
// For international tax IDs with different formats, use the Custom domain builder.
package taxid

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

const domainName = "taxid"

var (
	// einPattern matches EINs in XX-XXXXXXX format.
	einPattern = regexp.MustCompile(`^\d{2}-\d{7}$`)

	// einDigitsPattern matches EINs as 9 raw digits.
	einDigitsPattern = regexp.MustCompile(`^\d{9}$`)
)

// ErrInvalidTaxID is returned when the input is not a valid EIN format.
var ErrInvalidTaxID = errors.New("taxid: input must be in XX-XXXXXXX or XXXXXXXXX format")

// domain implements domains.Domain for tax IDs.
type domain struct{}

// New returns a TaxID Domain.
func New() domains.Domain {
	return &domain{}
}

// Name returns "taxid".
func (d *domain) Name() string { return domainName }

// Validate checks that input is a valid EIN format.
func (d *domain) Validate(input string) error {
	if einPattern.MatchString(input) || einDigitsPattern.MatchString(input) {
		return nil
	}
	return ErrInvalidTaxID
}

// Normalize standardizes the EIN to the XX-XXXXXXX format.
func (d *domain) Normalize(input string) (string, error) {
	if einPattern.MatchString(input) {
		return input, nil
	}
	if einDigitsPattern.MatchString(input) {
		return input[:2] + "-" + input[2:], nil
	}
	return "", ErrInvalidTaxID
}

// Alphabet returns the digit alphabet (radix 10).
func (d *domain) Alphabet() *alphabet.Alphabet {
	return alphabet.DigitsAlphabet
}

// Extract separates digit characters from the dash separator.
func (d *domain) Extract(normalized string) (string, []int, string) {
	var chars strings.Builder
	positions := make([]int, 0, 9)
	var tmpl strings.Builder

	for i, r := range normalized {
		if r >= '0' && r <= '9' {
			chars.WriteRune(r)
			positions = append(positions, i)
			tmpl.WriteByte('_')
		} else {
			tmpl.WriteRune(r)
		}
	}

	return chars.String(), positions, tmpl.String()
}

// Reconstruct reassembles the tax ID from encrypted digits and the template.
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

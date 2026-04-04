// Package ssn provides the SSN (Social Security Number) domain for Cyphera.
//
// The SSN domain handles US Social Security Numbers in the standard XXX-XX-XXXX format.
// It preserves the dash separators while encrypting only the digit characters,
// ensuring that encrypted SSNs remain visually indistinguishable from real SSNs.
//
// Example:
//
//	"123-45-6789" → "987-65-4321"
//
// The dashes at positions 3 and 6 are always preserved.
// The 9 digit characters are encrypted using the configured FPE engine.
package ssn

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

const domainName = "ssn"

var (
	// ssnPattern matches SSNs in the canonical XXX-XX-XXXX format.
	ssnPattern = regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)

	// ssnDigitsPattern matches SSNs provided as 9 raw digits (no dashes).
	ssnDigitsPattern = regexp.MustCompile(`^\d{9}$`)
)

// ErrInvalidSSN is returned when the input is not a valid SSN format.
var ErrInvalidSSN = errors.New("ssn: input must be in XXX-XX-XXXX or XXXXXXXXX format")

// domain implements domains.Domain for SSNs.
type domain struct{}

// New returns a Domain for Social Security Numbers.
func New() domains.Domain {
	return &domain{}
}

// Name returns "ssn".
func (d *domain) Name() string { return domainName }

// Validate checks that input is a valid SSN format.
// Accepts both "123-45-6789" and "123456789" forms.
func (d *domain) Validate(input string) error {
	if ssnPattern.MatchString(input) || ssnDigitsPattern.MatchString(input) {
		return nil
	}
	return ErrInvalidSSN
}

// Normalize standardizes the SSN to the XXX-XX-XXXX format.
// If input is 9 raw digits, dashes are inserted.
func (d *domain) Normalize(input string) (string, error) {
	if ssnPattern.MatchString(input) {
		return input, nil
	}
	if ssnDigitsPattern.MatchString(input) {
		return input[:3] + "-" + input[3:5] + "-" + input[5:], nil
	}
	return "", ErrInvalidSSN
}

// Alphabet returns the digit alphabet (radix 10) used for SSN encryption.
func (d *domain) Alphabet() *alphabet.Alphabet {
	return alphabet.DigitsAlphabet
}

// Extract separates the 9 digit characters from the dash separators.
// Returns the digits as a contiguous string, their positions in the original,
// and a template marking digit positions with '_' and dashes with '-'.
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

// Reconstruct reassembles the SSN from encrypted digits and the original template.
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

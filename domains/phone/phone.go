// Package phone provides the Phone domain for Cyphera.
//
// The Phone domain handles phone numbers in various international and domestic formats,
// preserving the visual structure (country code, parentheses, dashes, spaces) while
// encrypting the subscriber digits.
//
// Example:
//
//	"+1 (904) 555-1212" → "+1 (904) 832-7456"
//
// By default the country code is preserved and only the subscriber portion is encrypted.
// Options allow full encryption including the country code.
package phone

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

const domainName = "phone"

// phonePattern accepts common phone number formats.
var phonePattern = regexp.MustCompile(`^[\+\d\(\)\-\. ]{7,20}$`)

// ErrInvalidPhone is returned when the input is not a recognizable phone number.
var ErrInvalidPhone = errors.New("phone: input does not look like a phone number")

// PhoneOption configures the Phone domain.
type PhoneOption func(*domain)

// WithEncryptCountryCode causes the country code digits to be encrypted
// rather than preserved. By default the country code is passed through.
func WithEncryptCountryCode() PhoneOption {
	return func(d *domain) {
		d.encryptCountryCode = true
	}
}

// domain implements domains.Domain for phone numbers.
type domain struct {
	encryptCountryCode bool
}

// New returns a Phone Domain with the provided options.
func New(opts ...PhoneOption) domains.Domain {
	d := &domain{}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name returns "phone".
func (d *domain) Name() string { return domainName }

// Validate checks that input is a recognizable phone number.
func (d *domain) Validate(input string) error {
	if !phonePattern.MatchString(input) {
		return ErrInvalidPhone
	}
	digits := extractDigits(input)
	if len(digits) < 7 {
		return ErrInvalidPhone
	}
	return nil
}

// Normalize returns the input trimmed of leading/trailing whitespace.
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

// Extract separates digit characters from formatting, optionally skipping country code digits.
func (d *domain) Extract(normalized string) (string, []int, string) {
	var chars strings.Builder
	positions := make([]int, 0, 15)
	var tmpl strings.Builder

	// Detect +CC prefix: a leading '+' followed by 1-3 digits
	hasCountryCode := len(normalized) > 0 && normalized[0] == '+'

	digitCount := 0
	for i, r := range normalized {
		if r >= '0' && r <= '9' {
			// Preserve country code (first 1-3 digits after '+') unless option says otherwise
			if hasCountryCode && !d.encryptCountryCode && digitCount < 3 {
				tmpl.WriteRune(r) // preserve as-is
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

// Reconstruct reassembles the phone number from encrypted digits and the template.
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

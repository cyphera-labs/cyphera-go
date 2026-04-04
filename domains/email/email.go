// Package email provides the Email domain for Cyphera.
//
// The Email domain handles email addresses in standard user@domain.tld format.
// It encrypts only the local part (before @) while preserving the domain suffix,
// so encrypted email addresses remain valid-looking email addresses.
//
// Example:
//
//	"user@example.com" → "xkqm@example.com"
//
// The local part is encrypted using an alphanumeric alphabet (radix 36).
// The @domain.tld portion is always preserved unchanged.
package email

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/domains"
)

const domainName = "email"

// emailPattern is a basic email format check — not RFC 5322 complete, but sufficient
// to validate that the input has a recognizable email structure.
var emailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ErrInvalidEmail is returned when the input does not look like an email address.
var ErrInvalidEmail = errors.New("email: input must be a valid email address")

// domain implements domains.Domain for email addresses.
type domain struct{}

// New returns an Email Domain.
func New() domains.Domain {
	return &domain{}
}

// Name returns "email".
func (d *domain) Name() string { return domainName }

// Validate checks that input is a recognizable email address.
func (d *domain) Validate(input string) error {
	if !emailPattern.MatchString(input) {
		return ErrInvalidEmail
	}
	return nil
}

// Normalize lowercases the email address.
func (d *domain) Normalize(input string) (string, error) {
	if err := d.Validate(input); err != nil {
		return "", err
	}
	return strings.ToLower(input), nil
}

// Alphabet returns the lowercase alphanumeric alphabet (radix 36) used for
// encrypting email local parts.
func (d *domain) Alphabet() *alphabet.Alphabet {
	return alphabet.AlphanumericAlphabet
}

// Extract returns only the local-part characters for encryption, preserving
// the @ symbol and domain as template pass-throughs.
//
// Non-alphanumeric characters in the local part (dots, underscores, plus signs)
// are preserved in the template rather than encrypted, as they contribute to
// the email's structure.
func (d *domain) Extract(normalized string) (string, []int, string) {
	atIdx := strings.LastIndex(normalized, "@")
	if atIdx < 0 {
		// Shouldn't happen after Validate/Normalize, but handle gracefully
		return normalized, nil, normalized
	}

	local := normalized[:atIdx]
	suffix := normalized[atIdx:] // "@domain.tld"

	var chars strings.Builder
	positions := make([]int, 0, len(local))
	var tmpl strings.Builder

	for i, r := range local {
		if isAlphanumeric(r) {
			chars.WriteRune(r)
			positions = append(positions, i)
			tmpl.WriteByte('_')
		} else {
			tmpl.WriteRune(r)
		}
	}

	// Append the domain suffix verbatim — it's never encrypted
	tmpl.WriteString(suffix)

	return chars.String(), positions, tmpl.String()
}

// Reconstruct assembles the email from encrypted local-part characters and the template.
func (d *domain) Reconstruct(processed string, positions []int, template string) string {
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

func isAlphanumeric(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

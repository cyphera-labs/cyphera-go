// Package mask implements the Mask protection engine — an irreversible,
// pattern-based redaction engine for display and logging use cases.
//
// Masking is not encryption. It is one-way: a masked value cannot be recovered.
// Use masking when the audience (support agent, log system, UI) needs a sanitized
// representation of the data, not the original value.
//
// Common patterns:
//   - "last_4":   "123-45-6789" → "***-**-6789"
//   - "first_6":  "4111-1111-1111-1111" → "4111-11**-****-****"
//   - "full":     "123-45-6789" → "***-**-****"
//   - "email":    "user@example.com" → "u***@example.com"
//
// This package satisfies the engine.Protector interface.
// Calling Unprotect on a Mask engine always returns ErrIrreversible.
package mask

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/cyphera-labs/cyphera-go/engine"
)

const (
	engineName = "mask"
	engineType = "mask"

	// DefaultMaskChar is the character used to replace masked digits/letters.
	DefaultMaskChar = '*'
)

// Pattern names for common masking strategies.
const (
	// PatternLast4 preserves the last 4 alphanumeric characters.
	PatternLast4 = "last_4"
	// PatternFirst6 preserves the first 6 alphanumeric characters.
	PatternFirst6 = "first_6"
	// PatternFull replaces all alphanumeric characters.
	PatternFull = "full"
	// PatternEmail preserves the domain part and first character of the local part.
	PatternEmail = "email"
)

// ErrUnknownPattern is returned when an unrecognized masking pattern is requested.
var ErrUnknownPattern = errors.New("mask: unknown masking pattern")

// Engine is the Mask engine. Safe for concurrent use.
type Engine struct {
	defaultPattern  string
	defaultMaskChar rune
}

// New returns a Mask Engine with the given default pattern and mask character.
// Pass an empty pattern to require per-operation pattern specification.
func New(defaultPattern string, defaultMaskChar rune) *Engine {
	if defaultMaskChar == 0 {
		defaultMaskChar = DefaultMaskChar
	}
	return &Engine{
		defaultPattern:  defaultPattern,
		defaultMaskChar: defaultMaskChar,
	}
}

// Apply applies the named pattern to input, replacing non-preserved characters with maskChar.
// If maskChar is 0, DefaultMaskChar is used.
func Apply(input, pattern string, maskChar rune) (string, error) {
	if maskChar == 0 {
		maskChar = DefaultMaskChar
	}

	switch pattern {
	case PatternFull:
		return maskAll(input, maskChar), nil
	case PatternLast4:
		return maskKeepLast(input, 4, maskChar), nil
	case PatternFirst6:
		return maskKeepFirst(input, 6, maskChar), nil
	case PatternEmail:
		return maskEmail(input, maskChar), nil
	default:
		return "", ErrUnknownPattern
	}
}

// LastN returns a masked version of input preserving the last n alphanumeric characters.
func LastN(input string, n int) string {
	result, _ := maskKeepLastN(input, n, DefaultMaskChar)
	return result
}

// FirstN returns a masked version of input preserving the first n alphanumeric characters.
func FirstN(input string, n int) string {
	result, _ := maskKeepFirstN(input, n, DefaultMaskChar)
	return result
}

func maskAll(input string, maskChar rune) string {
	var b strings.Builder
	for _, r := range input {
		if isAlphanumeric(r) {
			b.WriteRune(maskChar)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func maskKeepLast(input string, n int, maskChar rune) string {
	result, _ := maskKeepLastN(input, n, maskChar)
	return result
}

func maskKeepFirst(input string, n int, maskChar rune) string {
	result, _ := maskKeepFirstN(input, n, maskChar)
	return result
}

func maskKeepLastN(input string, n int, maskChar rune) (string, error) {
	runes := []rune(input)
	alphanumericCount := 0
	for _, r := range runes {
		if isAlphanumeric(r) {
			alphanumericCount++
		}
	}

	keep := alphanumericCount - n
	if keep < 0 {
		keep = 0
	}

	var b strings.Builder
	seen := 0
	for _, r := range runes {
		if isAlphanumeric(r) {
			if seen < keep {
				b.WriteRune(maskChar)
			} else {
				b.WriteRune(r)
			}
			seen++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

func maskKeepFirstN(input string, n int, maskChar rune) (string, error) {
	var b strings.Builder
	seen := 0
	for _, r := range input {
		if isAlphanumeric(r) {
			if seen < n {
				b.WriteRune(r)
			} else {
				b.WriteRune(maskChar)
			}
			seen++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

func maskEmail(input string, maskChar rune) string {
	at := strings.LastIndex(input, "@")
	if at < 0 {
		return maskAll(input, maskChar)
	}

	local := input[:at]
	domain := input[at:]

	if utf8.RuneCountInString(local) <= 1 {
		return string([]rune(local)[0]) + strings.Repeat(string(maskChar), 3) + domain
	}

	firstRune, _ := utf8.DecodeRuneInString(local)
	masked := string(firstRune) + strings.Repeat(string(maskChar), utf8.RuneCountInString(local)-1)
	return masked + domain
}

func isAlphanumeric(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// Name returns "mask".
func (e *Engine) Name() string { return engineName }

// Type returns "mask".
func (e *Engine) Type() string { return engineType }

// IsReversible returns false — masking is irreversible.
func (e *Engine) IsReversible() bool { return false }

// Protect applies the masking pattern from params.Pattern (falling back to the engine default).
func (e *Engine) Protect(plaintext string, params engine.Params) (string, error) {
	pattern := params.Pattern
	if pattern == "" {
		pattern = e.defaultPattern
	}
	if pattern == "" {
		return "", errors.New("mask: no pattern specified")
	}

	maskChar := params.MaskChar
	if maskChar == 0 {
		maskChar = e.defaultMaskChar
	}

	return Apply(plaintext, pattern, maskChar)
}

// Unprotect always returns ErrIrreversible — masked values cannot be recovered.
func (e *Engine) Unprotect(_ string, _ engine.Params) (string, error) {
	return "", &engine.ErrIrreversible{EngineName: engineName}
}

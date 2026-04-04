// Package alphabet provides the character set abstraction used by FPE engines and domains.
//
// An Alphabet maps a chosen charset to digit values [0..radix-1] and back,
// with pass-through support for non-alphabet characters (punctuation, spaces, etc.).
// The radix equals the number of characters in the alphabet.
package alphabet

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Alphabet maps a chosen charset to digit values [0..radix-1] and back.
type Alphabet struct {
	chars []rune       // index -> rune
	idx   map[rune]int // rune  -> index
	radix int
}

// NewAlphabet builds an Alphabet from unique, ordered runes.
//
// Examples:
//
//	Digits:       "0123456789"
//	Alphanumeric: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
//	Custom:       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
func NewAlphabet(charset string) (*Alphabet, error) {
	if !utf8.ValidString(charset) {
		return nil, errors.New("charset must be valid UTF-8")
	}

	seen := map[rune]bool{}
	var chars []rune
	for _, r := range charset {
		if seen[r] {
			return nil, fmt.Errorf("alphabet contains duplicate character %q", r)
		}
		seen[r] = true
		chars = append(chars, r)
	}

	if len(chars) < 2 {
		return nil, errors.New("alphabet must have at least 2 characters")
	}

	idx := make(map[rune]int, len(chars))
	for i, r := range chars {
		idx[r] = i
	}

	return &Alphabet{chars: chars, idx: idx, radix: len(chars)}, nil
}

// Radix returns the number of symbols in the alphabet.
func (a *Alphabet) Radix() int { return a.radix }

// Charset returns the raw character string of the alphabet.
func (a *Alphabet) Charset() string { return string(a.chars) }

// String returns the raw character string (alias for Charset).
func (a *Alphabet) String() string { return string(a.chars) }

// Contains reports whether the alphabet includes the given rune.
func (a *Alphabet) Contains(r rune) bool {
	_, ok := a.idx[r]
	return ok
}

// IndexOf returns the numeric value of a character in the alphabet.
// Returns -1 if the character is not in the alphabet.
func (a *Alphabet) IndexOf(r rune) int {
	v, ok := a.idx[r]
	if !ok {
		return -1
	}
	return v
}

// CharAt returns the character at position i in the alphabet.
func (a *Alphabet) CharAt(i int) (rune, error) {
	if i < 0 || i >= len(a.chars) {
		return 0, fmt.Errorf("index %d out of range for alphabet of size %d", i, len(a.chars))
	}
	return a.chars[i], nil
}

// IsValid checks if a string contains only valid characters from this alphabet.
func (a *Alphabet) IsValid(s string) bool {
	for _, r := range s {
		if _, ok := a.idx[r]; !ok {
			return false
		}
	}
	return true
}

// FilterString returns only the characters from s that are in the alphabet.
func (a *Alphabet) FilterString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if a.Contains(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Encode selects only runes present in the alphabet and returns:
//   - digits: values in [0..radix-1] suitable for FPE engines
//   - pos: original string indices where those runes appeared
//   - orig: original string as runes (for reconstruction)
//
// Non-alphabet characters (punctuation, spaces, dashes) are preserved
// in orig at their original positions and not included in digits/pos.
func (a *Alphabet) Encode(s string) (digits []int, pos []int, orig []rune) {
	rs := []rune(s)
	orig = rs
	digits = make([]int, 0, len(rs))
	pos = make([]int, 0, len(rs))

	for i, r := range rs {
		if v, ok := a.idx[r]; ok {
			digits = append(digits, v)
			pos = append(pos, i)
		}
	}

	return digits, pos, orig
}

// Decode writes mapped runes back into their original positions,
// leaving all non-alphabet runes untouched.
func (a *Alphabet) Decode(digits []int, pos []int, orig []rune) (string, error) {
	if len(digits) != len(pos) {
		return "", errors.New("digits/pos length mismatch")
	}

	out := make([]rune, len(orig))
	copy(out, orig)

	for i, p := range pos {
		d := digits[i]
		if d < 0 || d >= a.radix {
			return "", fmt.Errorf("digit %d out of range for alphabet of size %d", d, a.radix)
		}
		out[p] = a.chars[d]
	}

	return string(out), nil
}

// EnsureDomain enforces NIST guidance: radix^length >= 1,000,000.
// This is a security requirement to ensure sufficient cryptographic strength.
//
// Examples:
//   - Radix 10 (digits): need ≥ 6 characters
//   - Radix 16 (hex):    need ≥ 5 characters
//   - Radix 36 (base36): need ≥ 4 characters
func EnsureDomain(radix, length int) error {
	const floor = 1_000_000

	if length == 0 {
		return errors.New("no characters to encrypt (empty alphabet subset)")
	}
	if radix < 2 {
		return errors.New("radix must be >= 2")
	}

	r := big.NewInt(int64(radix))
	n := new(big.Int).Exp(r, big.NewInt(int64(length)), nil)

	if n.Cmp(big.NewInt(floor)) < 0 {
		minLength := 1
		testPower := big.NewInt(int64(radix))
		for testPower.Cmp(big.NewInt(floor)) < 0 {
			minLength++
			testPower.Mul(testPower, r)
		}
		return fmt.Errorf("domain too small: radix %d with %d characters gives %s possible values, need ≥ 1,000,000 (minimum length for radix %d is %d)",
			radix, length, n.String(), radix, minLength)
	}

	return nil
}

// Character set constants.
const (
	Digits       = "0123456789"
	Hex          = "0123456789abcdef"
	HexUpper     = "0123456789ABCDEF"
	Letters      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LettersLow   = "abcdefghijklmnopqrstuvwxyz"
	Alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	Base36       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Base36Low    = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// Pre-built common alphabets.
var (
	DigitsAlphabet       *Alphabet
	HexAlphabet          *Alphabet
	HexUpperAlphabet     *Alphabet
	LettersAlphabet      *Alphabet
	LettersLowAlphabet   *Alphabet
	AlphanumericAlphabet *Alphabet
	Base36Alphabet       *Alphabet
	Base36LowAlphabet    *Alphabet
)

func init() {
	DigitsAlphabet, _ = NewAlphabet(Digits)
	HexAlphabet, _ = NewAlphabet(Hex)
	HexUpperAlphabet, _ = NewAlphabet(HexUpper)
	LettersAlphabet, _ = NewAlphabet(Letters)
	LettersLowAlphabet, _ = NewAlphabet(LettersLow)
	AlphanumericAlphabet, _ = NewAlphabet(Alphanumeric)
	Base36Alphabet, _ = NewAlphabet(Base36)
	Base36LowAlphabet, _ = NewAlphabet(Base36Low)
}

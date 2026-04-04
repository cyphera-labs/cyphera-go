// Package alphabet defines the character set abstraction used by FPE engines and domains.
// Both FF1 and FF3 require an alphabet to determine the radix and the mapping between
// characters and their numeric values. Domains reference alphabets to define the
// characters that will be encrypted versus passed through unchanged.
package alphabet

import (
	"fmt"
	"strings"
)

// Alphabet represents an ordered set of characters used as the symbol space for FPE.
// The radix equals the number of characters in the alphabet.
type Alphabet struct {
	chars  string
	index  map[rune]int
	radix  int
}

// DigitsAlphabet is the standard decimal alphabet (radix 10).
var DigitsAlphabet = mustNew("0123456789")

// AlphanumericAlphabet is the standard alphanumeric alphabet (radix 36).
var AlphanumericAlphabet = mustNew("0123456789abcdefghijklmnopqrstuvwxyz")

// UpperAlphanumericAlphabet is the uppercase alphanumeric alphabet (radix 36).
var UpperAlphanumericAlphabet = mustNew("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")

// HexAlphabet is the hexadecimal alphabet (radix 16).
var HexAlphabet = mustNew("0123456789abcdef")

// NewAlphabet creates an Alphabet from the given character string.
// The string must contain at least 2 unique characters and no duplicates.
func NewAlphabet(chars string) (*Alphabet, error) {
	if len(chars) < 2 {
		return nil, fmt.Errorf("alphabet must have at least 2 characters")
	}

	index := make(map[rune]int, len(chars))
	for i, r := range chars {
		if _, dup := index[r]; dup {
			return nil, fmt.Errorf("alphabet contains duplicate character %q", r)
		}
		index[r] = i
	}

	return &Alphabet{
		chars: chars,
		index: index,
		radix: len([]rune(chars)),
	}, nil
}

// Radix returns the number of symbols in the alphabet.
func (a *Alphabet) Radix() int {
	return a.radix
}

// Contains reports whether the alphabet includes the given rune.
func (a *Alphabet) Contains(r rune) bool {
	_, ok := a.index[r]
	return ok
}

// IndexOf returns the numeric value of a character in the alphabet.
// Returns -1 if the character is not in the alphabet.
func (a *Alphabet) IndexOf(r rune) int {
	v, ok := a.index[r]
	if !ok {
		return -1
	}
	return v
}

// CharAt returns the character at position i in the alphabet.
func (a *Alphabet) CharAt(i int) (rune, error) {
	runes := []rune(a.chars)
	if i < 0 || i >= len(runes) {
		return 0, fmt.Errorf("index %d out of range for alphabet of size %d", i, len(runes))
	}
	return runes[i], nil
}

// String returns the raw character string of the alphabet.
func (a *Alphabet) String() string {
	return a.chars
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

func mustNew(chars string) *Alphabet {
	a, err := NewAlphabet(chars)
	if err != nil {
		panic(err)
	}
	return a
}

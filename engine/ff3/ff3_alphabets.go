package ff3

// Canonical alphabets (order is part of the spec).
const (
	AlphaDigits    = "0123456789"
	AlphaHexLower  = "0123456789abcdef"
	AlphaHexUpper  = "0123456789ABCDEF"
	AlphaBase36Low = "0123456789abcdefghijklmnopqrstuvwxyz"
	AlphaBase36Up  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AlphaBase62    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// AlphabetSpec defines a charset — no normalization, pure format preservation.
type AlphabetSpec struct {
	Charset string
}

// Built-in specs.
var (
	SpecDigits    = AlphabetSpec{Charset: AlphaDigits}
	SpecHexLower  = AlphabetSpec{Charset: AlphaHexLower}
	SpecHexUpper  = AlphabetSpec{Charset: AlphaHexUpper}
	SpecBase36Low = AlphabetSpec{Charset: AlphaBase36Low}
	SpecBase36Up  = AlphabetSpec{Charset: AlphaBase36Up}
	SpecBase62    = AlphabetSpec{Charset: AlphaBase62}
)

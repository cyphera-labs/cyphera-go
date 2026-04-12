package ff1

import (
	"encoding/hex"
	"testing"
)

func h(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

const DIGITS = "0123456789"
const ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz"

func nist(t *testing.T, keyHex, tweakHex, alphabet, pt, ct string) {
	t.Helper()
	key := h(keyHex)
	var tweak []byte
	if tweakHex != "" {
		tweak = h(tweakHex)
	}
	c, err := New(key, tweak, alphabet)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	encrypted, err := c.Encrypt(pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encrypted != ct {
		t.Errorf("Encrypt(%s) = %s, want %s", pt, encrypted, ct)
	}
	decrypted, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != pt {
		t.Errorf("Decrypt(%s) = %s, want %s", ct, decrypted, pt)
	}
}

// NIST SP 800-38G FF1 test vectors — AES-128
func TestSample1(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3C", "", DIGITS, "0123456789", "2433477484")
}
func TestSample2(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3C", "39383736353433323130", DIGITS, "0123456789", "6124200773")
}
func TestSample3(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3C", "3737373770717273373737", ALPHANUMERIC, "0123456789abcdefghi", "a9tv40mll9kdu509eum")
}

// NIST SP 800-38G FF1 test vectors — AES-192
func TestSample4(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "", DIGITS, "0123456789", "2830668132")
}
func TestSample5(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "39383736353433323130", DIGITS, "0123456789", "2496655549")
}
func TestSample6(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "3737373770717273373737", ALPHANUMERIC, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr")
}

// NIST SP 800-38G FF1 test vectors — AES-256
func TestSample7(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "", DIGITS, "0123456789", "6657667009")
}
func TestSample8(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "39383736353433323130", DIGITS, "0123456789", "1001623463")
}
func TestSample9(t *testing.T) {
	nist(t, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "3737373770717273373737", ALPHANUMERIC, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd")
}

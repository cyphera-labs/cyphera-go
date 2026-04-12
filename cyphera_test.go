package cyphera

import (
	"os"
	"path/filepath"
	"testing"
)

var testConfig = Config{
	Policies: map[string]Policy{
		"ssn":          {Engine: "ff1", KeyRef: "test-key", Tag: "T01"},
		"ssn_digits":   {Engine: "ff1", Alphabet: "digits", KeyRef: "test-key", TagEnabled: boolPtr(false)},
		"ssn_mask":     {Engine: "mask", Pattern: "last4", TagEnabled: boolPtr(false)},
		"ssn_hash":     {Engine: "hash", Algorithm: "sha256", KeyRef: "test-key", TagEnabled: boolPtr(false)},
	},
	Keys: map[string]map[string]string{
		"test-key": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"},
	},
}

func boolPtr(b bool) *bool { return &b }

func TestProtectAccessWithTag(t *testing.T) {
	c, err := FromConfig(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := c.Protect("123456789", "ssn")
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) <= len("123456789") {
		t.Error("protected should be longer than input")
	}
	if protected[:3] != "T01" {
		t.Errorf("expected tag T01, got %s", protected[:3])
	}
	accessed, err := c.Access(protected)
	if err != nil {
		t.Fatal(err)
	}
	if accessed != "123456789" {
		t.Errorf("roundtrip failed: got %s", accessed)
	}
}

func TestProtectAccessWithPassthroughs(t *testing.T) {
	c, _ := FromConfig(testConfig)
	protected, _ := c.Protect("123-45-6789", "ssn")
	if !contains(protected, '-') {
		t.Error("dashes should be preserved")
	}
	accessed, _ := c.Access(protected)
	if accessed != "123-45-6789" {
		t.Errorf("roundtrip failed: got %s", accessed)
	}
}

func TestUntaggedDigitsRoundtrip(t *testing.T) {
	c, _ := FromConfig(testConfig)
	protected, _ := c.Protect("123456789", "ssn_digits")
	if len(protected) != 9 {
		t.Errorf("untagged should be same length, got %d", len(protected))
	}
	accessed, _ := c.Access(protected, "ssn_digits")
	if accessed != "123456789" {
		t.Errorf("roundtrip failed: got %s", accessed)
	}
}

func TestDeterministic(t *testing.T) {
	c, _ := FromConfig(testConfig)
	a, _ := c.Protect("123456789", "ssn")
	b, _ := c.Protect("123456789", "ssn")
	if a != b {
		t.Error("should be deterministic")
	}
}

func TestMaskLast4(t *testing.T) {
	c, _ := FromConfig(testConfig)
	result, _ := c.Protect("123-45-6789", "ssn_mask")
	if result != "*******6789" {
		t.Errorf("mask failed: got %s", result)
	}
}

func TestHashDeterministic(t *testing.T) {
	c, _ := FromConfig(testConfig)
	a, _ := c.Protect("123-45-6789", "ssn_hash")
	b, _ := c.Protect("123-45-6789", "ssn_hash")
	if a != b {
		t.Error("hash should be deterministic")
	}
}

func TestTagCollision(t *testing.T) {
	_, err := FromConfig(Config{
		Policies: map[string]Policy{
			"a": {Engine: "ff1", KeyRef: "k", Tag: "ABC"},
			"b": {Engine: "ff1", KeyRef: "k", Tag: "ABC"},
		},
		Keys: map[string]map[string]string{
			"k": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"},
		},
	})
	if err == nil {
		t.Error("should error on tag collision")
	}
}

func TestKeySourceEnv(t *testing.T) {
	os.Setenv("TEST_CYPHERA_KEY", "2B7E151628AED2A6ABF7158809CF4F3C")
	defer os.Unsetenv("TEST_CYPHERA_KEY")

	c, err := FromConfig(Config{
		Policies: map[string]Policy{
			"ssn": {Engine: "ff1", KeyRef: "k", Tag: "T01"},
		},
		Keys: map[string]map[string]string{
			"k": {"source": "env", "var": "TEST_CYPHERA_KEY"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.Protect("123456789", "ssn")
	if p[:3] != "T01" {
		t.Error("should have tag")
	}
	a, _ := c.Access(p)
	if a != "123456789" {
		t.Errorf("roundtrip failed: got %s", a)
	}
}

func TestKeySourceFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	os.WriteFile(path, []byte("2B7E151628AED2A6ABF7158809CF4F3C"), 0644)

	c, err := FromConfig(Config{
		Policies: map[string]Policy{
			"ssn": {Engine: "ff1", KeyRef: "k", Tag: "T01"},
		},
		Keys: map[string]map[string]string{
			"k": {"source": "file", "path": path},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.Protect("123456789", "ssn")
	a, _ := c.Access(p)
	if a != "123456789" {
		t.Errorf("roundtrip failed: got %s", a)
	}
}

func TestKeySourceEnvMatchesInline(t *testing.T) {
	os.Setenv("TEST_CYPHERA_KEY2", "2B7E151628AED2A6ABF7158809CF4F3C")
	defer os.Unsetenv("TEST_CYPHERA_KEY2")

	cInline, _ := FromConfig(testConfig)
	cEnv, _ := FromConfig(Config{
		Policies: testConfig.Policies,
		Keys: map[string]map[string]string{
			"test-key": {"source": "env", "var": "TEST_CYPHERA_KEY2"},
		},
	})
	p1, _ := cInline.Protect("123456789", "ssn")
	p2, _ := cEnv.Protect("123456789", "ssn")
	if p1 != p2 {
		t.Errorf("env source should match inline: %s != %s", p1, p2)
	}
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

package cyphera

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	protected, err := c.Protect("123456789", "ssn")
	require.NoError(t, err)
	assert.Greater(t, len(protected), len("123456789"), "protected should be longer than input")
	assert.Equal(t, "T01", protected[:3])

	accessed, err := c.Access(protected)
	require.NoError(t, err)
	assert.Equal(t, "123456789", accessed, "roundtrip failed")
}

func TestProtectAccessWithPassthroughs(t *testing.T) {
	c, err := FromConfig(testConfig)
	require.NoError(t, err)

	protected, err := c.Protect("123-45-6789", "ssn")
	require.NoError(t, err)
	assert.Contains(t, protected, "-")

	accessed, err := c.Access(protected)
	require.NoError(t, err)
	assert.Equal(t, "123-45-6789", accessed, "roundtrip failed")
}

func TestUntaggedDigitsRoundtrip(t *testing.T) {
	c, err := FromConfig(testConfig)
	require.NoError(t, err)

	protected, err := c.Protect("123456789", "ssn_digits")
	require.NoError(t, err)
	assert.Len(t, protected, 9, "untagged should be same length")

	accessed, err := c.Access(protected, "ssn_digits")
	require.NoError(t, err)
	assert.Equal(t, "123456789", accessed, "roundtrip failed")
}

func TestDeterministic(t *testing.T) {
	c, err := FromConfig(testConfig)
	require.NoError(t, err)

	a, err := c.Protect("123456789", "ssn")
	require.NoError(t, err)
	b, err := c.Protect("123456789", "ssn")
	require.NoError(t, err)
	assert.Equal(t, a, b, "should be deterministic")
}

func TestMaskLast4(t *testing.T) {
	c, err := FromConfig(testConfig)
	require.NoError(t, err)

	result, err := c.Protect("123-45-6789", "ssn_mask")
	require.NoError(t, err)
	assert.Equal(t, "*******6789", result, "mask failed")
}

func TestHashDeterministic(t *testing.T) {
	c, err := FromConfig(testConfig)
	require.NoError(t, err)

	a, err := c.Protect("123-45-6789", "ssn_hash")
	require.NoError(t, err)
	b, err := c.Protect("123-45-6789", "ssn_hash")
	require.NoError(t, err)
	assert.Equal(t, a, b, "hash should be deterministic")
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
	assert.Error(t, err, "should error on tag collision")
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
	require.NoError(t, err)

	p, err := c.Protect("123456789", "ssn")
	require.NoError(t, err)
	assert.Equal(t, "T01", p[:3])

	a, err := c.Access(p)
	require.NoError(t, err)
	assert.Equal(t, "123456789", a, "roundtrip failed")
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
	require.NoError(t, err)

	p, err := c.Protect("123456789", "ssn")
	require.NoError(t, err)

	a, err := c.Access(p)
	require.NoError(t, err)
	assert.Equal(t, "123456789", a, "roundtrip failed")
}

func TestKeySourceEnvMatchesInline(t *testing.T) {
	os.Setenv("TEST_CYPHERA_KEY2", "2B7E151628AED2A6ABF7158809CF4F3C")
	defer os.Unsetenv("TEST_CYPHERA_KEY2")

	cInline, err := FromConfig(testConfig)
	require.NoError(t, err)

	cEnv, err := FromConfig(Config{
		Policies: testConfig.Policies,
		Keys: map[string]map[string]string{
			"test-key": {"source": "env", "var": "TEST_CYPHERA_KEY2"},
		},
	})
	require.NoError(t, err)

	p1, err := cInline.Protect("123456789", "ssn")
	require.NoError(t, err)

	p2, err := cEnv.Protect("123456789", "ssn")
	require.NoError(t, err)

	assert.Equal(t, p1, p2, "env source should match inline")
}

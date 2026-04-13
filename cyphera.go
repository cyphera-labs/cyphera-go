// Package cyphera provides a data protection SDK with format-preserving encryption,
// data masking, and hashing. Policy-driven, cross-language compatible.
package cyphera

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"sort"
	"strings"

	"github.com/cyphera-labs/cyphera-go/engine/ff1"
	"github.com/cyphera-labs/cyphera-go/engine/ff3"
)

var cloudSources = map[string]bool{
	"aws-kms": true, "gcp-kms": true, "azure-kv": true, "vault": true,
}

func resolveKeySource(name, source string, config map[string]string) ([]byte, error) {
	switch source {
	case "env":
		varName, ok := config["var"]
		if !ok || varName == "" {
			return nil, fmt.Errorf("key '%s': source 'env' requires 'var' field", name)
		}
		val := os.Getenv(varName)
		if val == "" {
			return nil, fmt.Errorf("key '%s': environment variable '%s' is not set", name, varName)
		}
		encoding := config["encoding"]
		if encoding == "" {
			encoding = "hex"
		}
		if encoding == "base64" {
			return base64.StdEncoding.DecodeString(val)
		}
		return hex.DecodeString(val)

	case "file":
		path, ok := config["path"]
		if !ok || path == "" {
			return nil, fmt.Errorf("key '%s': source 'file' requires 'path' field", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("key '%s': failed to read file '%s': %w", name, path, err)
		}
		raw := strings.TrimSpace(string(data))
		encoding := config["encoding"]
		if encoding == "" {
			if strings.HasSuffix(path, ".b64") || strings.HasSuffix(path, ".base64") {
				encoding = "base64"
			} else {
				encoding = "hex"
			}
		}
		if encoding == "base64" {
			return base64.StdEncoding.DecodeString(raw)
		}
		return hex.DecodeString(raw)
	}

	if cloudSources[source] {
		return nil, fmt.Errorf(
			"key '%s' requires source '%s' but cyphera-keychain is not available.\n"+
				"See: github.com/cyphera-labs/keychain", name, source)
	}

	return nil, fmt.Errorf("key '%s': unknown source '%s'. Valid: env, file, aws-kms, gcp-kms, azure-kv, vault", name, source)
}

var defaultAlphabets = map[string]string{
	"digits":       "0123456789",
	"alpha_lower":  "abcdefghijklmnopqrstuvwxyz",
	"alpha_upper":  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alpha":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

func resolveAlphabet(name string) string {
	if name == "" {
		return defaultAlphabets["alphanumeric"]
	}
	if a, ok := defaultAlphabets[name]; ok {
		return a
	}
	return name
}

// Policy represents a named protection policy.
type Policy struct {
	Engine     string `json:"engine"`
	Alphabet   string `json:"alphabet,omitempty"`
	KeyRef     string `json:"key_ref,omitempty"`
	Tag        string `json:"tag,omitempty"`
	TagEnabled *bool  `json:"tag_enabled,omitempty"`
	TagLength  int    `json:"tag_length,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
}

func (p Policy) isTagEnabled() bool {
	if p.TagEnabled == nil {
		return true
	}
	return *p.TagEnabled
}

// Config is the JSON policy file structure.
type Config struct {
	Policies map[string]Policy            `json:"policies"`
	Keys     map[string]map[string]string `json:"keys"`
}

// Cyphera is the main SDK client.
type Cyphera struct {
	policies map[string]Policy
	tagIndex map[string]string
	keys     map[string][]byte
}

// Load auto-discovers cyphera.json.
func Load() (*Cyphera, error) {
	if p := os.Getenv("CYPHERA_POLICY_FILE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return FromFile(p)
		}
	}
	if _, err := os.Stat("cyphera.json"); err == nil {
		return FromFile("cyphera.json")
	}
	if _, err := os.Stat("/etc/cyphera/cyphera.json"); err == nil {
		return FromFile("/etc/cyphera/cyphera.json")
	}
	return nil, fmt.Errorf("no policy file found")
}

// FromFile loads from a JSON policy file.
func FromFile(path string) (*Cyphera, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return FromConfig(config)
}

// FromConfig creates a client from a Config struct.
func FromConfig(config Config) (*Cyphera, error) {
	c := &Cyphera{
		policies: config.Policies,
		tagIndex: make(map[string]string),
		keys:     make(map[string][]byte),
	}
	for name, kv := range config.Keys {
		if m, ok := kv["material"]; ok {
			key, err := hex.DecodeString(m)
			if err != nil {
				return nil, fmt.Errorf("bad key hex for %s: %w", name, err)
			}
			c.keys[name] = key
		} else if source, ok := kv["source"]; ok {
			key, err := resolveKeySource(name, source, kv)
			if err != nil {
				return nil, err
			}
			c.keys[name] = key
		} else {
			return nil, fmt.Errorf("key '%s' must have either 'material' or 'source'", name)
		}
	}
	for name, pol := range config.Policies {
		if pol.isTagEnabled() {
			if pol.Tag == "" {
				return nil, fmt.Errorf("policy '%s' has tag_enabled=true but no tag", name)
			}
			if existing, ok := c.tagIndex[pol.Tag]; ok {
				return nil, fmt.Errorf("tag collision: '%s' used by '%s' and '%s'", pol.Tag, existing, name)
			}
			c.tagIndex[pol.Tag] = name
		}
	}
	return c, nil
}

// Protect encrypts a value using the named policy.
func (c *Cyphera) Protect(value, policyName string) (string, error) {
	pol, ok := c.policies[policyName]
	if !ok {
		return "", fmt.Errorf("unknown policy: %s", policyName)
	}
	switch pol.Engine {
	case "ff1":
		return c.protectFPE(value, pol, false)
	case "ff3":
		return c.protectFPE(value, pol, true)
	case "mask":
		return c.protectMask(value, pol)
	case "hash":
		return c.protectHash(value, pol)
	default:
		return "", fmt.Errorf("unknown engine: %s", pol.Engine)
	}
}

// Access decrypts a protected value. Without policyName, uses tag-based lookup.
func (c *Cyphera) Access(protectedValue string, policyName ...string) (string, error) {
	if len(policyName) > 0 && policyName[0] != "" {
		pol, ok := c.policies[policyName[0]]
		if !ok {
			return "", fmt.Errorf("unknown policy: %s", policyName[0])
		}
		return c.accessFPE(protectedValue, pol, true)
	}
	tags := make([]string, 0, len(c.tagIndex))
	for t := range c.tagIndex {
		tags = append(tags, t)
	}
	sort.Slice(tags, func(i, j int) bool { return len(tags[i]) > len(tags[j]) })
	for _, tag := range tags {
		if strings.HasPrefix(protectedValue, tag) {
			pol := c.policies[c.tagIndex[tag]]
			return c.accessFPE(protectedValue, pol, false)
		}
	}
	return "", fmt.Errorf("no matching tag found")
}

func (c *Cyphera) protectFPE(value string, pol Policy, isFF3 bool) (string, error) {
	key := c.keys[pol.KeyRef]
	if key == nil {
		return "", fmt.Errorf("unknown key: %s", pol.KeyRef)
	}
	alphabet := resolveAlphabet(pol.Alphabet)
	enc, pos, ch := extractPassthroughs(value, alphabet)
	if enc == "" {
		return "", fmt.Errorf("no encryptable characters")
	}
	var encrypted string
	var err error
	if isFF3 {
		cipher, e := ff3.New(key, make([]byte, 8), alphabet)
		if e != nil {
			return "", e
		}
		encrypted, err = cipher.Encrypt(enc)
	} else {
		cipher, e := ff1.New(key, nil, alphabet)
		if e != nil {
			return "", e
		}
		encrypted, err = cipher.Encrypt(enc)
	}
	if err != nil {
		return "", err
	}
	result := reinsertPassthroughs(encrypted, pos, ch)
	if pol.isTagEnabled() && pol.Tag != "" {
		return pol.Tag + result, nil
	}
	return result, nil
}

func (c *Cyphera) accessFPE(protectedValue string, pol Policy, explicitPolicy bool) (string, error) {
	if pol.Engine != "ff1" && pol.Engine != "ff3" {
		return "", fmt.Errorf("cannot reverse '%s'", pol.Engine)
	}
	key := c.keys[pol.KeyRef]
	if key == nil {
		return "", fmt.Errorf("unknown key: %s", pol.KeyRef)
	}
	alphabet := resolveAlphabet(pol.Alphabet)
	withoutTag := protectedValue
	if !explicitPolicy && pol.isTagEnabled() && pol.Tag != "" {
		withoutTag = protectedValue[len(pol.Tag):]
	}
	enc, pos, ch := extractPassthroughs(withoutTag, alphabet)
	var decrypted string
	var err error
	if pol.Engine == "ff3" {
		cipher, e := ff3.New(key, make([]byte, 8), alphabet)
		if e != nil {
			return "", e
		}
		decrypted, err = cipher.Decrypt(enc)
	} else {
		cipher, e := ff1.New(key, nil, alphabet)
		if e != nil {
			return "", e
		}
		decrypted, err = cipher.Decrypt(enc)
	}
	if err != nil {
		return "", err
	}
	return reinsertPassthroughs(decrypted, pos, ch), nil
}

func (c *Cyphera) protectMask(value string, pol Policy) (string, error) {
	if pol.Pattern == "" {
		return "", fmt.Errorf("mask requires 'pattern'")
	}
	n := len(value)
	switch pol.Pattern {
	case "last4", "last_4":
		return strings.Repeat("*", max(0, n-4)) + value[max(0, n-4):], nil
	case "last2", "last_2":
		return strings.Repeat("*", max(0, n-2)) + value[max(0, n-2):], nil
	case "first1", "first_1":
		return value[:min(1, n)] + strings.Repeat("*", max(0, n-1)), nil
	case "first3", "first_3":
		return value[:min(3, n)] + strings.Repeat("*", max(0, n-3)), nil
	default:
		return strings.Repeat("*", n), nil
	}
}

func (c *Cyphera) protectHash(value string, pol Policy) (string, error) {
	algo := strings.ToLower(strings.ReplaceAll(pol.Algorithm, "-", ""))
	if algo == "" {
		algo = "sha256"
	}
	data := []byte(value)
	if pol.KeyRef != "" {
		key := c.keys[pol.KeyRef]
		if key == nil {
			return "", fmt.Errorf("unknown key: %s", pol.KeyRef)
		}
		var h func() hash.Hash
		switch algo {
		case "sha256":
			h = sha256.New
		case "sha384":
			h = sha512.New384
		case "sha512":
			h = sha512.New
		default:
			return "", fmt.Errorf("unsupported algorithm: %s", algo)
		}
		mac := hmac.New(h, key)
		mac.Write(data)
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
	switch algo {
	case "sha256":
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:]), nil
	case "sha384":
		s := sha512.Sum384(data)
		return hex.EncodeToString(s[:]), nil
	case "sha512":
		s := sha512.Sum512(data)
		return hex.EncodeToString(s[:]), nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

func extractPassthroughs(value, alphabet string) (string, []int, []rune) {
	var enc strings.Builder
	var positions []int
	var chars []rune
	for i, r := range value {
		if strings.ContainsRune(alphabet, r) {
			enc.WriteRune(r)
		} else {
			positions = append(positions, i)
			chars = append(chars, r)
		}
	}
	return enc.String(), positions, chars
}

func reinsertPassthroughs(encrypted string, positions []int, chars []rune) string {
	runes := []rune(encrypted)
	for i, pos := range positions {
		if pos <= len(runes) {
			runes = append(runes[:pos], append([]rune{chars[i]}, runes[pos:]...)...)
		} else {
			runes = append(runes, chars[i])
		}
	}
	return string(runes)
}

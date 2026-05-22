// Package cyphera provides a data protection SDK with format-preserving encryption,
// data masking, and hashing. Configuration-driven, cross-language compatible.
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
	"sync"

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

// Configuration represents a named protection configuration.
type Configuration struct {
	Engine        string `json:"engine"`
	Alphabet      string `json:"alphabet,omitempty"`
	KeyRef        string `json:"key_ref,omitempty"`
	Header        string `json:"header,omitempty"`
	HeaderEnabled *bool  `json:"header_enabled,omitempty"`
	HeaderLength  int    `json:"header_length,omitempty"`
	Pattern       string `json:"pattern,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
}

func (c Configuration) isHeaderEnabled() bool {
	if c.HeaderEnabled == nil {
		return true
	}
	return *c.HeaderEnabled
}

// Config is the JSON configuration file structure.
type Config struct {
	Configurations map[string]Configuration     `json:"configurations"`
	Keys           map[string]map[string]string `json:"keys"`
}

// Cyphera is the main SDK client.
type Cyphera struct {
	configurations map[string]Configuration
	headerIndex    map[string]string
	keys           map[string][]byte
}

// Load auto-discovers cyphera.json.
func Load() (*Cyphera, error) {
	if p := os.Getenv("CYPHERA_CONFIG_FILE"); p != "" {
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
	return nil, fmt.Errorf("no configuration file found")
}

// FromFile loads from a JSON configuration file.
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
		configurations: config.Configurations,
		headerIndex:    make(map[string]string),
		keys:           make(map[string][]byte),
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
	for name, cfg := range config.Configurations {
		if cfg.isHeaderEnabled() {
			if cfg.Header == "" {
				return nil, fmt.Errorf("configuration '%s' has header_enabled=true but no header", name)
			}
			if existing, ok := c.headerIndex[cfg.Header]; ok {
				return nil, fmt.Errorf("header collision: '%s' used by '%s' and '%s'", cfg.Header, existing, name)
			}
			c.headerIndex[cfg.Header] = name
		}
	}
	return c, nil
}

var ff3DeprecationOnce sync.Once

// warnFF3Deprecated emits the FF3 deprecation warning to stderr, once per
// process. Original FF3 is cryptographically weak; configurations should use
// the 'ff31' engine.
func warnFF3Deprecated() {
	ff3DeprecationOnce.Do(func() {
		fmt.Fprintln(os.Stderr, "WARNING: engine 'ff3' is deprecated and cryptographically weak — migrate to 'ff31' (FF3-1).")
	})
}

// Protect encrypts a value using the named configuration.
func (c *Cyphera) Protect(value, configurationName string) (string, error) {
	cfg, ok := c.configurations[configurationName]
	if !ok {
		return "", fmt.Errorf("unknown configuration: %s", configurationName)
	}
	switch cfg.Engine {
	case "ff1", "ff3", "ff31":
		return c.protectFPE(value, cfg)
	case "mask":
		return c.protectMask(value, cfg)
	case "hash":
		return c.protectHash(value, cfg)
	default:
		return "", fmt.Errorf("unknown engine: %s", cfg.Engine)
	}
}

// Access reverses a protected value. The SDK uses the loaded configurations
// to figure out which one applies — it checks the leading bytes of the
// value against the registered headers (longest first to avoid prefix
// collisions), strips the matched header, and decrypts.
//
// For unique situations where the protected value has no header, use the
// AccessWithConfig(name, value) escape hatch.
func (c *Cyphera) Access(protectedValue string) (string, error) {
	headers := make([]string, 0, len(c.headerIndex))
	for h := range c.headerIndex {
		headers = append(headers, h)
	}
	sort.Slice(headers, func(i, j int) bool { return len(headers[i]) > len(headers[j]) })
	for _, header := range headers {
		if strings.HasPrefix(protectedValue, header) {
			cfg := c.configurations[c.headerIndex[header]]
			// Strip the header here — accessFPE always assumes headerless input.
			return c.accessFPE(protectedValue[len(header):], cfg)
		}
	}
	return "", fmt.Errorf("no matching header found")
}

// AccessWithConfig is the escape-hatch reverse path for unique situations
// where the protected value has no header (mainframe formats, fixed-width
// legacy systems, etc.). The caller names the configuration explicitly and
// the value is decrypted as raw headerless ciphertext.
//
// Prefer Access(value) for normal use — that's the primary API. This form
// is intentionally not promoted in examples.
//
// Errors if the configuration is unknown or its engine is irreversible
// (mask/hash). There is no header_enabled guard — the caller is asserting
// that value has no header.
func (c *Cyphera) AccessWithConfig(configurationName, value string) (string, error) {
	cfg, ok := c.configurations[configurationName]
	if !ok {
		return "", fmt.Errorf("unknown configuration: %s", configurationName)
	}
	return c.accessFPE(value, cfg)
}

func (c *Cyphera) protectFPE(value string, cfg Configuration) (string, error) {
	key := c.keys[cfg.KeyRef]
	if key == nil {
		return "", fmt.Errorf("unknown key: %s", cfg.KeyRef)
	}
	alphabet := resolveAlphabet(cfg.Alphabet)
	enc, pos, ch := extractPassthroughs(value, alphabet)
	if enc == "" {
		return "", fmt.Errorf("no encryptable characters")
	}
	var encrypted string
	var err error
	switch cfg.Engine {
	case "ff3":
		warnFF3Deprecated()
		cipher, e := ff3.New(key, make([]byte, 8), alphabet)
		if e != nil {
			return "", e
		}
		encrypted, err = cipher.Encrypt(enc)
	case "ff31":
		cipher, e := ff3.NewFF31(key, make([]byte, 7), alphabet)
		if e != nil {
			return "", e
		}
		encrypted, err = cipher.Encrypt(enc)
	default:
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
	if cfg.isHeaderEnabled() && cfg.Header != "" {
		return cfg.Header + result, nil
	}
	return result, nil
}

// accessFPE decrypts a headerless ciphertext using the given configuration.
// Callers are responsible for stripping any DPH before calling — Access
// does the strip itself, and AccessWithConfig is the escape hatch where
// the caller asserts the input has no header.
func (c *Cyphera) accessFPE(protectedValue string, cfg Configuration) (string, error) {
	if cfg.Engine != "ff1" && cfg.Engine != "ff3" && cfg.Engine != "ff31" {
		return "", fmt.Errorf("cannot reverse '%s'", cfg.Engine)
	}
	key := c.keys[cfg.KeyRef]
	if key == nil {
		return "", fmt.Errorf("unknown key: %s", cfg.KeyRef)
	}
	alphabet := resolveAlphabet(cfg.Alphabet)
	enc, pos, ch := extractPassthroughs(protectedValue, alphabet)
	var decrypted string
	var err error
	switch cfg.Engine {
	case "ff3":
		warnFF3Deprecated()
		cipher, e := ff3.New(key, make([]byte, 8), alphabet)
		if e != nil {
			return "", e
		}
		decrypted, err = cipher.Decrypt(enc)
	case "ff31":
		cipher, e := ff3.NewFF31(key, make([]byte, 7), alphabet)
		if e != nil {
			return "", e
		}
		decrypted, err = cipher.Decrypt(enc)
	default:
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

func (c *Cyphera) protectMask(value string, cfg Configuration) (string, error) {
	if cfg.Pattern == "" {
		return "", fmt.Errorf("mask requires 'pattern'")
	}
	n := len(value)
	switch cfg.Pattern {
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

func (c *Cyphera) protectHash(value string, cfg Configuration) (string, error) {
	algo := strings.ToLower(strings.ReplaceAll(cfg.Algorithm, "-", ""))
	if algo == "" {
		algo = "sha256"
	}
	data := []byte(value)
	if cfg.KeyRef != "" {
		key := c.keys[cfg.KeyRef]
		if key == nil {
			return "", fmt.Errorf("unknown key: %s", cfg.KeyRef)
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

package cyphera

import (
	"github.com/cyphera-labs/cyphera-go/domains"
	"github.com/cyphera-labs/cyphera-go/engine"
	"github.com/cyphera-labs/cyphera-go/keys"
	"github.com/cyphera-labs/cyphera-go/ops"
)

// config holds the resolved configuration for a Client.
// It is built up by applying Option functions to a zero-value config.
type config struct {
	keyProvider    keys.Provider
	domainRegistry domains.Registry
	engines        map[string]engine.Engine
	logger         ops.Logger
	policy         ops.Policy
	defaultKeyRef  string
	defaultEngine  string
}

// Option is a functional option for configuring a Cyphera Client.
type Option func(*config) error

// WithKeyProvider sets the key provider used to resolve key references.
// This is required for all Encrypt and Decrypt operations.
func WithKeyProvider(p keys.Provider) Option {
	return func(c *config) error {
		c.keyProvider = p
		return nil
	}
}

// WithDomain registers a custom or additional Domain in the client's registry.
// The domain is identified by its Name() return value.
// This option may be applied multiple times to register multiple domains.
func WithDomain(d domains.Domain) Option {
	return func(c *config) error {
		if c.domainRegistry == nil {
			c.domainRegistry = domains.NewRegistry()
		}
		c.domainRegistry.Register(d)
		return nil
	}
}

// WithEngine registers an additional engine by name in the client's engine registry.
// This allows custom or third-party engines to be used via the SDK.
func WithEngine(e engine.Engine) Option {
	return func(c *config) error {
		if c.engines == nil {
			c.engines = make(map[string]engine.Engine)
		}
		c.engines[e.Name()] = e
		return nil
	}
}

// WithLogger sets the audit logger. If not set, audit events are discarded.
// Use ops.NewJSONLogger or ops.NewStdLogger for production deployments.
func WithLogger(l ops.Logger) Option {
	return func(c *config) error {
		c.logger = l
		return nil
	}
}

// WithPolicy sets the policy enforcer. Policies govern which keys may be used
// with which domains and whether deprecated keys are accepted for encryption.
func WithPolicy(p ops.Policy) Option {
	return func(c *config) error {
		if err := p.Validate(); err != nil {
			return err
		}
		c.policy = p
		return nil
	}
}

// WithDefaultKeyRef sets the key reference used when a Request does not specify one.
func WithDefaultKeyRef(ref string) Option {
	return func(c *config) error {
		c.defaultKeyRef = ref
		return nil
	}
}

// WithDefaultEngine sets the engine name used when no engine is specified by the domain
// or policy. Defaults to "adf1".
func WithDefaultEngine(name string) Option {
	return func(c *config) error {
		c.defaultEngine = name
		return nil
	}
}

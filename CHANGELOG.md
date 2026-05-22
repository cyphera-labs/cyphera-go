# Changelog

## v0.2 (unreleased)

Breaking schema change.

- Rename JSON key `policies` → `configurations` in `cyphera.json`.
- Rename JSON key `tag` → `header`.
- Rename JSON key `tag_enabled` → `header_enabled`.
- Rename JSON key `tag_length` → `header_length`.
- Rename Go type `Policy` → `Configuration`.
- Rename `Config.Policies` field → `Configurations`.
- Rename env var `CYPHERA_POLICY_FILE` → `CYPHERA_CONFIG_FILE`.
- Method parameter `policyName` → `configurationName`.
- Error messages updated: "policy not found" → "configuration not found",
  "tag collision" → "header collision", etc.

No behavioral change. Update your `cyphera.json` to use the new keys.
The `header` (Data Protection Header, DPH) is the short prefix prepended
to protected output identifying the configuration used.

API change.

- `Access(value)` is the primary one-argument method. The SDK uses the
  loaded configurations and their headers to figure out which one applies
  (longest-prefix match), strips the header, and decrypts.
- `AccessWithConfig(configurationName, value)` is the escape hatch for
  unique situations where the protected value has no header (mainframe
  formats, fixed-width legacy systems, etc.). The caller names the
  configuration explicitly; the value is decrypted as raw headerless
  ciphertext. Errors only if the configuration is unknown or its engine
  is irreversible (mask/hash) — there is no header_enabled guard.
- The `AccessByHeader(value)` alias is gone — `Access(value)` is the
  header-driven form.

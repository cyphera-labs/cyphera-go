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

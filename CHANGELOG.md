# Changelog

Changes to the public contract are recorded here. Versions follow Semantic Versioning.

## 0.2.0 (2026-10-17)

### Changed

- Organize vendor parsers as `Baseline::<Vendor>::Parser`, with Hillstone and Palo Alto `Document` classes beside their parsers. Shared parsing uses `Baseline::Parser`, `Comware::Parser`, and `Cisco::Parser`; platform entry points load independently.
- Rename extraction helpers and ACL/credential APIs to describe their purpose: `permitted_source_networks`, `source_network`, `address_range`, `network_prefixes`, `networks_within?`, and `record_credential`. Remove redundant immutable-data and range-subtraction wrappers.
- Replace `snmp.read_only` with `snmp.write_enabled`. Set `expected: false` to prohibit writes. Old class names, methods, and rule keys have no compatibility aliases; update custom callers and policies.
- Require `ctx_parser ~> 0.2.0` for the shared configuration API.

### Fixed

- Keep out-of-policy source findings unknown for incomplete ordered ACL input: an unseen earlier deny can change the permitted sources. Report caller input completeness separately from parser status.
- Copy ACL names and management bindings without freezing or borrowing caller-owned strings.
- Preserve NTP source and source-interface command recognition across the shared Cisco and Comware parser families.

### Performance and verification

- Compare IPv4 network unions and rejected sources with sorted scans, and index credential source lines to avoid quadratic lookups.
- Add regression coverage, independent platform loading checks, and synthetic benchmarks. Verify installed default policy and compliance behavior outside the checkout.

## 0.1.0 (2026-10-16)

### Added

- Configuration facts, declarative baseline policies, vendor adapters, and explainable compliance reports.
- Standalone RubyGems packaging under `baseline-rb` with the `baseline` require path and `Baseline` namespace.
- English and Chinese documentation, an offline example, and standalone RSpec/RuboCop development tasks.
- Linux/macOS CI, isolated package verification, and automatic RubyGems and GitHub Releases with identical artifacts.

### Fixed

- Keep ACL exposure unknown when paging interrupts its source rules.
- Copy configuration identity strings without freezing caller-owned values.

### Changed

- Cross-module dependencies resolve through RubyGems/Bundler instead of relative sibling paths.
- Motor persistence and application-specific adapters remain in the host application.

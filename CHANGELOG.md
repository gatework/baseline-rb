# Changelog

Changes to the public contract are recorded here. Versions follow Semantic Versioning.

## Unreleased

- Expose immutable scoped syslog resources through `Evidence#resources`, retaining Comware/VRP, IOS/NX-OS, StoneOS category and PAN-OS profile/server identities alongside existing audit facts. Mark unparsed options incomplete and exclude them from resource data.
- Keep Cisco syslog destinations in other VRFs when a destination in one VRF is cancelled.

- Keep H3C SSH ACL denial logging separate from ACL bindings, so enabling or disabling logging cannot hide missing management restrictions.
- Distinguish Huawei log destination domains and source-port controls; source-port declarations no longer inflate syslog server counts or invalidate source-interface evidence.
- Normalize split Comware/VRP NTP and syslog source interface type/number declarations and recognize their resets.

## 0.3.1 (2026-10-18)

- Withhold IOS SNMP ACL facts after contradictory community access declarations, while accepting equivalent repeats and preserving NX-OS incremental attributes.

- Clear Bundler bootstrap variables when verifying packages in an isolated gem installation, including calls made through bundle exec.

- Remove cancelled IOS SNMP communities and their credential evidence before deriving access and permission facts.

- Keep management restrictions unknown when vendor ACL rules repeat an explicit sequence identity.
- Stop reusing Cisco TACACS login methods after the final named list is cancelled or malformed; independent lists remain available.

## 0.3.0 (2026-10-18)

- Breaking: rename mutable fact assembly to `FactBuilder`, immutable parsed snapshots to `Evidence`, multiline quoted-value documents to `MultilineDocument`, and the PAN-OS prefix lookup to `CommandIndex#matching_prefix`.
- Name parser pipeline actions `parse_*`, fact/diagnostic mutations `record_*`, regular-expression providers `*_pattern`, and policy branch selection `resolve_with_path`; rename IPv4 range/CIDR conversions to describe their results. Update require paths and callers without compatibility aliases.

- Reject malformed ACL `host` operands rather than interpreting them as unrestricted addresses in ordered deny rules.
- Require explicit fact capability declarations so new policy rules do not automatically advertise vendor support.
- Resolve the final PAN-OS management-profile binding per interface scope while retaining other interfaces independently.

- Standardize vendor NTP, Syslog, and SNMP hooks under a shared pipeline; keep syntax extraction in the vendor adapters and permission reduction in `FactBuilder`.
- Add Hillstone SNMPv3 group permissions, user authentication/privacy, safe credential metadata, and IPv4 polling-source evaluation.
- Expose immutable per-rule vendor implementation coverage via `Audit.capabilities(platform:)`, shared platform normalization, and explicit unknown diagnostics for unmodeled capabilities.

- Declare the `ctx_parser` runtime dependency without a version constraint; application lockfiles control reproducible installation versions.

- Validate Cisco/Comware server addresses before counting NTP, Syslog, or TACACS endpoints; malformed endpoint declarations remain unknown and supported endpoint cancellations remove prior entries.
- Preserve VRF identity while reducing supported NTP declarations and validate their full option lists; keep unsupported or malformed options unknown. Reduce IOS logging aliases in source order and discard removed TACACS host keys.
- Evaluate modeled management, source-interface, and AAA declarations in configuration order, preserving cancellations and malformed replacements instead of falling back to older values. Reject malformed final hostname declarations across all platforms.
- Diagnose multi-line PAN-OS interface bindings and handle malformed externally supplied credential facts without raising internal exceptions.
- Let `CtxParser::Result` own snapshot freezing and copying, avoiding a duplicate traversal of facts and diagnostic trees.

- Keep incomplete and unsupported SNMP group declarations unknown instead of proving absent write permission; reject malformed Cisco version tokens without raising an internal exception.
- Build each `FactBuilder#build` snapshot independently; replaced management/SNMP evidence, resolved group references, and source-free values no longer retain stale derived facts, diagnostics, or source lines.
- Index PAN-OS statements by decoded token prefixes with bounded depth, and reuse network deviations during evaluation, avoiding repeated full-export scans, excessive indexing of malformed tails, and duplicate network comparisons.

## 0.2.1 (2026-10-17)

- Reject duplicate normalized context keys before policy selection; preserve source lines and cursor captures for scalar NTP and Syslog configuration facts.

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

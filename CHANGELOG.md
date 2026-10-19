# Changelog

Changes to the public contract are recorded here. Versions follow Semantic Versioning.

## 0.4.0 (2026-10-19)

- Keep Cisco TACACS key evidence per endpoint identity, preventing another named object at the same canonical address from supplying missing material.
- Treat malformed Cisco TACACS key material and address withdrawals as unresolved evidence rather than certifying a complete active inventory.
- Reduce Cisco named TACACS server deletion, recreation, address replacement and object/global key withdrawal before deriving references, resources or credentials.
- Resolve Cisco TACACS group address members canonically while keeping named server references distinct; reject missing-object/DNS-name collisions, fold group reentry/withdrawal, and retain unresolved membership evidence without secret tails.

- Canonicalize server address identity across resource fields, resolved approvals, legacy address/count rules, withdrawals, reference inventories and typed operation fingerprints; fold IPv6 spellings and ASCII DNS case without changing named objects or scopes.
- Reject canonical duplicate structured approvals and malformed legacy address policies before planning, retain absolute/relative DNS distinctions, and prevent invalid-input text leaking through nested address validation exceptions.

- Block Syslog/NTP IP alias transitions and duplicate native identities before capacity planning, preventing an add/remove pair from deleting the approved endpoint; preserve distinct roles and scopes. Protect TACACS observed fallback/capacity counts against the same aliases. Explicit unresolved NTP authentication evidence also blocks new unkeyed targets.

- Record final Comware/VRP NTP key material metadata, trust state, association configuration prerequisites and sanitized credential evidence; reject stale material/trust/switch updates without masking independently proven unsafe storage.
- Reuse existing trusted NTP keys for newly approved associations only with external peer-compatibility verification; retain renderer dependency guards and verify convergence through an independent command model.

- List SNMP write-grant review requirements per anonymous community, group definition and known user reference; preserve view/security/ACL dependencies and unresolved evidence without generating permission or secret commands.

- Generate nonsecret Comware 7 TACACS endpoint changes within existing default-routing schemes, preserving role keys and shared domain references; require explicit targets, scope, external fallback/key verification and capacity evidence.
- Protect physical primary slots, native endpoint identity, last-role paths and intermediate secondary capacity; verify native command application and repeated planning with an independent test model.
- Treat unmodelled scheme VPN and same-address multiport inventory as unknown rather than proving a default-scope object.

- Respect vendor name identity: fold Comware HWTACACS scheme reentry/removal, but require exact Huawei template and named AAA scheme references while keeping domain matching separate.

- Add typed TACACS `aaa.domain` binding policies, exact reference-set comparison, selected-domain predicates, and explicit object-only verification scope.
- Inventory unselected Comware/VRP domain references without dropping shared uses; incomplete or unsupported binding evidence stays unknown.
- Expose object and binding audit capabilities separately and retain shared-reference approval requirements without emitting binding changes.
- Retain immutable resource values through fact construction, append binding evidence without reparsing identity, and share owned authentication graph views.

- Derive Comware/VRP TACACS usage from selected-domain AAA bindings, preserving ordered methods, local fallback/none, role endpoints, VTY evidence and provenance.
- Reject stale domain selections and malformed Huawei method tails; model Comware login/default inheritance and explicitly represented built-in domains.
- Provide object-specific management AAA approval/evidence requirements without selecting unapproved candidate groups or generating authentication changes.

- Keep only the final H3C primary TACACS server per responsibility, apply unqualified resets, and retain multiple secondary servers; replaced primary addresses cannot inflate redundancy or remain as resources.

- Reduce Comware/VRP TACACS scheme keys in order across replacement, withdrawal, and reopened/deleted schemes; exclude stale credentials and resources.
- Report missing or unresolved scheme key material by responsibility and known endpoint, retaining manual peer/AAA/fallback prerequisites without secret commands.

- Require validated Comware/VRP SNMP commands as implicit enable evidence; preserve ordered explicit state and the H3C password-calculation exception.
- Report per-object credential rotation/material and external-strength-evidence requirements without producing secret-bearing commands; retain SNMP authentication/privacy and Comware/VRP TACACS key purposes.

- Intersect H3C global, group, and user SNMP ACLs; report fully parsed unbound IPv4 principals as unrestricted rather than unknown.
- Generate conditional H3C global SNMP ACL creation/binding without rewriting secrets or per-principal filters; reject cross-domain fresh ACL allocation conflicts.
- Parse SNMP access options by argument position, preserve safe group definitions, replace stale H3C VACM user/credential state, and recognize command-wide cipher qualifiers and documented SHA-2 names.

- Extend dedicated IPv4 management ACL rendering to Huawei and IOS, preserving existing IOS VRF qualifiers and requiring explicit VRF scope on initial bindings.
- Bind ACL identity collision checks to the same immutable input snapshot as the audit; scan all candidates in one pass and conservatively reject proposed identities appearing even in unmodelled commands.

- Preserve management endpoint protocol/port differences and intersect chained SSH/VTY ACL source permissions.
- Generate guarded H3C IPv4 dedicated basic ACL creation and VTY rebinding, retaining stricter permissions and existing shared ACLs; require explicit initial targets and reject occupied or referenced ACL numbers.
- Show the highest operation risk in human-readable remediation plans.

- Fold H3C SNMP version enable/removal state and reject stale version evidence after malformed commands.
- Generate guarded H3C SNMP version removals only with existing authPriv/group evidence and explicit manual v3 access verification; retain principals and ACLs.

- Respect the H3C VTY authentication/transport inheritance pair; range overrides no longer inherit a passing counterpart from the line class. Malformed range resets cannot fall back to valid class settings.

- Generate scoped H3C/Huawei/IOS VTY protocol narrowing with SSH enable prerequisites, overlap rejection, explicit compatible range authentication guards, and cross-rule conflict detection.
- Generate explicitly approved H3C/Huawei/NX-OS SSH service shutdowns as high-risk review operations without altering key material; keep enablement blocked pending key/endpoint evidence.

- Extend coordinated target planning to NTP server/peer associations on H3C, Huawei, IOS, and NX-OS; retain correct association attributes and peers under legacy server-list checks, and withhold unauthenticated additions under authentication requirements.

- Extend syslog target rendering to verified Huawei, IOS, NX-OS, and StoneOS syntax subsets with exact scope/category handling and convergence regressions. Block unresolved IOS parallel transports and named-default VRFs instead of deleting by an ambiguous identity.

- Generate H3C syslog target additions, removals, and attribute replacements with atomic rendering, retained unmanaged options, shared count/address/object constraints, capacity-aware ordering, and independently modelled convergence tests.
- Expose capacity provenance and early-removal decisions in per-check plan details. Reject ambiguous named-default routing scopes and reserved CLI keywords as destination names.

- Add an offline `Remediation` entry point and immutable manual-review plans containing source/policy identities, a result for every enabled metric, typed setting operations, guarded single-line commands, and explicit unresolved requirements. Partial support remains visible rather than claiming complete remediation.
- Render selected source-interface, SSHv2, and service changes with separate vendor command classes; reject command injection and invalid PAN-OS interface spellings, and withhold service-route interface changes with unresolved source-address dependencies.

- Add optional structured syslog destination, NTP association, and TACACS endpoint rules with explicit managed scopes, typed approved attributes, missing/unexpected/changed differences, and conservative handling of unverified defaults. The default policy retains its original 30 checks.
- Retain TACACS endpoint roles, priorities, scheme/profile identity, ports, and routing domains without storing key values in resources.

- Retain scoped NTP association resources, including separate server/peer identities, source interfaces, version, preference, key references, and PAN-OS primary/secondary slots without secret values.
- Count distinct NTP, syslog, and TACACS servers rather than duplicate observations; compare approved server sets independently of duplicate observations.
- Keep malformed applicability facts unknown instead of using them to exclude security checks.
- Add explicit acceptance cases for all 30 baseline metrics, covering passing, deviating, missing evidence, missing approval, out-of-scope, incomplete, and unsupported syntax states.

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

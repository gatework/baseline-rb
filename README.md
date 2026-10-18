# baseline-rb

[简体中文](README-zh.md) | [Source](https://github.com/gatework/baseline-rb) | [Changelog](CHANGELOG.md)

Policy-driven configuration baseline checks for network devices. It turns previously collected configuration text into normalized facts, evaluates explicit approved values, and produces explainable compliance reports.

## Features

- Configuration adapters for H3C, Huawei, Cisco IOS/IOS-XE, Cisco NX-OS, Hillstone, and Palo Alto.
- SNMP, NTP, Syslog, SSH, management ACLs, services, credential metadata, and TACACS.
- Declarative YAML policies with host/model/site/role/vendor scopes.
- Source fingerprints, safe findings, coverage, and readable or structured reports.

## Installation

Requires **Ruby 4.0.6 or newer**. Add this line to your application's `Gemfile`:

```ruby
gem "baseline-rb", require: "baseline"
```

Then run `bundle install`, or install directly with `gem install baseline-rb`. The require path is `baseline` and the public namespace is `Baseline`; package names and Ruby namespaces are intentionally separate.

Internal runtime dependencies: [`ctx_parser`](https://github.com/gatework/ctx_parser). The gemspec declares `ctx_parser` without a version constraint for the shared configuration API. Applications should commit their own `Gemfile.lock` to make deployments reproducible. No Rails boot or sibling checkout paths are required.

Release artifacts and checksums are available from [GitHub Releases](https://github.com/gatework/baseline-rb/releases). Check [RubyGems](https://rubygems.org/gems/baseline-rb) for published versions.

## Offline example

From a development checkout after installing dependencies:

```sh
bundle exec ruby examples/offline.rb
```

The example uses synthetic data and performs no network access:

```ruby
require "baseline"

# 批准值独立于本例的合成配置声明。
policy = Baseline::Policy.new(
  "version" => 1,
  "checks" => { "ssh.enabled" => { "expected" => true, "severity" => "high" } }
)
report = Baseline::Audit.new(policy: policy).call(
  configuration: "sysname EXAMPLE-SWITCH\nssh server enable\nreturn\n",
  platform: :h3c,
  complete: true,
  context: { host: "192.0.2.10" }
)
puts report.to_text
# 仅检查显式选择的 SSH 配置项；不据此判断设备可达性。
```

## Public contract and limits

`Policy.new(definition)`, `Policy.load(path)`, and `Policy.default` construct validated policies. `Audit.new(policy:).call(configuration:, platform:, complete: false, context: {})` returns a `Report` with `to_text`, `to_h`, `summary`, and `compliant?`. The bundled [policy.yml](policy.yml) is a starting point; organization-specific approved values are intentionally unset.

Checks use `pass`, `fail`, `unknown`, and `not_applicable`. Missing approved values and unsupported syntax remain unknown. Partial input can preserve independently proven violations but cannot prove compliance. Configuration cannot prove reachability, NTP synchronization, or an authentication server being available.

Management-source checks currently model supported IPv4 ACL semantics. PAN-OS input is a local complete `set` export, not XML or expanded Panorama templates. Password ciphertext is never decrypted or used to claim strength. Raw configuration and secrets must not enter report storage.

The library performs no device access, backup collection, remediation execution, or database writes. Motor persistence and `Baseline::Check` belong to the host application.

`Evidence#resources` exposes immutable syslog, NTP, and TACACS objects with vendor identities, scopes, options, and source lines. `ConfigurationResource#complete?` describes understood object syntax; it does not establish input completeness, active references, or compliance. Unsupported options are excluded from resource data.

`Remediation.new(policy:).call(configuration:, platform:, complete: false, context: {})` returns a manual-review plan with its audit, per-check results, operations, steps, configuration commands, and serialization. Statuses are `noop/ready/partial/blocked`; unresolved checks remain visible. Commands never execute or save configuration. Current rendering covers selected source-interface, SSHv2, and service settings; full object changes, ACL, SNMP, and authentication-chain rendering remain in development. `Remediation.capabilities(platform:)` reports actual command coverage separately from parsing capabilities. See [the offline example](examples/remediation.rb).

Optional `syslog.destinations`, `ntp.associations`, and `tacacs.endpoints` rules compare arrays of objects containing `identity`, `scope`, and optional `attributes`. Only declared attributes are managed. `managed_scopes` explicitly enables detection of unwanted objects within those scopes; omitting it checks approved objects and attributes without treating unrelated objects as unwanted. Unverified attribute defaults remain unknown. The default policy retains its original 30 checks; these three object rules require explicit approval data.

H3C syslog plans can add/remove destinations and replace attributes while retaining unmanaged options and checking related server-count/address constraints. Structured changes require explicit managed scopes. Net additions require verified device capacity in the rule's `remediation.maximum_targets`; a pure swap may use observed occupancy as a conservative capacity lower bound and remove wrong targets first. Plans expose the capacity source and ordering. `remediation.order: remove_before_add` explicitly prioritizes removal. No generated command is executed by this library.

Additional syslog renderers support a verified subset of Huawei domain/VPN targets, IOS transport/port targets, NX-OS severity/facility/VRF targets, and StoneOS transport/port event/config category targets. Unknown native options block an entire metric's operations before any command is exposed. NX-OS port extensions, IOS parallel transport identity, and PAN-OS target changes remain unsupported by these renderers.

NTP target planning supports modelled server/peer objects on H3C, Huawei, IOS, and NX-OS. Legacy server-list rules retain peer associations; structured association rules explicitly manage their declared scopes. Server counts and approved addresses constrain the same projected configuration. Existing key references may be retained, but a new key ID does not establish key material. Authentication requirements block unauthenticated additions; complete key/trust-chain provisioning remains pending.

VTY protocol narrowing is available for non-overlapping H3C/Huawei/IOS ranges when SSH enable evidence exists. H3C/Huawei additionally require explicit compatible authentication in each edited range (scheme/aaa); inherited authentication alone blocks generation because range protocol edits can change its effective behavior. Authentication and ACL commands are preserved. Explicit approved SSH shutdowns are supported for H3C/Huawei/NX-OS and marked high risk. Conflicting SSH-only and SSH-disabled requirements block changes. SSH key provisioning and selecting new authentication chains remain unresolved prerequisites, not silently generated defaults.

H3C SNMP version narrowing only disables unapproved versions. It requires existing enabled v3, authPriv users with resolved group references, and `remediation: {existing_v3_access_verified: true}` on the `snmp.versions` rule. This records manual verification of a working v3 management path; backups cannot establish it. User/group withdrawal evidence blocks generation until fully modelled. Operations are high risk, retain users/communities/ACLs, and neither provision v3 users nor remove all active versions. Other vendors and complete SNMP permission/authentication correction remain pending.

IPv4 management ACL planning creates fresh ACLs before rebinding H3C `line vty`, Huawei `user-interface vty`, and IOS `line vty` ranges. H3C/Huawei use basic ACL numbers 2000–2999; IOS uses standard ACL numbers 1–99/1300–1999 or names beginning with a letter and passing the library token whitelist (at most 253 bytes). Supply approved `management.sources` limits and `remediation.access_targets`; initial bindings also require explicit `sources`. IOS preserves existing `vrf-also`; initial bindings require a boolean `vrf_also` approval, and source tightening cannot change an existing VRF scope.

Existing access is intersected with approved limits; explicit targets cannot expand it. A proposed ACL identity occurring anywhere in the same input is conservatively occupied, including unmodelled commands, comments, and banners; numeric matches recognize leading zeros. Old ACLs and their SNMP/business references remain untouched. Empty intersections require explicit `sources: []`. Unresolved evidence, overlapping ranges, and unrepresentable protocol/port differences block the metric. NX-OS/firewalls, IPv6, legacy H3C `user-interface`, and complex ACL rendering remain pending. See the [example](examples/remediation_access.rb).

H3C SNMP source planning can create a fresh basic ACL and bind it with `snmp-agent acl`, retaining communities, users, groups, and tighter per-principal ACLs. Supply `snmp.sources` limits and `remediation.access_targets` with `{endpoint: "snmp.global", acl: "2005"}`; unbound principals also require explicit `sources`. If the backup has no global command evidence, `global_acl_supported: true` must confirm firmware support. Existing global permissions cannot expand. Management and SNMP plans allocating the same fresh ACL on one device block each other. See the [SNMP example](examples/remediation_snmp_access.rb).

SNMP assessment now intersects H3C global/group/user ACLs, identifies communities by anonymous sequence numbers, and keeps IPv6-only ACLs separate from IPv4 controls. Completely parsed unbound principals are unrestricted; malformed/unsupported access remains unknown. H3C VACM users use their latest complete definition and credential records; Huawei split configuration remains incremental. Nonsecret group view/security definitions are retained, while complete MIB-view permission modelling and group changes remain pending.

Detailed vendor behavior, historical validation notes, and Motor-only integration are preserved in [the architecture reference](docs/architecture-zh.md). Host integration examples in that reference require Motor; they are not standalone gem APIs. Motor adapters live under `backend/lib/baseline`, `backend/lib/vxlan`, and `backend/lib/wireless` in the [Motor repository](https://github.com/gatework/motor/tree/main/backend/lib).

## Domain vocabulary

`FactBuilder` assembles configuration evidence; `Policy` supplies approved values; `Evaluator` produces compliance findings. `Acl#permitted_source_networks` returns the IPv4 networks permitted by ordered rules for a protocol and destination port: `nil` means unresolved evidence, while `[]` means no permitted sources. `FactBuilder#record_credential` records safe credential attributes. Partial evidence may establish a conclusive violation, but cannot establish compliance.

Vendor-specific code lives in a vendor namespace: `Baseline::Hillstone::Parser` and `Baseline::Hillstone::Document` reside in `baseline/hillstone/`; Palo Alto uses the same layout. The six platform parsers inherit shared behavior from `Baseline::Parser`, `Comware::Parser`, or `Cisco::Parser`. Load only one platform with `require "baseline/hillstone/parser"`, or load the assessment API with `require "baseline"`.

Parser helpers describe the evidence they extract: `matching_blocks`, `configured_values`, `last_configured_value`, `configured_state`, and `parse_acl_source_network`. SNMP write permission uses the policy key `snmp.write_enabled` (`expected: false` to prohibit writes). Update custom policies that used `snmp.read_only`; old class names and rule keys have no compatibility aliases.

Context accepts string or symbol keys, but rejects duplicate keys after normalization with `ArgumentError` rather than selecting a device policy by insertion order.

`complete: true` asserts that the caller supplied the entire snapshot. Reports retain that assertion as `input_complete`, separately from parser status. A partial ordered ACL cannot prove an out-of-policy source: an unseen earlier deny may change its meaning, so the finding stays `unknown`.

## Shared vendor capabilities

All adapters follow the same management, NTP, Syslog, SNMP, and authentication pipeline and return the same `Evidence` / `Report` contracts. Cisco and Comware families share syntax where it is equivalent; native firewall endpoints use their own syntax and produce the same management-source facts. `FactBuilder` owns cross-command permission and evidence reduction; `Evaluator` does not branch on vendor.

Query implementation coverage without supplying a device configuration:

```ruby
Baseline::Audit.capabilities(platform: :stoneos)["snmp.auth_priv"]
# => { fact: "snmp.v3_auth_priv", status: :supported, reason: nil }
Baseline::Audit.capabilities(platform: :panos)["tacacs.accounting"]
# => { fact: "tacacs.accounting", status: :unsupported, reason: :platform_semantics_unresolved }
```

The deeply frozen result contains every public rule. New facts require explicit adapter capability declarations; adding a policy rule alone does not advertise implementation support. Status is `supported`, `partial`, or `unsupported`; it describes implemented evidence extraction, not runtime availability or support for every vendor release. The same platform aliases apply to queries and audits. `Audit.normalize_platform(name)` exposes the canonical platform name.

| Capability | H3C / Huawei | IOS / NX-OS | Hillstone | Palo Alto |
| --- | --- | --- | --- | --- |
| NTP servers, authentication, source | Supported | Supported | Supported | Supported |
| Syslog servers and source | Supported | Supported | Supported | Supported |
| SNMP versions, writes, v3 auth/privacy | Supported | Supported | Supported | Supported |
| IPv4 management / SNMP source ranges | Supported | Supported | Supported | Supported |
| SSH enabled | Supported | Supported | Supported | Supported |
| Explicit SSH versions and VTY checks | Supported | Supported | Unmodeled | Unmodeled |
| Credential storage and observable strength | Supported | Supported | Supported | Supported |
| TACACS servers, keys, login | Supported | Supported | Supported | Supported |
| TACACS authorization | Supported | Supported | Supported | Unmodeled |
| TACACS accounting | Supported | Supported | Unmodeled | Unmodeled |
| Disabled service set | Supported | Supported | Partial | Partial |

Hillstone service state covers Telnet, HTTP, HTTPS, and FTP; Palo Alto covers Telnet, HTTP, and HTTPS. Missing service states remain unknown. Native firewall endpoints do not provide router-style VTY facts. These checks are retained as `unknown` with `unsupported_capability` diagnostics, rather than excluded or treated as compliance. Protocol reachability and opaque password strength remain unobservable across all vendors.

Hillstone v3 extraction follows the formal group/user syntax in the [StoneOS CLI guide](https://kb.hillstonenet.com/en/wp-content/uploads/2017/11/StoneOS_CLI_User_Guide_Complete_Book_5.5R5-1.pdf): `auth-protocol` and `enc-protocol` user options, explicit group write views, and IPv4 remote hosts. Unsupported algorithms, IPv6 remote users, removals, unresolved groups, or v3 host entries without user evidence remain unknown. User security comes from configured user evidence, not the group's required security level.

## Naming and object responsibilities

Names identify the object lifecycle and the method's result or side effect. `FactBuilder` accumulates evidence and `build` returns an independent parser result; `Evidence` owns the immutable snapshot used for evaluation; `MultilineDocument` isolates multiline quoted values; `PaloAlto::CommandIndex` searches commands by token prefix. Vendor `Parser` and command-mapped names retain their domain meaning.

| Previous name | Current name | Meaning |
| --- | --- | --- |
| `Facts`, `baseline/facts` | `FactBuilder`, `baseline/fact_builder` | Mutable fact assembly |
| `Configuration`, `baseline/configuration` | `Evidence`, `baseline/evidence` | Immutable evidence snapshot |
| `QuotedDocument`, `baseline/quoted_document` | `MultilineDocument`, `baseline/multiline_document` | Multiline quoted-value boundaries |
| `PaloAlto::Statements#at` | `PaloAlto::CommandIndex#matching_prefix` | All statements with a token prefix |
| `Facts#result` | `FactBuilder#build` | Build a fresh result snapshot |
| `Facts#record` / `unknown` | `FactBuilder#record_fact` / `record_unknown_fact` | Record facts or diagnostics |
| `Facts#management` / `snmp` | `FactBuilder#record_management_access` / `record_snmp_access` | Update management or SNMP evidence |
| `Facts#direct_acl` | `FactBuilder#record_source_restriction` | Record native source ranges, without a named ACL |
| `Configuration#value` / `known?` / `scope_known?` | `Evidence#fact` / `fact_known?` / `applicability_fact_known?` | Query a fact and its evidence availability |
| `Policy#resolve_with_source` | `Policy#resolve_with_path` | Return the value, reason, and policy branch path |
| `Acl.address_range` / `network_prefixes` | `Acl.ipv4_range` / `cidrs_from_ranges` | Convert IPv4 CIDRs and integer ranges |

Internal pipeline steps use `parse_*`; writers use `record_*`; regex providers use `*_pattern`. A tristate result uses `*_state` rather than a boolean predicate, and parsing/validation helpers name what they parse. Plain established names such as `Policy`, `Rule`, `Acl`, `Credential`, `Evaluator`, `Report`, `to_h`, and `inspect` remain appropriate. Old names and require paths have no aliases. Rule IDs, fact keys, and report JSON retain their business vocabulary.

## Development and tests

Name shared classes by their responsibility and use the namespace for platform context. Preserve filenames and class names that directly match device commands.

```sh
bundle install
bundle exec rake
bundle exec ruby examples/offline.rb
bundle exec rake build
```

`bundle exec rake` runs RSpec, RuboCop, and the offline examples. Tests live in `spec/`, following the existing project's RSpec convention; fixtures use synthetic or sanitized evidence. Add regression cases for successful, incomplete, unsupported, and malformed inputs when extending a parser. Offline tests do not certify all device versions or replace live integration checks.

Run `bundle exec ruby -Ilib script/benchmark.rb` for synthetic network-coverage, credential-lookup, rejected-source report, PAN-OS account parsing, and fact snapshot timings. It reports the median of three runs at two input sizes; compare revisions on the same runtime and machine.

Use the declared minimum Ruby version for compatibility checks. Document source methods and non-obvious business logic in concise Chinese, preserve public return/error contracts, and never add raw device captures or credentials to examples, fixtures, logs, or release archives.

## Release

This directory can be maintained as the independent [baseline-rb](https://github.com/gatework/baseline-rb) repository. Update `VERSION` and `CHANGELOG.md`, run the validation and build commands above, and inspect the packaged file list before tagging `vVERSION`.

CI runs tests, lint, examples, build, and an isolated installation on Linux and macOS. After CI passes on `main`, push `vVERSION` to run the release workflow. It publishes the tested Linux artifact to RubyGems and GitHub Releases, attaches `SHA256SUMS`, and verifies downloaded bytes. The GitHub `release` environment accepts a `RUBYGEMS_API_KEY` secret; without it, configure RubyGems Trusted Publishing for this repository, `release.yml`, and the `release` environment. Retry a failed publish job to reuse its CI artifact; an already published version must have identical bytes. See [release details](docs/release.md).

Publish dependency gems first. A Git tag, a successful build, or a workflow file does not establish that the gem has reached RubyGems; confirm the registry result separately. See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT. See [LICENSE](LICENSE).

Credential review plans identify unsafe-storage and observable weak-password objects in `check.details[:credentials]`, with source lines, purpose, deviations, material requirements, and consumer/recovery dependencies. Opaque strength requires external evidence rather than an assertion of weakness. SNMP authentication/privacy material remains distinct. These checks stay blocked: ordinary plans contain neither replacement secrets nor placeholder commands. Command capabilities remain unsupported and explain the manual material requirements. See the [credential example](examples/remediation_credentials.rb).

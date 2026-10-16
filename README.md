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

Internal runtime dependencies: [`ctx_parser`](https://github.com/gatework/ctx_parser). The gemspec declares runtime dependencies without version constraints. Applications should commit their own `Gemfile.lock` to make deployments reproducible. No Rails boot or sibling checkout paths are required.

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

The library performs no device access, backup collection, remediation, or database writes. Motor persistence and `Baseline::Check` belong to the host application.

Detailed vendor behavior, historical validation notes, and Motor-only integration are preserved in [the architecture reference](docs/architecture-zh.md). Host integration examples in that reference require Motor; they are not standalone gem APIs. Motor adapters live under `backend/lib/baseline`, `backend/lib/vxlan`, and `backend/lib/wireless` in the [Motor repository](https://github.com/gatework/motor/tree/main/backend/lib).

## Development and tests

```sh
bundle install
bundle exec rake
bundle exec ruby examples/offline.rb
bundle exec rake build
```

`bundle exec rake` runs RSpec, RuboCop, and the offline examples. Tests live in `spec/`, following the existing project's RSpec convention; fixtures use synthetic or sanitized evidence. Add regression cases for successful, incomplete, unsupported, and malformed inputs when extending a parser. Offline tests do not certify all device versions or replace live integration checks.

Use the declared minimum Ruby version for compatibility checks. Document source methods and non-obvious business logic in concise Chinese, preserve public return/error contracts, and never add raw device captures or credentials to examples, fixtures, logs, or release archives.

## Release

This directory can be maintained as the independent [baseline-rb](https://github.com/gatework/baseline-rb) repository. Update `VERSION` and `CHANGELOG.md`, run the validation and build commands above, and inspect the packaged file list before tagging `vVERSION`.

CI runs tests, lint, examples, build, and an isolated installation on Linux and macOS. After CI passes on `main`, push `vVERSION` to run the release workflow. It publishes the tested Linux artifact to RubyGems and GitHub Releases, attaches `SHA256SUMS`, and verifies downloaded bytes. The GitHub `release` environment accepts a `RUBYGEMS_API_KEY` secret; without it, configure RubyGems Trusted Publishing for this repository, `release.yml`, and the `release` environment. Retry a failed publish job to reuse its CI artifact; an already published version must have identical bytes. See [release details](docs/release.md).

Publish dependency gems first. A Git tag, a successful build, or a workflow file does not establish that the gem has reached RubyGems; confirm the registry result separately. See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT. See [LICENSE](LICENSE).

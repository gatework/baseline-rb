# Changelog

Changes to the public contract are recorded here. Versions follow Semantic Versioning.

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

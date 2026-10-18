# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"
require_relative "support/comware_ntp_state"

RSpec.describe "NTP authenticated association remediation" do
  def policy(verified: false, key_id: 7)
    object = { "identity" => { "address" => "192.0.2.12", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "key_id" => key_id } }
    Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ object ], "managed_scopes" => [ { "vrf" => "default" } ],
      "remediation" => { "maximum_targets" => 3, "ntp_peer_key_compatibility_verified" => verified }
    } })
  end

  def source
    "sysname LAB\nntp-service authentication enable\nntp-service authentication-keyid 7 authentication-mode md5 cipher SYNTHETIC-KEY\n" \
      "ntp-service reliable authentication-keyid 7\nntp-service unicast-server 192.0.2.10 authentication-keyid 7\n"
  end

  def plan(text = source, verified: true, key_id: 7)
    Baseline::Remediation.new(policy: policy(verified: verified, key_id: key_id)).call(configuration: text, platform: "h3c", complete: true)
  end

  it "can reuse known trusted material for a new approved endpoint after external peer verification" do
    result = plan
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("ntp-service unicast-server 192.0.2.12 authentication-keyid 7", "undo ntp-service unicast-server 192.0.2.10")
    expect(result.checks.first.details[:verified_ntp_key_ids]).to eq([ 7 ])
    expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
    after = ComwareNtpState.new(source).apply(result.configuration_commands).configuration
    unrelated = ->(body) { body.lines.reject { |line| /\Antp-service unicast-/.match?(line) } }
    expect(unrelated.call(after)).to eq(unrelated.call(source))
    audit = Baseline::Audit.new(policy: policy(verified: true)).call(configuration: after, platform: "h3c", complete: true)
    expect(audit).to be_compliant
    expect(audit.configuration.fact("ntp.authentication_bindings").map { |row| row[:configured_ready] }).to eq([ true ])
    expect(plan(after).status).to eq(:noop)
  end

  it "requires actual key/trust evidence and external compatibility rather than numeric identity alone" do
    expect(plan(verified: false).checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    expect(plan(key_id: 8).checks.first.reason).to eq(:ntp_authentication_dependency)
    expect(plan(source.sub("ntp-service reliable authentication-keyid 7\n", "")).checks.first.reason).to eq(:ntp_authentication_dependency)
    expect(plan(source + "undo ntp-service authentication-keyid 7\n").operations).to be_empty
  end

  it "does not allow the syntax renderer to assume authentication approval on its own" do
    result = plan
    operation = result.operations.find { |item| item.action == :add }
    expect { Baseline::H3c::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "validates the external verification flag and advertises the material prerequisite" do
    expect { policy(verified: "true") }.to raise_error(ArgumentError)
    expect(Baseline::Remediation.capabilities(platform: "h3c").fetch("ntp.associations")[:requirements]).to include(
      "ntp_peer_key_compatibility_verified", "known_trusted_ntp_key")
  end

  it "retains an existing key reference only when its modelled material remains valid" do
    current = source.sub("unicast-server 192.0.2.10 authentication-keyid 7", "unicast-server 192.0.2.12 authentication-keyid 7 version 3")
    definition = policy(verified: false).rules.first
    object = definition.expected.first.merge("attributes" => { "key_id" => 7, "version" => 4 })
    changed = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ object ], "managed_scopes" => definition.managed_scopes
    } })
    engine = Baseline::Remediation.new(policy: changed)
    result = engine.call(configuration: current, platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
    after = ComwareNtpState.new(current).apply(result.configuration_commands).configuration
    expect(engine.call(configuration: after, platform: "h3c", complete: true).status).to eq(:noop)
    expect(engine.call(configuration: current + "undo ntp-service authentication-keyid 7\n", platform: "h3c", complete: true).operations).to be_empty
  end

  it "uses VRP material syntax and key evidence without borrowing Comware algorithms" do
    engine = Baseline::Remediation.new(policy: policy(verified: true))
    text = source.sub("authentication-mode md5", "authentication-mode hmac-sha256")
    result = engine.call(configuration: text, platform: "huawei", complete: true)
    expect(result.status).to eq(:ready)
    after = ComwareNtpState.new(text).apply(result.configuration_commands).configuration
    expect(engine.call(configuration: after, platform: "huawei", complete: true).status).to eq(:noop)
    expect(plan(text).operations).to be_empty
  end

  it "does not add an unkeyed target when an explicit authentication switch is unresolved" do
    definition = Baseline::Policy.new("version" => 1, "checks" => { "ntp.servers" => {
      "expected" => [ "192.0.2.12" ], "remediation" => { "maximum_targets" => 3 }
    } })
    text = "sysname LAB\nntp-service authentication enable unsupported-option VALUE\nntp-service unicast-server 192.0.2.10\n"
    result = Baseline::Remediation.new(policy: definition).call(configuration: text, platform: "h3c", complete: true)
    expect(result.checks.first.reason).to eq(:ntp_authentication_dependency)
    expect(result.operations).to be_empty
  end
end

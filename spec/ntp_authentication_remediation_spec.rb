# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/ntp_authentication_state"

RSpec.describe "Guarded NTP authentication switching" do
  def source(platform, enabled: false, keyed: true)
    if platform == "hillstone"
      "hostname LAB\nntp authentication-key 7 md5 SYNTHETIC-KEY\n#{enabled ? 'ntp authentication' : 'no ntp authentication'}\n" \
        "ntp server 192.0.2.10#{keyed ? ' key 7' : ''}\n"
    else
      "sysname LAB\nntp-service authentication-keyid 7 authentication-mode md5 cipher SYNTHETIC-KEY\n" \
        "ntp-service reliable authentication-keyid 7\n#{enabled ? '' : 'undo '}ntp-service authentication enable\n" \
        "ntp-service unicast-server 192.0.2.10#{keyed ? ' authentication-keyid 7' : ''}\n"
    end
  end

  def policy(expected: true, verified: true, recreation: true, profile: "comware_legacy", checks: {})
    Baseline::Policy.new("version" => 1, "checks" => { "ntp.authentication" => { "expected" => expected,
      "remediation" => { "ntp_peer_key_compatibility_verified" => verified, "ntp_association_recreation_approved" => recreation, "syntax_profile" => profile }.compact } }.merge(checks))
  end

  def object(address, **attributes)
    { "identity" => { "address" => address, "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => attributes.transform_keys(&:to_s) }
  end

  def association_rule(targets)
    { "ntp.associations" => { "expected" => targets, "managed_scopes" => [ { "vrf" => "default" } ], "remediation" => { "maximum_targets" => 3 } } }
  end

  %w[h3c huawei hillstone].each do |platform|
    it "enables #{platform} authentication only after verified material and preserves unrelated source" do
      text = source(platform) + (platform == "hillstone" ? "ntp query-interval 5\n" : "ntp-service dscp 16\n")
      engine = Baseline::Remediation.new(policy: policy(profile: platform == "huawei" ? "vrp_s_series" : "comware_legacy"))
      result = engine.call(configuration: text, platform: platform, complete: true)
      expect(result.status).to eq(:ready)
      expect(result.operations.map(&:kind)).to include("ntp.authentication")
      activation = result.operations.find { |operation| operation.kind == "ntp.authentication" }
      expect(activation.phase).to eq(platform == "hillstone" ? :activate : :prepare)
      if platform != "hillstone"
        commands = result.configuration_commands
        expect(commands.index("undo ntp-service unicast-server 192.0.2.10")).to be < commands.index("ntp-service authentication enable")
        expect(commands.index("ntp-service authentication enable")).to be < commands.index("ntp-service unicast-server 192.0.2.10 authentication-keyid 7")
      end
      after = NtpAuthenticationState.new(text, platform: platform).apply(result.configuration_commands).configuration
      expect(after).to include("SYNTHETIC-KEY", platform == "hillstone" ? "ntp query-interval 5" : "ntp-service dscp 16")
      expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
      expect(engine.call(configuration: after, platform: platform, complete: true).status).to eq(:noop)
    end
  end

  it "requires explicit temporary association recreation approval for Comware and VRP" do
    %w[h3c huawei].each do |platform|
      result = Baseline::Remediation.new(policy: policy(recreation: false, profile: platform == "huawei" ? "vrp_s_series" : "comware_legacy")).call(configuration: source(platform), platform: platform, complete: true)
      expect(result.operations).to be_empty
      expect(result.checks.first.requirements).to include("ntp_association_recreation_approved")
    end
  end

  it "recreates the complete final VRP inventory including peers outside endpoint management scopes" do
    text = source("huawei", keyed: false) + "ntp-service unicast-peer 192.0.2.30 vpn-instance OPS authentication-keyid 7 preference source-interface LoopBack0 version 4\n"
    engine = Baseline::Remediation.new(policy: policy(profile: "vrp_s_series", checks: association_rule([ object("192.0.2.20", key_id: 7) ])))
    result = engine.call(configuration: text, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    commands = result.configuration_commands
    activation = commands.index("ntp-service authentication enable")
    expect(commands.index("undo ntp-service unicast-server 192.0.2.10")).to be < activation
    expect(commands.index("undo ntp-service unicast-peer 192.0.2.30 vpn-instance OPS")).to be < activation
    expect(commands.index("ntp-service unicast-peer 192.0.2.30 vpn-instance OPS version 4 authentication-keyid 7 preference source-interface LoopBack0")).to be > activation
    expect(commands).not_to include("ntp-service unicast-server 192.0.2.10")
    expect(result.checks.map(&:operation_ids).uniq).to eq([ result.operations.map(&:id) ])
    after = NtpAuthenticationState.new(text, platform: "huawei").apply(commands).configuration
    expect(engine.call(configuration: after, platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "applies approved key references and removes obsolete unkeyed peers before activation" do
    text = source("hillstone", keyed: false)
    engine = Baseline::Remediation.new(policy: policy(checks: association_rule([ object("192.0.2.20", key_id: 7) ])))
    result = engine.call(configuration: text, platform: :hillstone, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands.index("no ntp server 192.0.2.10")).to be < result.configuration_commands.index("ntp authentication")
    after = NtpAuthenticationState.new(text, platform: "hillstone").apply(result.configuration_commands).configuration
    expect(engine.call(configuration: after, platform: :hillstone, complete: true).status).to eq(:noop)
  end

  it "disables authentication before an explicitly approved unkeyed addition and preserves key material" do
    text = source("hillstone", enabled: true)
    engine = Baseline::Remediation.new(policy: policy(expected: false, checks: association_rule([ object("192.0.2.20") ])))
    result = engine.call(configuration: text, platform: :hillstone, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands.index("no ntp authentication")).to be < result.configuration_commands.index("ntp server 192.0.2.20")
    after = NtpAuthenticationState.new(text, platform: "hillstone").apply(result.configuration_commands).configuration
    expect(after).to include("ntp authentication-key 7 md5 SYNTHETIC-KEY")
    expect(engine.call(configuration: after, platform: :hillstone, complete: true).status).to eq(:noop)
  end

  it "requires global peer compatibility approval rather than inferring it from configured keys" do
    result = Baseline::Remediation.new(policy: policy(verified: false)).call(configuration: source("hillstone"), platform: :hillstone, complete: true)
    expect(result.checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    expect(result.operations).to be_empty
  end

  it "rejects unkeyed or untrusted final associations and does not partially emit related target changes" do
    checks = association_rule([ object("192.0.2.10", source: "MGT1") ])
    result = Baseline::Remediation.new(policy: policy(checks: checks)).call(configuration: source("hillstone", keyed: false), platform: :hillstone, complete: true)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
    expect(result.checks.find { |check| check.id == "ntp.authentication" }.requirements).to include("approved_ntp_key_references")
    no_trust = source("h3c").sub("ntp-service reliable authentication-keyid 7\n", "")
    blocked = Baseline::Remediation.new(policy: policy).call(configuration: no_trust, platform: :h3c, complete: true)
    expect(blocked.operations).to be_empty
    expect(blocked.checks.first.requirements).to include("known_trusted_ntp_key:7")
  end

  it "does not assume an empty static inventory covers interface broadcast consumers or partial input" do
    engine = Baseline::Remediation.new(policy: policy)
    text = "sysname LAB\nundo ntp-service authentication enable\ninterface Vlan-interface1\n ntp-service broadcast-client\n#\n"
    result = engine.call(configuration: text, platform: :h3c, complete: true)
    expect(result.checks.first.requirements).to include("resolved_ntp_authentication_consumers")
    expect(result.operations).to be_empty
    expect(engine.call(configuration: source("hillstone"), platform: :hillstone, complete: false).operations).to be_empty
  end

  it "uses the documented Comware and VRP disabled default only for complete input without an overriding declaration" do
    %w[h3c huawei].each do |platform|
      engine = Baseline::Remediation.new(policy: policy(recreation: false))
      result = engine.call(configuration: "sysname LAB\n", platform: platform, complete: true)
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands).to eq([ "system-view", "ntp-service authentication enable", "return" ])
      partial = engine.call(configuration: "sysname LAB\n", platform: platform, complete: false)
      expect(partial.audit.configuration.fact_known?("ntp.authentication")).to be(false)
      expect(partial.operations).to be_empty
      malformed = engine.call(configuration: "sysname LAB\nundo ntp-service authentication enable\nntp-service authentication malformed\n", platform: platform, complete: true)
      expect(malformed.operations).to be_empty
      expect(malformed.checks.first.requirements).to include("known_ntp_authentication_state")
    end
  end

  it "does not promote an empty configured inventory to peer-compatibility approval" do
    %w[h3c huawei hillstone].each do |platform|
      header = platform == "hillstone" ? "hostname LAB\nno ntp authentication\n" : "sysname LAB\nundo ntp-service authentication enable\n"
      result = Baseline::Remediation.new(policy: policy(verified: false, recreation: false)).call(configuration: header, platform: platform, complete: true)
      expect(result.operations).to be_empty
      expect(result.checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    end
  end

  it "requires an explicit platform-compatible association syntax profile before recreating peers" do
    [ [ "h3c", nil ], [ "h3c", "vrp_s_series" ], [ "huawei", nil ], [ "huawei", "comware_legacy" ] ].each do |platform, profile|
      result = Baseline::Remediation.new(policy: policy(profile: profile)).call(configuration: source(platform), platform: platform, complete: true)
      expect(result.operations).to be_empty
      expect(result.checks.first.requirements).to include("native_ntp_syntax_profile")
    end
  end

  it "recreates Comware 7 associations with post-address VPN and native source options" do
    text = source("h3c").sub("192.0.2.10 authentication-keyid 7", "192.0.2.10 vpn-instance OPS authentication-keyid 7 priority source-interface LoopBack0")
    engine = Baseline::Remediation.new(policy: policy(profile: "comware7"))
    result = engine.call(configuration: text, platform: :h3c, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "undo ntp-service unicast-server 192.0.2.10 vpn-instance OPS",
      "ntp-service authentication enable", "ntp-service unicast-server 192.0.2.10 vpn-instance OPS authentication-keyid 7 priority source LoopBack0", "return" ])
    after = NtpAuthenticationState.new(text, platform: "h3c").apply(result.configuration_commands).configuration
    expect(engine.call(configuration: after, platform: :h3c, complete: true).status).to eq(:noop)
  end

  it "rejects a keyless unmanaged survivor in the global authentication projection" do
    text = source("huawei") + "ntp-service unicast-peer 192.0.2.30 vpn-instance OPS\n"
    checks = association_rule([ object("192.0.2.20", key_id: 7) ])
    result = Baseline::Remediation.new(policy: policy(profile: "vrp_s_series", checks: checks)).call(configuration: text, platform: :huawei, complete: true)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
    expect(result.checks.map(&:status)).to eq([ :blocked, :blocked ])
    expect(result.checks.first.requirements).to include("approved_ntp_key_references")
  end

  it "emits no withdrawal or switch when a final association cannot be rendered" do
    checks = association_rule([ object("2001:db8::20", key_id: 7, version: 4) ])
    result = Baseline::Remediation.new(policy: policy(profile: "vrp_s_series", checks: checks)).call(configuration: source("huawei"), platform: :huawei, complete: true)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
    expect(result.checks.map(&:reason)).to eq([ :unsupported_setting, :unsupported_setting ])
  end

  it "disables each supported global profile before adding an approved unkeyed endpoint" do
    %w[h3c huawei hillstone].each do |platform|
      checks = association_rule([ object("192.0.2.20") ])
      engine = Baseline::Remediation.new(policy: policy(expected: false, recreation: false, profile: platform == "huawei" ? "vrp_s_series" : "comware_legacy", checks: checks))
      text = source(platform, enabled: true)
      result = engine.call(configuration: text, platform: platform, complete: true)
      expect(result.status).to eq(:ready), platform
      expect(result.operations.first).to have_attributes(kind: "ntp.authentication", after: false, phase: :prepare)
      after = NtpAuthenticationState.new(text, platform: platform).apply(result.configuration_commands).configuration
      expect(after).to include("SYNTHETIC-KEY")
      expect(engine.call(configuration: after, platform: platform, complete: true).status).to eq(:noop)
    end
  end

  it "binds low-level switch rendering to the complete operation and the native activation phase" do
    early = Baseline::ConfigurationOperation.new(kind: "ntp.authentication", identity: {}, before: false, after: true, phase: :prepare)
    late = Baseline::ConfigurationOperation.new(kind: "ntp.authentication", identity: {}, before: false, after: true, phase: :activate)
    h3c = Baseline::H3c::CommandRenderer.new
    stoneos = Baseline::Hillstone::CommandRenderer.new
    expect { h3c.render(early) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation, "ntp_authentication_preconditions_unverified")
    expect { h3c.render(early, verified_ntp_authentication_operation_ids: [ late.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { h3c.render(late, verified_ntp_authentication_operation_ids: [ late.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation, "invalid_ntp_authentication_order")
    expect { stoneos.render(early, verified_ntp_authentication_operation_ids: [ early.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation, "invalid_ntp_authentication_order")
  end

  it "does not broaden temporary recreation approval into key trust or unsupported consumer modes" do
    [ source("h3c").sub("cipher SYNTHETIC-KEY", "cipher"),
      source("h3c") + "ntp-service refclock-master\n", source("h3c") + "ntp-service multicast-server\n" ].each do |text|
      result = Baseline::Remediation.new(policy: policy).call(configuration: text, platform: :h3c, complete: true)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
    expect { policy(recreation: "yes") }.to raise_error(ArgumentError)
  end

  it "assigns an approved existing trusted key to a fully parsed but previously unkeyed Comware or VRP association" do
    %w[h3c huawei].each do |platform|
      checks = association_rule([ object("192.0.2.10", key_id: 7, source: "LoopBack0") ])
      engine = Baseline::Remediation.new(policy: policy(profile: platform == "huawei" ? "vrp_s_series" : "comware7", checks: checks))
      text = source(platform, keyed: false)
      result = engine.call(configuration: text, platform: platform, complete: true)
      expect(result.audit.findings.find { |finding| finding.id == "ntp.associations" }.status).to eq(:unknown)
      expect(result.status).to eq(:ready), platform
      expect(result.operations.map(&:action)).to eq([ :remove, :set, :add ])
      after = NtpAuthenticationState.new(text, platform: platform).apply(result.configuration_commands).configuration
      expect(engine.call(configuration: after, platform: platform, complete: true).status).to eq(:noop)
      expect(result.to_text).not_to include("SYNTHETIC-KEY")
    end
  end

  it "rejects an IPv6 version option outside the Comware 7 profile without emitting a partial transaction" do
    text = source("h3c").sub("ntp-service unicast-server 192.0.2.10 authentication-keyid 7", "ntp-service ipv6 unicast-server 2001:db8::10 authentication-keyid 7 version 4")
    result = Baseline::Remediation.new(policy: policy(profile: "comware7")).call(configuration: text, platform: :h3c, complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.first.reason).to eq(:unsupported_setting)
  end
end

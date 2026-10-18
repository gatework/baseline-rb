# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "NTP association remediation" do
  {
    "h3c" => [ "sysname LAB", "ntp-service unicast-server", "ntp-service unicast-peer", "undo", "system-view", "return" ],
    "huawei" => [ "sysname LAB", "ntp-service unicast-server", "ntp-service unicast-peer", "undo", "system-view", "return" ],
    "cisco_ios" => [ "hostname LAB", "ntp server", "ntp peer", "no", "configure terminal", "end" ],
    "cisco_nxos" => [ "hostname LAB", "ntp server", "ntp peer", "no", "configure terminal", "end" ]
  }.each do |platform, (hostname, prefix, peer, negate, enter, leave)|
    it "replaces wrong #{platform} servers while preserving peers and correct server attributes" do
      policy = Baseline::Policy.new("version" => 1, "checks" => {
        "ntp.servers" => { "expected" => %w[192.0.2.10 192.0.2.12], "remediation" => { "maximum_targets" => 5 } },
        "ntp.minimum_servers" => { "expected" => 2 }
      })
      engine = Baseline::Remediation.new(policy: policy)
      text = "#{hostname}\n#{prefix} 192.0.2.10 version 4\n#{prefix} 192.0.2.11\n#{peer} 192.0.2.99\n"
      plan = engine.call(configuration: text, platform: platform, complete: true)
      expect(plan.status).to eq(:ready)
      expect(plan.configuration_commands).to eq([ enter, "#{prefix} 192.0.2.12", "#{negate} #{prefix} 192.0.2.11", leave ])
      after = text.sub("#{prefix} 192.0.2.11\n", "#{prefix} 192.0.2.12\n")
      second = engine.call(configuration: after, platform: platform, complete: true)
      expect(second.status).to eq(:noop)
      expect(second.audit.configuration.resources.any? { |item| item.identity["role"] == "peer" }).to be(true)
    end
  end

  it "updates an H3C association version without discarding its source and priority" do
    object = { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "OPS" }, "attributes" => { "version" => 4 } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ object ], "managed_scopes" => [ { "vrf" => "OPS" } ] } })
    engine = Baseline::Remediation.new(policy: policy)
    before = "ntp-service unicast-server vpn-instance OPS 192.0.2.10 version 3 priority source-interface LoopBack0"
    after = "ntp-service unicast-server vpn-instance OPS 192.0.2.10 version 4 priority source-interface LoopBack0"
    plan = engine.call(configuration: "sysname LAB\n#{before}\n", platform: "h3c", complete: true)
    expect(plan.configuration_commands).to eq([ "system-view", "undo ntp-service unicast-server vpn-instance OPS 192.0.2.10", after, "return" ])
    expect(engine.call(configuration: "sysname LAB\n#{after}\n", platform: "h3c", complete: true).status).to eq(:noop)
  end

  it "does not enable authentication without verified key material and trusted key references" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.authentication" => { "expected" => true } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nundo ntp-service authentication enable\n", platform: "h3c", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.checks.first.requirements).to include("ntp_key_reference_evidence")
    expect(plan.configuration_commands).to be_empty
  end

  it "does not add an unauthenticated target when authentication is enabled or required by policy" do
    [ "ntp-service authentication enable", "undo ntp-service authentication enable" ].each do |state|
      policy = Baseline::Policy.new("version" => 1, "checks" => {
        "ntp.servers" => { "expected" => [ "192.0.2.12" ], "remediation" => { "maximum_targets" => 3 } },
        "ntp.authentication" => { "expected" => true }
      })
      plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\n#{state}\nntp-service unicast-server 192.0.2.10\n", platform: "h3c", complete: true)
      expect(plan.configuration_commands).to be_empty
      expect(plan.checks.first.reason).to eq(:ntp_authentication_dependency)
    end
  end

  it "does not synthesize a new key reference merely because an association approves its numeric ID" do
    object = { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "key_id" => 7 } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => { "expected" => [ object ],
      "managed_scopes" => [ { "vrf" => "default" } ], "remediation" => { "maximum_targets" => 4 } } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\n", platform: "h3c", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
  end

  it "does not claim convergence for an unverified implicit preference state" do
    object = { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "prefer" => false } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => { "expected" => [ object ], "managed_scopes" => [ { "vrf" => "default" } ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nntp-service unicast-server 192.0.2.10 priority\n", platform: "h3c", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
  end
end

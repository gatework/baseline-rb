# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Huawei native NTP association syntax" do
  def engine(target)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ target ], "managed_scopes" => [ { "vrf" => "OPS" } ], "remediation" => { "maximum_targets" => 3 }
    } })
    Baseline::Remediation.new(policy: policy)
  end

  it "preserves VRP preference and renders the VPN after the IPv4 address" do
    target = { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "OPS" }, "attributes" => { "version" => 4 } }
    service = engine(target)
    text = "sysname LAB\nntp-service unicast-server 192.0.2.10 vpn-instance OPS version 3 preference source-interface LoopBack0\n"
    result = service.call(configuration: text, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    expected = "ntp-service unicast-server 192.0.2.10 vpn-instance OPS version 4 preference source-interface LoopBack0"
    expect(result.configuration_commands).to eq([ "system-view", "undo ntp-service unicast-server 192.0.2.10 vpn-instance OPS", expected, "return" ])
    expect(service.call(configuration: "sysname LAB\n#{expected}\n", platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "uses the VRP IPv6 keyword after unicast-peer and retains exact routing identity" do
    target = { "identity" => { "address" => "2001:db8::10", "role" => "peer" }, "scope" => { "vrf" => "OPS" }, "attributes" => { "source" => "LoopBack1" } }
    service = engine(target)
    result = service.call(configuration: "sysname LAB\nntp-service unicast-peer ipv6 2001:db8::10 vpn-instance OPS preference source-interface LoopBack0\n", platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "undo ntp-service unicast-peer ipv6 2001:db8::10 vpn-instance OPS",
      "ntp-service unicast-peer ipv6 2001:db8::10 vpn-instance OPS preference source-interface LoopBack1", "return" ])
    after = "sysname LAB\nntp-service unicast-peer ipv6 2001:db8::10 vpn-instance OPS preference source-interface LoopBack1\n"
    expect(service.call(configuration: after, platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "rejects H3C family/priority spellings and unverified VRP DNS or IPv6-version combinations" do
    target = { "identity" => { "address" => "192.0.2.20", "role" => "server" }, "scope" => { "vrf" => "OPS" } }
    [ "ntp-service ipv6 unicast-server 2001:db8::10", "ntp-service unicast-server vpn-instance OPS 192.0.2.10",
      "ntp-service unicast-server 192.0.2.10 priority", "ntp-service unicast-server time.example.test",
      "ntp-service unicast-server ipv6 2001:db8::10 version 4" ].each do |command|
      result = engine(target).call(configuration: "sysname LAB\n#{command}\n", platform: :huawei, complete: true)
      expect(result.audit.configuration.fact_known?("ntp.associations")).to be(false), command
      expect(result.configuration_commands).to be_empty
    end
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/configuration_resource"

RSpec.describe "Baseline configuration resources" do
  def resource(address: "192.0.2.20", vrf: "default", port: 514)
    Baseline::ConfigurationResource.new(kind: "syslog.destination", identity: { "address" => address },
      scope: { "vrf" => vrf }, attributes: { "port" => port, "protocol" => "udp" }, lines: [ 3 ])
  end

  it "keeps resource snapshots independent of mutable caller inputs" do
    address = +"192.0.2.20"
    item = resource(address: address)
    address.replace("192.0.2.99")
    expect(item.identity).to eq("address" => "192.0.2.20")
    expect(item.attributes).to be_frozen
    expect(item.identity.fetch("address")).to be_frozen
    expect(item).to be_frozen
    expect(item).to be_complete
  end

  it "does not expose the builder's mutable resource record" do
    builder = Baseline::FactBuilder.new(complete: true)
    expect(builder.record_resource(resource)).to be(true)
  end

  it "distinguishes the same destination in independent routing domains" do
    expect(resource(vrf: "A").key).not_to eq(resource(vrf: "B").key)
    expect(resource(port: 514).key).to eq(resource(port: 1514).key)
  end

  it "rejects credential fields and CLI control characters before serialization" do
    [ { "secret" => "PRIVATE-TOKEN" }, { "port" => 0 }, { "protocol" => "udp\nsave" } ].each do |attributes|
      expect do
        Baseline::ConfigurationResource.new(kind: "syslog.destination", identity: { "address" => "192.0.2.20" }, attributes: attributes)
      end.to raise_error(ArgumentError)
    end
    expect { resource(address: "192.0.2.20\nquit") }.to raise_error(ArgumentError)
    expect { resource(address: "999.999.999.999") }.to raise_error(ArgumentError)
    expect { resource(address: "192.0.2.0/24") }.to raise_error(ArgumentError)
  end

  it "accepts compressed IPv6 destination addresses" do
    expect(resource(address: "::1").identity).to eq("address" => "::1")
    expect(resource(address: "2001:db8::20").identity).to eq("address" => "2001:db8::20")
  end

  it "preserves resources across independent FactBuilder snapshots" do
    builder = Baseline::FactBuilder.new(complete: true)
    builder.record_fact("hostname", "LAB")
    builder.record_resource(resource(vrf: "A"))
    first = builder.build
    builder.record_resource(resource(vrf: "B"))
    evidence = Baseline::Evidence.new(platform: "h3c", sha256: "synthetic", result: first)
    expect(evidence.resources.map { |item| item.scope.fetch("vrf") }).to eq([ "A" ])
    expect(evidence.resources).to be_frozen
    expect(builder.build.records.first.fetch("resources").size).to eq(2)
    expect(evidence.to_h.fetch(:resources)).to eq([ resource(vrf: "A").to_h ])
  end

  it "keeps resource identity and metadata out of inspect" do
    expect(resource.inspect).not_to include("192.0.2.20")
  end

  %w[h3c huawei].each do |platform|
    it "retains syslog options and independent VPN identities on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
      text = "sysname LAB\ninfo-center loghost vpn-instance A 192.0.2.20 port 1514 facility local6\n" \
        "info-center loghost vpn-instance B 192.0.2.20 port 2514\n" \
        "undo info-center loghost vpn-instance A 192.0.2.20\n"
      report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
      expect(report.configuration.resources.size).to eq(1)
      item = report.configuration.resources.first
      expect(item.scope).to eq("vrf" => "B")
      expect(item.identity).to eq("address" => "192.0.2.20")
      expect(item.attributes).to eq("port" => 2514, "protocol" => "udp")
      expect(item.lines).to eq([ 3 ])
      expect(item).to be_complete
      expect(report.findings.first.status).to eq(:pass)
    end

    it "withholds a complete resource after unsupported syslog options on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
      text = "sysname LAB\ninfo-center loghost 192.0.2.20 port 514\ninfo-center loghost 192.0.2.20 unknown-option PRIVATE-SYNTHETIC\n"
      report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
      expect(report.configuration.resources.size).to eq(1)
      expect(report.configuration.resources.first).not_to be_complete
      expect(report.to_h.to_json).not_to include("PRIVATE-SYNTHETIC")
    end

    it "withholds complete resources for conflicting VPNs or invalid facilities on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
      [ "vpn-instance A 192.0.2.20 vpn-instance B", "192.0.2.20 facility INVALID" ].each do |arguments|
        report = Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\ninfo-center loghost #{arguments}\n",
          platform: platform, complete: true)
        expect(report.configuration.resources.first).not_to be_complete
      end
    end
  end

  it "keeps Huawei domain destination scope from a trailing VPN option" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
    text = "sysname LAB\ninfo-center loghost domain logs.example.test vpn-instance OPS port 1514\n"
    report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: "huawei", complete: true)
    expect(report.configuration.resources.first.scope).to eq("vrf" => "OPS")
    expect(report.configuration.resources.first.identity).to eq("address" => "logs.example.test")
    expect(report.configuration.resources.first.attributes).to eq("port" => 1514, "protocol" => "udp")
  end

  {
    "cisco_ios" => [ "logging host 192.0.2.20 vrf A transport tcp port 1514", "logging host 192.0.2.20 vrf B transport udp port 2514",
      "no logging host 192.0.2.20 vrf A", { "protocol" => "udp", "port" => 2514 } ],
    "cisco_nxos" => [ "logging server 192.0.2.20 6 use-vrf A", "logging server 192.0.2.20 5 use-vrf B port 2514 facility local6",
      "no logging server 192.0.2.20 use-vrf A", { "severity" => 5, "port" => 2514, "facility" => "local6" } ]
  }.each do |platform, (first, second, removal, attributes)|
    it "retains scoped logging resources and cancellation on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
      report = Baseline::Audit.new(policy: policy).call(configuration: "hostname LAB\n#{first}\n#{second}\n#{removal}\n",
        platform: platform, complete: true)
      expect(report.findings.first.status).to eq(:pass)
      expect(report.configuration.resources.size).to eq(1)
      item = report.configuration.resources.first
      expect(item.scope).to eq("vrf" => "B")
      expect(item.identity).to eq("address" => "192.0.2.20")
      expect(item.attributes).to eq(attributes)
      expect(item).to be_complete
    end
  end

  it "retains each Hillstone logging category and routing scope" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
    text = "hostname LAB\nlogging syslog 192.0.2.20 vrouter A udp 514 type event\n" \
      "logging syslog 192.0.2.20 vrouter A udp 514 type config\n" \
      "logging syslog 192.0.2.20 vrouter B tcp 1514 type event\nEnd\n"
    report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: "hillstone", complete: true)
    expect(report.configuration.resources.size).to eq(3)
    expect(report.configuration.resources.map(&:key).uniq.size).to eq(3)
    expect(report.configuration.resources).to all(be_complete)
    expect(report.configuration.resources.last.scope).to eq("vrf" => "B")
    expect(report.configuration.resources.last.identity).to eq("address" => "192.0.2.20", "protocol" => "tcp", "port" => 1514, "types" => [ "event" ])
  end

  it "retains PAN-OS profile/server identities and latest leaf values" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
    prefix = "set shared log-settings syslog OPS server LOG"
    text = "set deviceconfig system hostname LAB\n#{prefix} server 192.0.2.20\n#{prefix} port 514\n#{prefix} port 1514\n" \
      "#{prefix} transport TCP\n#{prefix} facility LOG_LOCAL6\n#{prefix} format BSD\n"
    report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: "palo_alto", complete: true)
    expect(report.configuration.resources.size).to eq(1)
    item = report.configuration.resources.first
    expect(item.scope).to eq("profile" => "OPS")
    expect(item.identity).to eq("name" => "LOG")
    expect(item.attributes).to eq("address" => "192.0.2.20", "port" => 1514, "protocol" => "tcp", "facility" => "LOG_LOCAL6", "format" => "BSD")
    expect(item).to be_complete
  end
end

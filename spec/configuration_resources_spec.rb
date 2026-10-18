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
      expect(item.attributes).to eq("port" => 2514)
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
    expect(report.configuration.resources.first.attributes).to eq("port" => 1514)
  end
end

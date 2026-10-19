# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Canonical server address identity" do
  let(:long_ip) { "2001:0DB8:0:0:0:0:0:10" }
  let(:short_ip) { "2001:db8::10" }

  def audit(text, checks, platform: "h3c")
    policy = Baseline::Policy.new("version" => 1, "checks" => checks)
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
  end

  def object(address, role = "server", vrf = "default")
    { "identity" => { "address" => address, "role" => role }, "scope" => { "vrf" => vrf } }
  end

  it "owns canonical addresses without changing object names, scopes or caller values" do
    identity = { "name" => "Time.EXAMPLE.TEST" }
    attributes = { "address" => long_ip.dup }
    resource = Baseline::ConfigurationResource.new(kind: "ntp.association", identity: identity, scope: { "vrf" => "OPS" }, attributes: attributes)
    expect(resource.attributes).to eq("address" => short_ip)
    expect(resource.identity).to eq(identity)
    expect(resource.scope).to eq("vrf" => "OPS")
    expect(attributes).to eq("address" => long_ip)
    expect(resource.attributes["address"]).to be_frozen
  end

  it "compares structured approvals using the same identity and canonical address attributes" do
    policy = { "ntp.associations" => { "expected" => [ object(long_ip) ] } }
    report = audit("sysname LAB\nntp-service ipv6 unicast-server #{short_ip}\n", policy)
    expect(report).to be_compliant
    expect(report.findings.first.expected.first["identity"]["address"]).to eq(short_ip)
    report_policy = Baseline::Policy.new("version" => 1, "checks" => policy)
    expect(Baseline::Remediation.new(policy: report_policy).call(configuration: "sysname LAB\nntp-service ipv6 unicast-server #{short_ip}\n", platform: "h3c", complete: true).status).to eq(:noop)
    expect(report_policy.rules.first.expected.first["identity"]["address"]).to eq(long_ip)
  end

  it "rejects conflicting canonical structured identities before planning while preserving roles and VRFs" do
    checks = { "ntp.associations" => { "expected" => [ object(short_ip), object(long_ip) ] } }
    expect { Baseline::Policy.new("version" => 1, "checks" => checks) }.to raise_error(ArgumentError)
    checks["ntp.associations"]["expected"] = [ object(long_ip), object(short_ip, "peer"), object(short_ip, "server", "OPS") ]
    expect { Baseline::Policy.new("version" => 1, "checks" => checks) }.not_to raise_error
  end

  it "folds only address DNS labels and preserves absolute versus relative spelling" do
    text = "sysname LAB\nntp-service unicast-server Time.EXAMPLE.TEST\nntp-service unicast-server time.example.test\n"
    report = audit(text, { "ntp.minimum_servers" => { "expected" => 2 }, "ntp.servers" => { "expected" => [ "TIME.example.test" ] } })
    expect(report.findings.map(&:status)).to eq([ :fail, :pass ])
    expect(report.configuration.fact("ntp.servers")).to eq([ "time.example.test" ])
    absolute = audit(text + "ntp-service unicast-server time.example.test.\n", { "ntp.minimum_servers" => { "expected" => 2 } })
    expect(absolute).to be_compliant
  end

  it "reduces add and withdrawal aliases consistently without deleting another VRF" do
    text = "sysname LAB\nntp-service ipv6 unicast-server #{long_ip}\nntp-service ipv6 unicast-server vpn-instance OPS #{short_ip}\n" \
      "undo ntp-service ipv6 unicast-server #{short_ip}\n"
    report = audit(text, { "ntp.servers" => { "expected" => [ long_ip ] } })
    expect(report).to be_compliant
    resources = report.configuration.resources.select { |resource| resource.kind == "ntp.association" }
    expect(resources).to contain_exactly(have_attributes(identity: { "address" => short_ip, "role" => "server" }, scope: { "vrf" => "OPS" }))
    expect(report.configuration.fact("ntp.servers")).to eq([ short_ip ])
  end

  it "does not count IP spelling variants as distinct servers across parser families" do
    {
      "h3c" => "sysname LAB\nntp-service ipv6 unicast-server",
      "huawei" => "sysname LAB\nntp-service ipv6 unicast-server",
      "cisco_ios" => "hostname LAB\nntp server ipv6",
      "cisco_nxos" => "hostname LAB\nntp server",
      "hillstone" => "hostname LAB\nntp server"
    }.each do |platform, source|
      hostname, command = source.split("\n")
      report = audit("#{hostname}\n#{command} #{short_ip}\n#{command} #{long_ip}\n", { "ntp.minimum_servers" => { "expected" => 2 } }, platform: platform)
      expect(report.findings.first.status).to eq(:fail)
      expect(report.configuration.fact("ntp.servers")).to eq([ short_ip ])
      expect(report.configuration.resources.count { |resource| resource.kind == "ntp.association" }).to eq(1)
    end
  end

  it "counts unique addresses across named slots without merging the named resources" do
    text = "set deviceconfig system hostname LAB\nset deviceconfig system ntp-servers primary-ntp-server ntp-server-address #{short_ip}\n" \
      "set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address #{long_ip}\n"
    report = audit(text, { "ntp.minimum_servers" => { "expected" => 2 } }, platform: "palo_alto")
    expect(report.findings.first.status).to eq(:fail)
    resources = report.configuration.resources.select { |resource| resource.kind == "ntp.association" }
    expect(resources.size).to eq(2)
    expect(resources.map { |resource| resource.attributes["address"] }.uniq).to eq([ short_ip ])
  end

  it "shares canonical legacy comparisons with externally supplied facts and rejects malformed address evidence" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 2 } })
    [ [ short_ip, long_ip ], [ "not an address", "192.0.2.1" ] ].each_with_index do |addresses, index|
      result = CtxParser::Result.new(status: :complete, records: [ { "facts" => { "ntp.servers" => addresses } } ])
      evidence = Baseline::Evidence.new(platform: "h3c", sha256: "synthetic", result: result)
      finding = Baseline::Evaluator.new(policy: policy).call(configuration: evidence).findings.first
      expect(finding.status).to eq(index.zero? ? :fail : :unknown)
    end
  end

  it "keeps operation fingerprints stable across equivalent typed address representations" do
    make = lambda do |address|
      Baseline::ConfigurationOperation.new(kind: "ntp.association", identity: { "address" => address, "role" => "server" },
        scope: { "vrf" => "default" }, before: nil, after: {}, action: :add, phase: :create)
    end
    expect(make.call(long_ip).id).to eq(make.call(short_ip).id)
  end

  it "does not broaden host identity to Unicode folding, URI brackets, prefixes or scoped literals" do
    [ "\u212A.example.test", "[2001:db8::10]", "2001:db8::/64", "fe80::1%Vlan1", "256.0.0.1", "001.2.3.4" ].each do |address|
      expect(Baseline::ResourceSchema.address?(address)).to be(false)
    end
    %w[xn--bcher-kva.example 0.0.0.0 255.255.255.255].each { |address| expect(Baseline::ResourceSchema.address?(address)).to be(true) }
  end

  it "does not retain invalid address text in nested validation exceptions" do
    invalid = "PRIVATE BOUNDARY VALUE"
    expect { Baseline::ServerAddress.normalize(invalid) }.to raise_error(ArgumentError) { |error| expect(error.full_message).not_to include(invalid) }
  end

  it "uses canonical resource keys when attaching independently supplied reference evidence" do
    builder = Baseline::FactBuilder.new(complete: true)
    resource = Baseline::ConfigurationResource.new(kind: "tacacs.endpoint",
      identity: { "address" => long_ip, "role" => "authentication" }, scope: { "group" => "OPS" })
    builder.record_resource(resource)
    builder.record_resource_bindings(kind: "tacacs.endpoint", identity: { "address" => short_ip, "role" => "authentication" },
      scope: { "group" => "OPS" }, bindings: [], lines: [ 2 ])
    expect(builder.resources_for("tacacs.endpoint")).to contain_exactly(include(identity: { "address" => short_ip, "role" => "authentication" }, bindings: []))
  end
end

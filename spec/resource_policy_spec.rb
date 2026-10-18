# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Structured baseline resources" do
  def destination(address = "192.0.2.20", port: 1514)
    { "identity" => { "address" => address }, "scope" => { "vrf" => "default" }, "attributes" => { "port" => port } }
  end

  def audit_destinations(text, expected:, managed_scopes: nil, complete: true)
    options = { "expected" => expected }
    options["managed_scopes"] = managed_scopes unless managed_scopes.nil?
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => options })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{text}\n", platform: "h3c", complete: complete)
  end

  it "detects a wrong destination port even when the approved address is present" do
    report = audit_destinations("info-center loghost 192.0.2.20 port 514", expected: [ destination ])
    expect(report.findings.first.status).to eq(:fail)
    expect(report.findings.first.details.fetch(:changed).size).to eq(1)
    expect(report.findings.first.details.fetch(:missing)).to be_empty
    expect(audit_destinations("info-center loghost 192.0.2.20 port 1514", expected: [ destination ])).to be_compliant
  end

  it "only checks declared attributes and preserves stricter or unrelated options" do
    expected = destination
    expected.delete("attributes")
    report = audit_destinations("info-center loghost 192.0.2.20 port 514 facility local6", expected: [ expected ])
    expect(report).to be_compliant
  end

  it "reports additions, removals and field changes within the managed scope" do
    report = audit_destinations("info-center loghost 192.0.2.20 port 514\ninfo-center loghost 192.0.2.30 port 514",
      expected: [ destination, destination("192.0.2.40") ], managed_scopes: [ { "vrf" => "default" } ])
    expect(report.findings.first.status).to eq(:fail)
    details = report.findings.first.details
    expect(details.fetch(:missing).map { |item| item["identity"]["address"] }).to eq([ "192.0.2.40" ])
    expect(details.fetch(:unexpected).map { |item| item["identity"]["address"] }).to eq([ "192.0.2.30" ])
    expect(details.fetch(:changed).size).to eq(1)
  end

  it "does not infer management of extra destinations without a declared scope" do
    report = audit_destinations("info-center loghost 192.0.2.20 port 1514\ninfo-center loghost 192.0.2.30 port 514", expected: [ destination ])
    expect(report).to be_compliant
  end

  it "does not treat destinations in another VPN as unwanted managed objects" do
    report = audit_destinations("info-center loghost 192.0.2.20 port 1514\ninfo-center loghost vpn-instance OTHER 192.0.2.30",
      expected: [ destination ], managed_scopes: [ { "vrf" => "default" } ])
    expect(report).to be_compliant
  end

  it "keeps malformed targets unknown even when the approved set is empty" do
    report = audit_destinations("info-center loghost 999.999.999.999", expected: [], managed_scopes: [ { "vrf" => "default" } ])
    expect(report.findings.first.status).to eq(:unknown)
  end

  it "keeps unsupported resource options and incomplete input unknown" do
    expect(audit_destinations("info-center loghost 192.0.2.20 custom PRIVATE-OPTION", expected: [ destination ]).findings.first.status).to eq(:unknown)
    report = audit_destinations("info-center loghost 192.0.2.20 port 1514", expected: [ destination ], complete: false)
    expect(report.findings.first).to have_attributes(status: :unknown, reason: :input_incomplete)
  end

  it "compares NTP association roles and approved versions" do
    expected = [ { "identity" => { "address" => "192.0.2.10", "role" => "server" },
      "scope" => { "vrf" => "default" }, "attributes" => { "version" => 4 } } ]
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => { "expected" => expected } })
    audit = Baseline::Audit.new(policy: policy)
    expect(audit.call(configuration: "sysname LAB\nntp-service unicast-server 192.0.2.10 version 3\n", platform: "h3c", complete: true).findings.first.status).to eq(:fail)
    expect(audit.call(configuration: "sysname LAB\nntp-service unicast-server 192.0.2.10 version 4\n", platform: "h3c", complete: true)).to be_compliant
  end

  it "compares TACACS role and port in the approved scheme" do
    expected = [ { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" },
      "scope" => { "group" => "OPS", "vrf" => "default" }, "attributes" => { "port" => 49 } } ]
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => { "expected" => expected } })
    report = Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30 149\n",
      platform: "h3c", complete: true)
    expect(report.findings.first.status).to eq(:fail)
    expect(report.findings.first.details.fetch(:changed).size).to eq(1)
  end

  it "rejects duplicate identities, secrets and unsafe policy attributes" do
    [ [ destination, destination ], [ destination.merge("secret" => "PRIVATE") ],
      [ destination.merge("attributes" => { "port" => 0 }) ],
      [ destination.merge("scope" => { "vrf" => "OPS\nquit" }) ] ].each do |expected|
      expect { audit_destinations("sysname LAB", expected: expected) }.to raise_error(ArgumentError)
    end
  end

  it "requires valid identities for each resource domain" do
    cases = {
      "syslog.destinations" => [ { "identity" => { "port" => 514 }, "scope" => {} } ],
      "ntp.associations" => [ { "identity" => { "address" => "192.0.2.10", "role" => "authentication" }, "scope" => {} } ],
      "tacacs.endpoints" => [ { "identity" => { "address" => "192.0.2.30", "role" => "server" }, "scope" => {} } ]
    }
    cases.each do |id, expected|
      expect { Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => expected } }) }.to raise_error(ArgumentError)
    end
  end

  it "rejects contradictory identity attributes and targets outside the managed scope" do
    expected = destination.merge("attributes" => { "address" => "192.0.2.99" })
    expect { audit_destinations("sysname LAB", expected: [ expected ]) }.to raise_error(ArgumentError)
    expect { audit_destinations("sysname LAB", expected: [ destination ], managed_scopes: [ { "vrf" => "OTHER" } ]) }.to raise_error(ArgumentError)
  end

  it "uses the verified Comware default syslog port when it is omitted" do
    report = audit_destinations("info-center loghost 192.0.2.20", expected: [ destination(port: 514) ])
    expect(report).to be_compliant
  end

  it "does not invent an NTP version default when no explicit version exists" do
    expected = [ { "identity" => { "address" => "192.0.2.10", "role" => "server" },
      "scope" => { "vrf" => "default" }, "attributes" => { "version" => 4 } } ]
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => { "expected" => expected } })
    report = Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\nntp-service unicast-server 192.0.2.10\n", platform: "h3c", complete: true)
    expect(report.findings.first).to have_attributes(status: :unknown, reason: :resource_attribute_unresolved)
  end

  it "uses the default routing domain for an address object that omits its VRF" do
    expected = destination.merge("scope" => {})
    report = audit_destinations("info-center loghost 192.0.2.20 port 1514", expected: [ expected ])
    expect(report).to be_compliant
    expect(report.findings.first.expected.first["scope"]).to eq("vrf" => "default")
  end

  it "withholds Comware object compliance when a named default VPN cannot be distinguished from the public domain" do
    cases = {
      "ntp.associations" => [ { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "version" => 4 } },
        "ntp-service unicast-server 192.0.2.10 version 4 vpn-instance default" ],
      "tacacs.endpoints" => [ { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" },
        "scope" => { "group" => "OPS", "vrf" => "default" }, "attributes" => { "port" => 49 } },
        "hwtacacs scheme OPS\n primary authentication 192.0.2.30 49 vpn-instance default" ]
    }
    cases.each do |id, (object, commands)|
      policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => [ object ] } })
      report = Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{commands}\n", platform: "h3c", complete: true)
      expect(report.findings.first.status).to eq(:unknown)
    end
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Facts do
  it "copies configuration identity without freezing caller strings" do
    platform = +"h3c"
    checksum = +"fixture"
    configuration = Baseline::Configuration.new(platform: platform, sha256: checksum,
      result: CtxParser::Result.new(status: :complete))
    expect(platform).not_to be_frozen
    expect(checksum).not_to be_frozen
    platform.replace("changed")
    checksum.replace("changed")
    expect(configuration.platform).to eq("h3c")
    expect(configuration.sha256).to eq("fixture")
    expect(configuration.platform).to be_frozen
    expect(configuration.sha256).to be_frozen
  end

  def access_list(name)
    Baseline::Acl.new(name: name, line: 2, rules: [
      { sequence: 10, action: "permit", protocol: "ip", source: "198.51.100.0/24", line: 3 }
    ])
  end

  it "preserves explicit false but does not infer absence from an incomplete configuration" do
    facts = described_class.new(complete: false)
    facts.record("hostname", "LAB")
    facts.record("ssh.enabled", false, lines: [ 2, 2 ])
    facts.record("ssh.versions", nil)
    facts.record("ntp.servers", [])

    result = facts.result
    expect(result.status).to eq(:partial)
    expect(result.records.first.fetch("facts")).to include("ssh.enabled" => false)
    expect(result.records.first.fetch("facts")).not_to have_key("ssh.versions")
    expect(result.records.first.fetch("facts")).not_to have_key("ntp.servers")
    expect(result.records.first.fetch("sources")).to include("ssh.enabled" => [ 2 ])
  end

  it "keeps an ambiguous ACL alias unknown without changing an earlier result" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    facts.register_acl(access_list("MGMT"), aliases: [ "2000" ])
    facts.management(vtys: [ { protocols: [ "ssh" ], authentication: "aaa", line: 10 } ], ssh_acl: "2000")
    original = facts.result
    expect(original.records.first.fetch("facts")).to include("management.acl.restricted" => true)

    facts.register_acl(access_list("OTHER"), aliases: [ "2000" ], lines: [ 12 ])
    result = facts.result
    configuration = Baseline::Configuration.new(platform: "h3c", sha256: "fixture", result: result)
    expect(configuration.known?("management.acl.restricted")).to be(false)
    expect(result.issues).to include(code: :duplicate_acl, fact: "acls.2000", lines: [ 12 ])
    expect(original.issues).to be_empty
    expect(original.records.first.fetch("facts").fetch("acls").size).to eq(1)
  end

  it "resolves SNMP group ACLs without modifying the parser's supplied users" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    facts.register_acl(access_list("MGMT"))
    users = [ { name: "observer", group: "READONLY", auth: true, priv: true, line: 4 } ]
    facts.snmp(communities: [], users: users, groups: { "READONLY" => { acl: "MGMT" } })

    values = facts.result.records.first.fetch("facts")
    expect(values).to include("snmp.v3_auth_priv" => true, "snmp.acl.restricted" => true)
    expect(values.fetch("snmp.users").first).to include(acl: "MGMT")
    expect(users.first).not_to have_key(:acl)
  end

  it "checks the combined exposure of all management and SNMP entry points" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    %w[0.0.0.0/1 128.0.0.0/1].each_with_index do |source, index|
      facts.register_acl(Baseline::Acl.new(name: "ACL#{index}", line: index + 2, rules: [
        { sequence: 10, action: "permit", protocol: "ip", source: source, line: index + 3 }
      ]))
    end
    entries = 2.times.map { |index| { acl: "ACL#{index}", protocols: [ "ssh" ], authentication: "aaa", line: index + 8 } }
    facts.management(vtys: entries)
    facts.snmp(communities: entries.map { |entry| entry.merge(write: false) }, users: [])

    values = facts.result.records.first.fetch("facts")
    %w[management snmp].each do |scope|
      expect(values.fetch("#{scope}.acl.sources")).to eq([ "0.0.0.0/0" ])
      expect(values.fetch("#{scope}.acl.restricted")).to be(false)
    end
  end

  it "resolves each VTY ACL against that VTY's transport protocols" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    facts.register_acl(Baseline::Acl.new(name: "SSH", line: 2, rules: [
      { sequence: 10, action: "permit", protocol: "tcp", source: "192.0.2.0/24", destination_port: 22 }
    ]))
    facts.register_acl(Baseline::Acl.new(name: "TELNET", line: 4, rules: [
      { sequence: 10, action: "permit", protocol: "tcp", source: "198.51.100.0/24", destination_port: 23 },
      { sequence: 20, action: "permit", protocol: "tcp", source: "0.0.0.0/0", destination_port: 22 }
    ]))
    facts.management(vtys: [
      { acl: "SSH", protocols: [ "ssh" ], authentication: "aaa", line: 6 },
      { acl: "TELNET", protocols: [ "telnet" ], authentication: "aaa", line: 8 }
    ])

    values = facts.result.records.first.fetch("facts")
    expect(values.fetch("management.acl.sources")).to eq(%w[192.0.2.0/24 198.51.100.0/24])
    expect(values.fetch("management.acl.restricted")).to be(true)
  end

  %w[management.acl snmp.acl].each do |scope|
    context "with direct #{scope} sources" do
      it "distinguishes unresolved sources, an empty allowlist, and unrestricted access" do
        [ [ nil, nil ], [ [], true ], [ [ "0.0.0.0/0" ], false ] ].each do |sources, restricted|
          facts = described_class.new(complete: true)
          facts.record("hostname", "LAB")
          facts.direct_acl(fact: scope, sources: sources, bound: true, lines: [ 4 ])
          configuration = Baseline::Configuration.new(platform: "hillstone", sha256: "fixture", result: facts.result)

          expect(configuration.value("#{scope}.bound")).to be(true)
          expect(configuration.value("#{scope}.sources")).to eq(sources)
          expect(configuration.value("#{scope}.restricted")).to eq(restricted)
          expect(configuration.known?("#{scope}.sources")).to eq(!sources.nil?)
          expect(configuration.known?("#{scope}.restricted")).to eq(!sources.nil?)
          if sources.nil?
            expect(configuration.issues).to include(code: :acl_unresolved, fact: "#{scope}.sources", lines: [ 4 ])
          end
        end
      end

      it "retains an explicit unbound state without inferring approved sources" do
        facts = described_class.new(complete: true)
        facts.record("hostname", "LAB")
        facts.direct_acl(fact: scope, sources: nil, bound: false, lines: [ 2 ])
        configuration = Baseline::Configuration.new(platform: "hillstone", sha256: "fixture", result: facts.result)

        expect(configuration.value("#{scope}.bound")).to be(false)
        expect(configuration.known?("#{scope}.bound")).to be(true)
        expect(configuration.known?("#{scope}.sources")).to be(false)
        expect(configuration.known?("#{scope}.restricted")).to be(false)
      end

      it "normalizes combined exposure and preserves the caller's networks and lines" do
        facts = described_class.new(complete: true)
        facts.record("hostname", "LAB")
        networks = %w[192.0.2.128/25 192.0.2.1/25 192.0.2.64/26]
        lines = [ 7, 3, 7 ]
        facts.direct_acl(fact: scope, sources: networks, bound: true, lines: lines)
        result = facts.result
        expect(result.records.first.fetch("facts")).to include("#{scope}.sources" => [ "192.0.2.0/24" ], "#{scope}.restricted" => true)
        expect(result.records.first.fetch("sources").fetch("#{scope}.sources")).to eq([ 7, 3 ])
        expect(networks).to eq(%w[192.0.2.128/25 192.0.2.1/25 192.0.2.64/26])
        expect(lines).to eq([ 7, 3, 7 ])

        facts.direct_acl(fact: scope, sources: %w[0.0.0.0/1 128.0.0.0/1], bound: true)
        expect(facts.result.records.first.fetch("facts")).to include("#{scope}.sources" => [ "0.0.0.0/0" ], "#{scope}.restricted" => false)
        expect(result.records.first.fetch("facts").fetch("#{scope}.sources")).to eq([ "192.0.2.0/24" ])
      end
    end
  end

  it "rejects invalid direct access inputs without recording a source fact" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    valid = { fact: "management.acl", sources: [ "192.0.2.0/24" ], bound: true }
    [ { fact: "invented.acl" }, { bound: nil }, { bound: "true" }, { sources: "192.0.2.0/24" },
      { sources: [ "2001:db8::/32" ] }, { sources: [ "invalid-address" ] } ].each do |invalid|
      expect { facts.direct_acl(**valid.merge(invalid)) }.to raise_error(ArgumentError)
    end
    expect(facts.result.records.first.fetch("facts")).not_to have_key("management.acl.sources")
  end

  it "marks incomplete input without discarding existing evidence or changing earlier snapshots" do
    facts = described_class.new(complete: true)
    facts.record("hostname", "LAB")
    facts.record("ntp.servers", [ "192.0.2.10" ], lines: [ 2 ])
    facts.record("services", { "http" => true }, lines: [ 3 ])
    original = facts.result
    facts.incomplete!(code: :invalid_set_statement, lines: [ 4, 4 ])
    facts.record("syslog.servers", [])
    result = facts.result

    expect(result.status).to eq(:partial)
    expect(result.issues).to include(code: :invalid_set_statement, lines: [ 4 ])
    expect(result.records.first.fetch("facts")).to include("ntp.servers" => [ "192.0.2.10" ], "services" => { "http" => true })
    expect(result.records.first.fetch("facts")).not_to have_key("syslog.servers")
    expect(original.status).to eq(:complete)
    expect(original.issues).to be_empty

    configuration = Baseline::Configuration.new(platform: "palo_alto", sha256: "fixture", result: result)
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "ntp.servers" => { "expected" => [ "192.0.2.10" ] }, "services.disabled" => { "expected" => [ "http" ] }
    })
    report = Baseline::Evaluator.new(policy: policy).call(configuration: configuration)
    expect(report.findings.map(&:status)).to eq(%i[unknown fail])
    expect(report).not_to be_complete
  end
end

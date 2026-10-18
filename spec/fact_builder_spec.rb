# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::FactBuilder do
  it "tracks credential source lines without collapsing credentials from the same line" do
    facts = described_class.new(complete: true)
    expect(facts.credential_recorded?(7)).to be(false)
    %w[snmp_user tacacs].each do |kind|
      facts.record_credential(Baseline::Credential.new(owner: "example", kind: kind, format: "cipher", secret: "synthetic", line: 7))
    end
    expect(facts.credential_recorded?(7)).to be(true)
    expect(facts.credential_recorded?(8)).to be(false)
    values = facts.build.records.first.fetch("facts").fetch("credentials.records")
    expect(values.map { |value| value[:kind] }).to eq(%w[snmp_user tacacs])
  end

  it "copies configuration identity without freezing caller strings" do
    platform = +"h3c"
    checksum = +"fixture"
    configuration = Baseline::Evidence.new(platform: platform, sha256: checksum,
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

  it "keeps received-input completeness separate from parsed-fact completeness" do
    partial = CtxParser::Result.new(status: :partial)
    configuration = Baseline::Evidence.new(platform: "h3c", sha256: "fixture", result: partial, input_complete: true)
    expect(configuration).to be_input_complete
    expect(configuration).not_to be_complete
    expect(configuration.to_h).to include(input_complete: true, status: :partial)
    expect(Baseline::Evidence.new(platform: "h3c", sha256: "fixture", result: partial)).not_to be_input_complete
    complete = CtxParser::Result.new(status: :complete)
    unconfirmed = Baseline::Evidence.new(platform: "h3c", sha256: "fixture", result: complete, input_complete: false)
    expect(unconfirmed).not_to be_complete
    expect do
      Baseline::Evidence.new(platform: "h3c", sha256: "fixture", result: partial, input_complete: "true")
    end.to raise_error(ArgumentError)
  end

  def access_list(name)
    Baseline::Acl.new(name: name, line: 2, rules: [
      { sequence: 10, action: "permit", protocol: "ip", source: "198.51.100.0/24", line: 3 }
    ])
  end

  it "owns the SSH ACL binding name throughout fact assembly" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(access_list("MGMT"))
    facts.register_acl(Baseline::Acl.new(name: "OPEN", line: 4, rules: [
      { sequence: 10, action: "permit", protocol: "ip", source: "0.0.0.0/0" }
    ]))
    binding = +"MGMT"
    facts.record_management_access(vtys: [ { protocols: [ "ssh" ], authentication: "aaa", line: 8 } ], ssh_acl: binding)
    binding.replace("OPEN")
    expect(facts.build.records.first.fetch("facts").fetch("management.acl.sources")).to eq([ "198.51.100.0/24" ])
    expect(binding).not_to be_frozen
  end

  it "rebuilds derived management and SNMP evidence independently for each snapshot" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(access_list("MGMT"))
    facts.record_management_access(vtys: [ { acl: "MGMT", protocols: [ "ssh" ], authentication: "aaa", line: 5 } ])
    facts.record_snmp_access(communities: [], users: [ { auth: true, priv: true, write: false, acl: "MGMT", line: 6 } ])
    original = facts.build

    facts.record_management_access(vtys: [])
    facts.record_snmp_access(communities: [], users: [])
    values = facts.build.records.first.fetch("facts")
    expect(values).to include("management.acl.bound" => false, "snmp.acl.bound" => false)
    expect(values.keys & %w[ssh.vty_ssh_only ssh.vty_aaa management.acl.sources management.acl.restricted
      snmp.v3_auth_priv snmp.acl.sources snmp.acl.restricted]).to be_empty
    expect(original.records.first.fetch("facts")).to include("ssh.vty_aaa" => true,
      "management.acl.sources" => [ "198.51.100.0/24" ], "snmp.v3_auth_priv" => true)
  end

  it "does not carry a previous snapshot's missing-hostname diagnostic into later evidence" do
    facts = described_class.new(complete: true)
    original = facts.build
    facts.record_fact("hostname", "LAB")
    expect(facts.build.issues).not_to include(code: :hostname_missing)
    expect(original.issues).to include(code: :hostname_missing)
  end

  it "replaces SNMP group resolution diagnostics while preserving parser diagnostics" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(access_list("MGMT"))
    facts.record_unknown_fact("snmp.versions", lines: [ 3 ], code: :unsupported_snmp_version)
    users = [ { group: "OPS", auth: true, priv: true, line: 4 } ]
    facts.record_snmp_access(communities: [], users: users, groups: {})
    original = facts.build
    expect(original.issues).to include(hash_including(code: :snmp_group_unresolved))

    facts.record_snmp_access(communities: [], users: users, groups: { "OPS" => { acl: "MGMT", write: false } })
    current = facts.build
    expect(current.issues).not_to include(hash_including(code: :snmp_group_unresolved))
    expect(current.issues).to include(code: :unsupported_snmp_version, fact: "snmp.versions", lines: [ 3 ])
    expect(current.records.first.fetch("facts")).to include("snmp.acl.restricted" => true)
    expect(original.issues).to include(hash_including(code: :snmp_group_unresolved))
  end

  it "removes previous source lines when a replacement fact has no source" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "OLD", lines: [ 2 ])
    original = facts.build
    facts.record_fact("hostname", "NEW")
    expect(facts.build.records.first.fetch("sources")).not_to have_key("hostname")
    expect(original.records.first.fetch("sources")).to include("hostname" => [ 2 ])
  end

  it "preserves explicit false but does not infer absence from an incomplete configuration" do
    facts = described_class.new(complete: false)
    facts.record_fact("hostname", "LAB")
    facts.record_fact("ssh.enabled", false, lines: [ 2, 2 ])
    facts.record_fact("ssh.versions", nil)
    facts.record_fact("ntp.servers", [])

    result = facts.build
    expect(result.status).to eq(:partial)
    expect(result.records.first.fetch("facts")).to include("ssh.enabled" => false)
    expect(result.records.first.fetch("facts")).not_to have_key("ssh.versions")
    expect(result.records.first.fetch("facts")).not_to have_key("ntp.servers")
    expect(result.records.first.fetch("sources")).to include("ssh.enabled" => [ 2 ])
  end

  it "keeps an ambiguous ACL alias unknown without changing an earlier result" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(access_list("MGMT"), aliases: [ "2000" ])
    facts.record_management_access(vtys: [ { protocols: [ "ssh" ], authentication: "aaa", line: 10 } ], ssh_acl: "2000")
    original = facts.build
    expect(original.records.first.fetch("facts")).to include("management.acl.restricted" => true)

    facts.register_acl(access_list("OTHER"), aliases: [ "2000" ], lines: [ 12 ])
    result = facts.build
    configuration = Baseline::Evidence.new(platform: "h3c", sha256: "fixture", result: result)
    expect(configuration.fact_known?("management.acl.restricted")).to be(false)
    expect(result.issues).to include(code: :duplicate_acl, fact: "acls.2000", lines: [ 12 ])
    expect(original.issues).to be_empty
    expect(original.records.first.fetch("facts").fetch("acls").size).to eq(1)
  end

  it "resolves SNMP group ACLs without modifying the parser's supplied users" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(access_list("MGMT"))
    users = [ { name: "observer", group: "READONLY", auth: true, priv: true, line: 4 } ]
    facts.record_snmp_access(communities: [], users: users, groups: { "READONLY" => { acl: "MGMT" } })

    values = facts.build.records.first.fetch("facts")
    expect(values).to include("snmp.v3_auth_priv" => true, "snmp.acl.restricted" => true)
    expect(values.fetch("snmp.users").first).to include(acl: "MGMT")
    expect(users.first).not_to have_key(:acl)
  end

  it "checks the combined exposure of all management and SNMP entry points" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    %w[0.0.0.0/1 128.0.0.0/1].each_with_index do |source, index|
      facts.register_acl(Baseline::Acl.new(name: "ACL#{index}", line: index + 2, rules: [
        { sequence: 10, action: "permit", protocol: "ip", source: source, line: index + 3 }
      ]))
    end
    entries = 2.times.map { |index| { acl: "ACL#{index}", protocols: [ "ssh" ], authentication: "aaa", line: index + 8 } }
    facts.record_management_access(vtys: entries)
    facts.record_snmp_access(communities: entries.map { |entry| entry.merge(write: false) }, users: [])

    values = facts.build.records.first.fetch("facts")
    %w[management snmp].each do |scope|
      expect(values.fetch("#{scope}.acl.sources")).to eq([ "0.0.0.0/0" ])
      expect(values.fetch("#{scope}.acl.restricted")).to be(false)
    end
  end

  it "resolves each VTY ACL against that VTY's transport protocols" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.register_acl(Baseline::Acl.new(name: "SSH", line: 2, rules: [
      { sequence: 10, action: "permit", protocol: "tcp", source: "192.0.2.0/24", destination_port: 22 }
    ]))
    facts.register_acl(Baseline::Acl.new(name: "TELNET", line: 4, rules: [
      { sequence: 10, action: "permit", protocol: "tcp", source: "198.51.100.0/24", destination_port: 23 },
      { sequence: 20, action: "permit", protocol: "tcp", source: "0.0.0.0/0", destination_port: 22 }
    ]))
    facts.record_management_access(vtys: [
      { acl: "SSH", protocols: [ "ssh" ], authentication: "aaa", line: 6 },
      { acl: "TELNET", protocols: [ "telnet" ], authentication: "aaa", line: 8 }
    ])

    values = facts.build.records.first.fetch("facts")
    expect(values.fetch("management.acl.sources")).to eq(%w[192.0.2.0/24 198.51.100.0/24])
    expect(values.fetch("management.acl.restricted")).to be(true)
  end

  %w[management.acl snmp.acl].each do |scope|
    context "with direct #{scope} sources" do
      it "distinguishes unresolved sources, an empty allowlist, and unrestricted access" do
        [ [ nil, nil ], [ [], true ], [ [ "0.0.0.0/0" ], false ] ].each do |sources, restricted|
          facts = described_class.new(complete: true)
          facts.record_fact("hostname", "LAB")
          facts.record_source_restriction(fact: scope, sources: sources, bound: true, lines: [ 4 ])
          configuration = Baseline::Evidence.new(platform: "hillstone", sha256: "fixture", result: facts.build)

          expect(configuration.fact("#{scope}.bound")).to be(true)
          expect(configuration.fact("#{scope}.sources")).to eq(sources)
          expect(configuration.fact("#{scope}.restricted")).to eq(restricted)
          expect(configuration.fact_known?("#{scope}.sources")).to eq(!sources.nil?)
          expect(configuration.fact_known?("#{scope}.restricted")).to eq(!sources.nil?)
          if sources.nil?
            expect(configuration.issues).to include(code: :acl_unresolved, fact: "#{scope}.sources", lines: [ 4 ])
          end
        end
      end

      it "retains an explicit unbound state without inferring approved sources" do
        facts = described_class.new(complete: true)
        facts.record_fact("hostname", "LAB")
        facts.record_source_restriction(fact: scope, sources: nil, bound: false, lines: [ 2 ])
        configuration = Baseline::Evidence.new(platform: "hillstone", sha256: "fixture", result: facts.build)

        expect(configuration.fact("#{scope}.bound")).to be(false)
        expect(configuration.fact_known?("#{scope}.bound")).to be(true)
        expect(configuration.fact_known?("#{scope}.sources")).to be(false)
        expect(configuration.fact_known?("#{scope}.restricted")).to be(false)
      end

      it "normalizes combined exposure and preserves the caller's networks and lines" do
        facts = described_class.new(complete: true)
        facts.record_fact("hostname", "LAB")
        networks = %w[192.0.2.128/25 192.0.2.1/25 192.0.2.64/26]
        lines = [ 7, 3, 7 ]
        facts.record_source_restriction(fact: scope, sources: networks, bound: true, lines: lines)
        result = facts.build
        expect(result.records.first.fetch("facts")).to include("#{scope}.sources" => [ "192.0.2.0/24" ], "#{scope}.restricted" => true)
        expect(result.records.first.fetch("sources").fetch("#{scope}.sources")).to eq([ 7, 3 ])
        expect(networks).to eq(%w[192.0.2.128/25 192.0.2.1/25 192.0.2.64/26])
        expect(lines).to eq([ 7, 3, 7 ])

        facts.record_source_restriction(fact: scope, sources: %w[0.0.0.0/1 128.0.0.0/1], bound: true)
        expect(facts.build.records.first.fetch("facts")).to include("#{scope}.sources" => [ "0.0.0.0/0" ], "#{scope}.restricted" => false)
        expect(result.records.first.fetch("facts").fetch("#{scope}.sources")).to eq([ "192.0.2.0/24" ])
      end
    end
  end

  it "rejects invalid direct access inputs without recording a source fact" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    valid = { fact: "management.acl", sources: [ "192.0.2.0/24" ], bound: true }
    [ { fact: "invented.acl" }, { bound: nil }, { bound: "true" }, { sources: "192.0.2.0/24" },
      { sources: [ "2001:db8::/32" ] }, { sources: [ "invalid-address" ] } ].each do |invalid|
      expect { facts.record_source_restriction(**valid.merge(invalid)) }.to raise_error(ArgumentError)
    end
    expect(facts.build.records.first.fetch("facts")).not_to have_key("management.acl.sources")
  end

  it "marks incomplete input without discarding existing evidence or changing earlier snapshots" do
    facts = described_class.new(complete: true)
    facts.record_fact("hostname", "LAB")
    facts.record_fact("ntp.servers", [ "192.0.2.10" ], lines: [ 2 ])
    facts.record_fact("services", { "http" => true }, lines: [ 3 ])
    original = facts.build
    facts.mark_incomplete!(code: :invalid_set_statement, lines: [ 4, 4 ])
    facts.record_fact("syslog.servers", [])
    result = facts.build

    expect(result.status).to eq(:partial)
    expect(result.issues).to include(code: :invalid_set_statement, lines: [ 4 ])
    expect(result.records.first.fetch("facts")).to include("ntp.servers" => [ "192.0.2.10" ], "services" => { "http" => true })
    expect(result.records.first.fetch("facts")).not_to have_key("syslog.servers")
    expect(original.status).to eq(:complete)
    expect(original.issues).to be_empty

    configuration = Baseline::Evidence.new(platform: "palo_alto", sha256: "fixture", result: result)
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "ntp.servers" => { "expected" => [ "192.0.2.10" ] }, "services.disabled" => { "expected" => [ "http" ] }
    })
    report = Baseline::Evaluator.new(policy: policy).call(configuration: configuration)
    expect(report.findings.map(&:status)).to eq(%i[unknown fail])
    expect(report).not_to be_complete
  end
end

# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "H3C layered SNMP access" do
  def audit(body)
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "snmp.acl_bound" => { "expected" => true }, "snmp.acl_restricted" => { "expected" => true },
      "snmp.sources" => { "expected" => [ "192.0.2.0/25" ] }
    })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\nsnmp-agent\n#{body}", platform: "h3c", complete: true)
  end

  let(:acls) do
    "acl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n rule 10 deny\n#\n" \
      "acl basic 2001\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 deny\n#\n" \
      "acl basic 2002\n rule 5 permit source 192.0.2.0 0.0.0.63\n rule 10 deny\n#\n"
  end

  let(:user) { "snmp-agent usm-user v3 observer OPS authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV acl 2000\n" }

  it "intersects user and group ACLs instead of replacing the group restriction" do
    report = audit(acls + "snmp-agent group v3 OPS privacy acl 2001\n" + user)
    expect(report.configuration.fact("snmp.acl.sources")).to eq([ "192.0.2.0/25" ])
    expect(report).to be_compliant
    entry = report.configuration.fact("snmp.access_endpoints").first
    expect(entry).to include(name: "user:observer", acl_chain: %w[2001 2000], sources: [ "192.0.2.0/25" ], complete: true)
    expect(report.to_h.to_json).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
  end

  it "applies the global ACL to both communities and v3 users while retaining per-principal differences" do
    report = audit(acls + "snmp-agent acl 2002\nsnmp-agent group v3 OPS privacy acl 2001\n" + user +
      "snmp-agent community read cipher SYNTHETIC-COMMUNITY acl 2000\n")
    expect(report.configuration.fact("snmp.acl.sources")).to eq([ "192.0.2.0/26" ])
    expect(report.configuration.fact("snmp.global_access")).to include(acl: "2002", sources: [ "192.0.2.0/26" ], supported: true, complete: true)
    expect(report.configuration.fact("snmp.access_endpoints").map { |entry| entry[:sources] }).to eq([ [ "192.0.2.0/26" ], [ "192.0.2.0/26" ] ])
    expect(report.to_h.to_json).not_to include("SYNTHETIC-COMMUNITY")
  end

  it "recognizes a global binding even when a community has no local ACL" do
    report = audit(acls + "snmp-agent acl 2001\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY\n")
    expect(report.configuration.fact("snmp.acl.bound")).to be(true)
    expect(report.configuration.fact("snmp.acl.sources")).to eq([ "192.0.2.0/25" ])
  end

  it "keeps missing global ACLs and malformed global declarations unresolved" do
    [ "snmp-agent acl 2999", "snmp-agent acl mac 4000" ].each do |command|
      report = audit(acls + "#{command}\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY acl 2001\n")
      expect(report.configuration.fact_known?("snmp.acl.sources")).to be(false)
      expect(report.configuration.fact("snmp.global_access")[:complete]).to be(false)
    end
  end

  it "does not prove a missing binding from malformed global ACL syntax" do
    report = audit("snmp-agent acl mac 4000\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY\n")
    expect(report.configuration.fact_known?("snmp.acl.bound")).to be(false)
  end

  it "resolves a shared ACL only once per endpoint snapshot" do
    acl = instance_double(Baseline::Acl)
    calls = 0
    allow(acl).to receive(:permitted_source_networks) { calls += 1; [ "192.0.2.0/24" ] }
    users = 20.times.map { |index| { name: "USER#{index}", acl_chain: [ "MGMT" ], line: index + 1 } }
    endpoints = Baseline::SnmpAccess.endpoints(communities: [], users: users, global_acl: nil, acls: { "MGMT" => acl }, port: 161, issues: [])
    expect(endpoints.size).to eq(20)
    expect(endpoints.map { |entry| entry[:sources] }).to all(eq([ "192.0.2.0/24" ]))
    expect(calls).to eq(1)
  end

  it "does not bypass missing or ambiguous group ACL evidence with an explicit user ACL" do
    [ "", "snmp-agent group v3 OPS privacy acl 2001\nsnmp-agent group v3 OPS authentication acl 2002\n" ].each do |groups|
      report = audit(acls + groups + user)
      expect(report.configuration.fact_known?("snmp.acl.sources")).to be(false)
      expect(report.configuration.fact("snmp.access_endpoints").first[:complete]).to be(false)
    end
  end
end

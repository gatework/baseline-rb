# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "SNMP access option boundaries" do
  def evidence(body)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "snmp.sources" => { "expected" => [ "192.0.2.0/24" ] } })
    prefix = "sysname LAB\nsnmp-agent\nacl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n rule 10 deny\n#\n"
    Baseline::Audit.new(policy: policy).call(configuration: prefix + body, platform: "h3c", complete: true).configuration
  end

  it "separates view argument names from ACL options and preserves nonsecret group definitions" do
    config = evidence("snmp-agent group v3 OPS privacy read-view acl write-view WRITE acl 2000\n" \
      "snmp-agent usm-user v3 observer OPS authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n")
    expect(config.fact("snmp.acl.sources")).to eq([ "192.0.2.0/24" ])
    expect(config.fact("snmp.group_definitions").first).to include(name: "OPS", version: "v3", security: "privacy", read_view: "acl", write_view: "WRITE", acl: "2000", complete: true)
    expect(config.facts.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
  end

  it "does not treat an IPv6-only community ACL as an IPv4 restriction" do
    config = evidence("snmp-agent community read cipher SYNTHETIC-COMMUNITY acl ipv6 2000\n")
    expect(config.fact("snmp.acl.bound")).to be(false)
    expect(config.fact("snmp.acl.sources")).to eq([ "0.0.0.0/0" ])
  end

  it "keeps unknown or contradictory community access tails unresolved" do
    [ "acl 2000 unsupported-option VALUE", "acl 2000 acl 2001", "mib-view", "acl name" ].each do |tail|
      config = evidence("snmp-agent community read cipher SYNTHETIC-COMMUNITY #{tail}\n")
      expect(config.fact_known?("snmp.acl.sources")).to be(false)
    end
  end

  it "uses the latest full H3C user definition without stale auth, ACL or credential records" do
    input = "snmp-agent group v3 OPS privacy\n" \
      "snmp-agent usm-user v3 observer OPS authentication-mode sha simple OLD-PLAINTEXT-SECRET privacy-mode aes128 simple OLD-PRIVACY-SECRET acl 2000\n" \
      "snmp-agent usm-user v3 observer OPS\n"
    config = evidence(input)
    expect(config.fact("snmp.v3_auth_priv")).to be(false)
    expect(config.fact("snmp.users").first[:acl]).to be_nil
    expect(config.fact("snmp.acl.sources")).to eq([ "0.0.0.0/0" ])
    expect(config.fact("credentials.records")).to eq([])
  end

  it "recognizes the H3C command-wide cipher qualifier without exposing key values" do
    config = evidence("snmp-agent group v3 OPS privacy\n" \
      "snmp-agent usm-user v3 observer OPS cipher authentication-mode sha SYNTHETIC-AUTH privacy-mode aes128 SYNTHETIC-PRIV\n")
    expect(config.fact("credentials.storage_safe")).to be(true)
    expect(config.fact("credentials.records").map { |entry| entry[:storage] }).to eq(%w[protected protected])
    expect(config.facts.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
  end

  it "recognizes documented H3C SHA-2 algorithm spellings" do
    %w[sha224 sha256 sha384 sha512].each do |algorithm|
      config = evidence("snmp-agent group v3 OPS privacy\n" \
        "snmp-agent usm-user v3 observer OPS cipher authentication-mode #{algorithm} SYNTHETIC-AUTH privacy-mode aes128 SYNTHETIC-PRIV\n")
      expect(config.fact_known?("snmp.v3_auth_priv")).to be(true)
      expect(config.fact("snmp.v3_auth_priv")).to be(true)
    end
  end

  it "keeps security and credential presence unresolved after an unsupported user-role update" do
    config = evidence("snmp-agent group v3 OPS privacy\n" \
      "snmp-agent usm-user v3 observer OPS cipher authentication-mode sha SYNTHETIC-AUTH privacy-mode aes128 SYNTHETIC-PRIV\n" \
      "snmp-agent usm-user v3 observer user-role network-admin\n")
    expect(config.fact_known?("snmp.v3_auth_priv")).to be(false)
    expect(config.fact_known?("credentials.storage_safe")).to be(false)
    expect(config.fact("credentials.present")).to be(true)
    expect(config.fact("credentials.records").map { |entry| entry[:storage] }).to eq(%w[unknown unknown])
  end

  it "does not reinterpret a dangling community format keyword as a plaintext community" do
    %w[cipher simple].each do |format|
      config = evidence("snmp-agent community read #{format}\n")
      expect(config.fact_known?("snmp.acl.sources")).to be(false)
      expect(config.fact("credentials.records")).to eq([])
    end
  end

  it "does not interpret a user's group name as an ACL option" do
    config = evidence("snmp-agent group v3 acl privacy\nsnmp-agent usm-user v3 observer acl authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n")
    expect(config.fact("snmp.users").first[:acl]).to be_nil
    expect(config.fact("snmp.acl.sources")).to eq([ "0.0.0.0/0" ])
  end
end

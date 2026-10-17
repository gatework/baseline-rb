# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"
require "baseline/palo_alto/parser"

RSpec.describe Baseline::PaloAlto::Parser do
  let(:fixture) { File.read(File.expand_path("fixtures/baseline/palo_alto.cfg", __dir__)) }

  def parse(text = fixture, complete: true)
    result = described_class.parse(text, complete: complete)
    Baseline::Configuration.new(platform: "palo_alto", sha256: "fixture", result: result)
  end

  it "extracts set syntax into shared facts while excluding certificate commands and secrets" do
    configuration = parse
    expect(configuration).to be_complete
    expect(configuration.value("hostname")).to eq("PA-FIXTURE")
    expect(configuration.value("ntp.servers")).to eq(%w[192.0.2.10 192.0.2.11])
    expect(configuration.value("ntp.authentication")).to be(false)
    expect(configuration.value("services")).to eq("telnet" => false, "http" => false, "https" => true)
    expect(configuration.value("tacacs.servers")).to eq(%w[192.0.2.30 192.0.2.31])
    expect(configuration.value("tacacs.login")).to be(true)
    expect(configuration.value("syslog.servers")).to eq([ "192.0.2.20" ])
    expect(configuration.value("snmp.write_enabled")).to be(false)
    expect(configuration.value("management.acl.sources")).to eq([ "198.51.100.0/24" ])
    expect(configuration.known?("ssh.vty_aaa")).to be(false)
    expect(configuration.known?("tacacs.accounting")).to be(false)
    expect(configuration.to_h.to_json).not_to include("PRIVATE-", "CERTIFICATE", "203.0.113.99")
  end

  it "unions native MGT and enabled data-interface allowlists and ignores unused profiles" do
    text = fixture + <<~CFG
      set network profiles interface-management-profile UNUSED https yes
      set network profiles interface-management-profile RESTRICTED https yes
      set network profiles interface-management-profile RESTRICTED permitted-ip 203.0.113.0/24
      set network interface ethernet ethernet1/1 layer3 interface-management-profile RESTRICTED
    CFG
    configuration = parse(text)
    expect(configuration.value("management.acl.sources")).to eq(%w[198.51.100.0/24 203.0.113.0/24])
    expect(configuration.value("management.acl.restricted")).to be(true)
    text += "set network interface ethernet ethernet1/2 layer3 interface-management-profile UNUSED\n"
    expect(parse(text).value("management.acl.sources")).to eq([ "0.0.0.0/0" ])
    expect(parse(text).value("management.acl.restricted")).to be(false)
  end

  it "does not add an unrestricted MGT source when its management services are all explicitly disabled" do
    text = fixture.gsub("disable-ssh no", "disable-ssh yes").gsub("disable-https no", "disable-https yes")
      .sub("set deviceconfig system permitted-ip 198.51.100.0/24\n", "") + <<~CFG
      set network profiles interface-management-profile SECURE ssh yes
      set network profiles interface-management-profile SECURE permitted-ip 203.0.113.7/32
      set network interface loopback units loopback.1 interface-management-profile SECURE
    CFG
    configuration = parse(text)
    expect(configuration.value("management.acl.sources")).to eq([ "203.0.113.7/32" ])
    expect(configuration.value("ssh.enabled")).to be(true)
    expect(configuration.value("snmp.acl.sources")).to eq([ "0.0.0.0/0" ])
  end

  it "keeps unknown profile references and unsupported IPv6 native sources unresolved" do
    [ fixture + "set network interface ethernet ethernet1/1 layer3 interface-management-profile MISSING\n",
      fixture.sub("permitted-ip 198.51.100.0/24", "permitted-ip 2001:db8::/64") ].each do |text|
      configuration = parse(text)
      expect(configuration.known?("management.acl.restricted")).to be(false)
      expect(configuration.known?("management.acl.bound")).to be(false)
    end
  end

  it "retains explicit violations but prevents absence-based conclusions from partial exports" do
    configuration = parse("set deviceconfig system hostname PA-PARTIAL\n", complete: false)
    expect(configuration).not_to be_complete
    expect(configuration.scope_known?("snmp.community_present")).to be(false)
    expect(configuration.scope_known?("credentials.present")).to be(false)
    expect(configuration.scope_known?("management.acl.restricted")).to be(false)
    configuration = parse(fixture, complete: false)
    expect(configuration.scope_known?("credentials.storage_safe")).to be(true)
    expect(configuration.value("credentials.storage_safe")).to be(false)
  end

  it "invalidates completeness for malformed relevant scalar, flag, community and quoted values" do
    [ "set deviceconfig system service disable-ssh\n",
      "set deviceconfig system service disable-ssh maybe\n",
      "set deviceconfig system snmp-setting access-setting version v2c snmp-community-string\n",
      "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address \"first\nsecond\"\n",
      "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address \\\n" ].each do |suffix|
      configuration = parse("set deviceconfig system hostname PA-MALFORMED\n" + suffix)
      expect(configuration).not_to be_complete
      expect(configuration.scope_known?("credentials.present")).to be(false)
      expect(configuration.scope_known?("ntp.servers")).to be(false)
    end
  end

  it "does not treat an unterminated certificate as a complete export" do
    configuration = parse(fixture.sub("-----END CERTIFICATE-----\n\"\n", ""))
    expect(configuration).not_to be_complete
    expect(configuration.issues).to include(hash_including(code: :incomplete_quoted_value))
    expect(configuration.scope_known?("snmp.write_enabled")).to be(false)
  end

  it "does not guess unspecified MGT service defaults or retain state when a parser is reused" do
    parser = described_class.new
    parser.parse(fixture, complete: true)
    result = parser.parse("set deviceconfig system hostname PA-SECOND\n", complete: true)
    facts = result.records.first.fetch("facts")
    expect(facts["ssh.enabled"]).to be_nil
    expect(facts["snmp.enabled"]).to be_nil
    expect(facts["services"]).to eq("telnet" => nil, "http" => nil, "https" => nil)
    expect(facts["ntp.servers"]).to eq([])
  end

  it "resolves the first profile in a sequence and rejects dangling or unknown primary methods" do
    text = fixture.sub("system authentication-profile TACACS-AUTH", "system authentication-profile ORDERED") + <<~CFG
      set shared authentication-profile LOCAL method local-database
      set shared authentication-sequence ORDERED authentication-profiles [ TACACS-AUTH LOCAL ]
    CFG
    expect(parse(text).value("tacacs.login")).to be(true)
    expect(parse(text.sub("[ TACACS-AUTH LOCAL ]", "[ LOCAL TACACS-AUTH ]")).value("tacacs.login")).to be(false)
    expect(parse(text.sub("[ TACACS-AUTH LOCAL ]", "[ MISSING LOCAL ]")).known?("tacacs.login")).to be(false)
    expect(parse(fixture.sub("method tacplus server-profile AAA", "method FUTURE server-profile AAA")).known?("tacacs.login")).to be(false)
  end

  it "distinguishes SNMPv3 polling credentials from outbound traps and requires both passwords" do
    text = fixture.lines.reject { |line| line.include?("snmp-community-string") }.join + <<~CFG
      set deviceconfig system snmp-setting access-setting version v3 users MONITOR authpwd -AQ==PRIVATE-AUTH
      set deviceconfig system snmp-setting access-setting version v3 users MONITOR privpwd -AQ==PRIVATE-PRIV
      set shared log-settings snmptrap TRAPS version v2c server DEST community PRIVATE-TRAP
    CFG
    configuration = parse(text)
    expect(configuration.value("snmp.versions")).to eq([ "v3" ])
    expect(configuration.value("snmp.community_present")).to be(false)
    expect(configuration.value("snmp.v3_auth_priv")).to be(true)
    expect(configuration.value("snmp.write_enabled")).to be(false)
    expect(configuration.to_h.to_json).not_to include("PRIVATE-")
    text = text.lines.reject { |line| line.include?("privpwd") }.join
    expect(parse(text).value("snmp.v3_auth_priv")).to be(false)
  end

  it "keeps contradictory SNMP versions and unrecognized phash formats unknown" do
    text = fixture + "set deviceconfig system snmp-setting access-setting version v3 users OTHER view ALL\n"
    expect(parse(text).known?("snmp.versions")).to be(false)
    text = fixture.lines.reject { |line| line.include?("snmp-community-string") }.join.sub("$5$fixture$PRIVATE-HASH", "unrecognized")
    expect(parse(text).known?("credentials.storage_safe")).to be(false)
  end

  it "preserves provenance line numbers without exposing a secret in captured data" do
    parser = described_class.new
    result = parser.parse(fixture, complete: true)
    line = fixture.lines.index { |text| text.include?("phash") } + 1
    expect(result.records.first.fetch("facts").fetch("credentials.records")).to include(hash_including(line: line, storage: "protected"))
    expect(parser.cursor.captures.to_json).not_to include("PRIVATE-")
  end

  it "keeps a syslog server definition with no address unresolved" do
    configuration = parse("set deviceconfig system hostname LAB\nset shared log-settings syslog LOGS server FIRST transport UDP\n")
    expect(configuration.known?("syslog.servers")).to be(false)
    expect(configuration.issues).to include(hash_including(code: :syslog_server_unresolved))
  end

  it "validates NTP authentication tuples without capturing keys or guessing future algorithms" do
    prefix = "set deviceconfig system ntp-servers primary-ntp-server"
    text = "set deviceconfig system hostname LAB\n#{prefix} ntp-server-address 192.0.2.10\n"
    symmetric = "#{prefix} authentication-type symmetric-key key-id 10\n#{prefix} authentication-type symmetric-key algorithm sha256 authentication-key PRIVATE-NTP\n"
    expect(parse(text + symmetric).value("ntp.authentication")).to be(true)
    expect(parse(text + symmetric).to_h.to_json).not_to include("PRIVATE-NTP")
    expect(parse(text + "#{prefix} authentication-type autokey\n").value("ntp.authentication")).to be(true)
    [ symmetric.sub("key-id 10", "key-id invalid"), symmetric.sub("sha256", "FUTURE"),
      "#{prefix} authentication-type none extra\n", "#{prefix} authentication-type autokey extra\n" ].each do |invalid|
      result = parse(text + invalid)
      expect(result.known?("ntp.authentication")).to be(false)
      expect(result.value("ntp.servers")).to eq([ "192.0.2.10" ])
    end
  end

  it "retains unknown credential evidence for accounts with missing or malformed hashes" do
    [ "set mgt-config users admin permissions role-based superuser yes\n",
      "set mgt-config users admin phash\n" ].each do |account|
      configuration = parse("set deviceconfig system hostname PA-ACCOUNT\n" + account)
      expect(configuration.value("credentials.present")).to be(true)
      expect(configuration.value("credentials.records")).to include(hash_including(owner: "admin", storage: "unknown"))
      expect(configuration.known?("credentials.storage_safe")).to be(false)
    end
    configuration = parse("set deviceconfig system hostname PA-EXTERNAL\nset mgt-config users remote authentication-profile EXTERNAL\n")
    expect(configuration.value("credentials.present")).to be(false)
  end

  it "does not present unresolved server definitions as confirmed empty server collections" do
    text = "set deviceconfig system hostname PA-UNRESOLVED\n" + <<~CFG
      set deviceconfig system ntp-servers primary-ntp-server unsupported value
      set shared server-profile tacplus AAA server FIRST secret -AQ==PRIVATE-CIPHER
      set shared authentication-profile TACACS-AUTH method tacplus server-profile AAA
      set deviceconfig system authentication-profile TACACS-AUTH
    CFG
    configuration = parse(text)
    expect(configuration.known?("ntp.servers")).to be(false)
    expect(configuration.known?("ntp.authentication")).to be(false)
    expect(configuration.known?("tacacs.servers")).to be(false)
    expect(configuration.known?("tacacs.login")).to be(false)
  end

  it "does not ignore malformed data-interface management profile bindings" do
    [ "interface-management-profile", "interface-management-profile PROFILE extra" ].each do |binding|
      configuration = parse(fixture + "set network interface ethernet ethernet1/1 layer3 #{binding}\n")
      expect(configuration).not_to be_complete
      expect(configuration.known?("management.acl.restricted")).to be(false)
      expect(configuration.known?("snmp.acl.restricted")).to be(false)
    end
  end
end

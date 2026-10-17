# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Hillstone::Parser do
  let(:configuration) { File.read(File.expand_path("fixtures/baseline/hillstone.cfg", __dir__)) }

  def parse(text, complete: true)
    result = described_class.parse(text, complete: complete)
    Baseline::Configuration.new(platform: "hillstone", sha256: "synthetic", result: result)
  end

  it "normalizes native host lists, services and server references without leaking credentials" do
    result = parse(configuration)
    expect(result).to be_complete
    expect(result.facts).to include("hostname" => "LAB-FW", "ssh.enabled" => true,
      "management.acl.sources" => [ "198.51.100.0/24" ], "management.acl.restricted" => true,
      "ntp.servers" => %w[192.0.2.10 192.0.2.11], "ntp.source" => "MGT0", "ntp.authentication" => true,
      "syslog.servers" => [ "192.0.2.20" ], "snmp.enabled" => true, "snmp.versions" => [ "v2c" ],
      "snmp.acl.sources" => [ "198.51.100.8/32" ], "snmp.write_enabled" => false,
      "tacacs.servers" => %w[192.0.2.30 192.0.2.31], "tacacs.login" => true, "tacacs.authorization" => true,
      "tacacs.keys_present" => true)
    expect(result.facts).not_to have_key("ssh.vty_aaa")
    expect(result.facts).not_to have_key("ssh.vty_ssh_only")
    expect(result.facts).not_to have_key("ssh.versions")
    expect(result.to_h.to_s).not_to include("SYNTHETIC-", "203.0.113.20")
  end

  it "recognizes explicit write grants and leaves an unknown security format local to SNMP" do
    result = parse(configuration.sub(" ro\n", " rw\n") + "snmp-server user malformed\n")
    expect(result.value("snmp.write_enabled")).to be(true)
    expect(result.known?("snmp.write_enabled")).to be(true)
    expect(result.known?("snmp.v3_auth_priv")).to be(false)
    expect(result.value("ssh.enabled")).to be(true)
  end

  it "does not infer disabled listeners or restrictive sources from an absent declaration" do
    result = parse("hostname LAB\n")
    expect(result.value("ssh.enabled")).to be_nil
    expect(result.value("services").values).to all(be_nil)
    expect(result.known?("management.acl.restricted")).to be(false)
    expect(result.value("tacacs.login")).to be_nil
  end

  it "combines trusted ranges and preserves explicitly unrestricted exposure" do
    result = parse(configuration + "admin host any ssh\n")
    expect(result.value("management.acl.sources")).to eq([ "0.0.0.0/0" ])
    expect(result.value("management.acl.restricted")).to be(false)
    result = parse(configuration.gsub("198.51.100.0/25", "198.51.100.0 255.255.255.128"))
    expect(result.value("management.acl.sources")).to eq([ "198.51.100.0/24" ])
  end

  it "marks invalid host ranges unknown instead of dropping them from a restrictive union" do
    [ "range 198.51.100.255 198.51.100.0", "2001:db8::/32", "not-an-address" ].each do |source|
      result = parse(configuration + "admin host #{source} ssh\n")
      expect(result.known?("management.acl.restricted")).to be(false)
    end
  end

  it "keeps unknown NTP and logging arguments from proving an empty compliant server set" do
    [ "ntp server", "ntp server 192.0.2.10 unsupported", "ntp server 192.0.2.10 key invalid" ].each do |command|
      expect(parse("hostname LAB\n#{command}\n").known?("ntp.servers")).to be(false)
    end
    result = parse("hostname LAB\nlogging syslog 192.0.2.1 udp bad-port\n")
    expect(result.known?("syslog.servers")).to be(false)
  end

  it "does not promote nested commands or multiline UI data into global facts" do
    text = <<~CONFIG
      hostname LAB
      interface ethernet0/0
        hostname SPOOF
        ntp server 203.0.113.5
      exit
      admin user operator
        value "first line
      snmp-server manager
      admin host any ssh
      ntp server 203.0.113.6
      last line"
      exit
      ntp server 192.0.2.10
    CONFIG
    result = parse(text)
    expect(result).to be_complete
    expect(result.value("hostname")).to eq("LAB")
    expect(result.value("ntp.servers")).to eq([ "192.0.2.10" ])
    expect(result.value("snmp.enabled")).to be_nil
    expect(result.value("management.acl.sources")).to be_nil
  end

  it "downgrades unterminated and modeled multiline values without losing earlier facts" do
    [ "value \"unterminated", "ntp server \"192.0.2.1\ncontinued\"\n" ].each do |ending|
      result = parse("hostname LAB\ninterface ethernet0/0\n  manage ssh\nexit\n#{ending}")
      expect(result.status).to eq(:partial)
      expect(result.value("ssh.enabled")).to be(true)
      expect(result.value("ntp.servers")).to be_nil
    end
  end

  it "retains known violations from partial input but never reports compliant absence" do
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "snmp.write_enabled" => { "expected" => false }, "ntp.minimum_servers" => { "expected" => 1 }
    })
    report = Baseline::Audit.new(policy: policy).call(platform: "stoneos", complete: false,
      configuration: "hostname LAB\nsnmp-server host 192.0.2.1 version 2c community PRIVATE-FIXTURE rw\n")
    expect(report.findings.map(&:status)).to eq(%i[fail unknown])
    expect(report.to_h.to_s).not_to include("PRIVATE-FIXTURE")
  end

  it "keeps unknown encoded password storage unknown and rejects incomplete secret tuples" do
    result = parse("hostname LAB\nadmin user operator\n  password $vendor-format$PRIVATE-FIXTURE\nexit\n")
    expect(result.value("credentials.storage_safe")).to be_nil
    expect(result.to_h.to_s).not_to include("PRIVATE-FIXTURE")
    malformed = parse("hostname LAB\naaa-server X type tacacs+\n  host 192.0.2.1\n  secret cipher\nexit\n")
    expect(malformed.status).to eq(:partial)
    expect(malformed.value("tacacs.keys_present")).to be(false)
  end

  it "does not let comment apostrophes hide a write grant or banner bodies inject one" do
    text = <<~CONFIG
      hostname LAB
      # operator's comments
      snmp-server manager
      snmp-server host any version 2c community SYNTHETIC rw
      # end user's comments
    CONFIG
    result = parse(text)
    expect(result).to be_complete
    expect(result.value("snmp.write_enabled")).to be(true)
    banner = "hostname LAB\nbanner motd ^\noperator's note\nsnmp-server host any version 2c community SYNTHETIC rw\n^\nntp server 192.0.2.1\n"
    expect(parse(banner).value("snmp.write_enabled")).to be(false)
    expect(parse(banner).value("ntp.servers")).to eq([ "192.0.2.1" ])
  end

  it "uses the documented read-only default and retains accounts without password evidence" do
    result = parse("hostname LAB\nsnmp-server host 192.0.2.1 version 2c community SYNTHETIC\nadmin user observer\n  role admin\nexit\n")
    expect(result.value("snmp.write_enabled")).to be(false)
    expect(result.value("snmp.versions")).to eq([ "v2c" ])
    expect(result.value("credentials.present")).to be(true)
    expect(result.value("credentials.records")).to include(hash_including(owner: "observer", storage: "unknown", present: false))
  end

  it "does not replace a duplicate TACACS definition with apparently complete evidence" do
    text = configuration + "aaa-server \"TACACS A\" type tacacs+\n  host 203.0.113.10\n  secret cipher SYNTHETIC\nexit\n"
    result = parse(text)
    expect(result.known?("tacacs.servers")).to be(false)
    expect(result.known?("tacacs.login")).to be(false)
    expect(result.value("ssh.enabled")).to be(true)
  end

  it "resolves StoneOS forward declarations without treating them as conflicting definitions" do
    text = "aaa-server \"TACACS A\" type tacacs+\nexit\n" + configuration
    result = parse(text)
    expect(result.known?("tacacs.servers")).to be(true)
    expect(result.value("tacacs.servers")).to eq(%w[192.0.2.30 192.0.2.31])
    expect(result.value("tacacs.login")).to be(true)
    expect(result.issues).not_to include(hash_including(code: :duplicate_tacacs_scheme))
    expect(parse(configuration + "aaa-server \"TACACS A\" type tacacs+\nexit\n").value("tacacs.servers")).to eq(result.value("tacacs.servers"))
    expect(parse("hostname LAB\naaa-server EMPTY type tacacs+\nexit\n").known?("tacacs.servers")).to be(false)
  end

  it "validates server destinations and does not turn incomplete definitions into empty approved sets" do
    [ '""', '"not a host"', "999.0.0.1", "192.0.2.1/24" ].each do |address|
      text = "hostname LAB\nntp server #{address}\nlogging syslog #{address} udp 514\naaa-server AAA type tacacs+\n  host #{address}\nexit\n"
      result = parse(text)
      %w[ntp.servers syslog.servers tacacs.servers].each { |path| expect(result.known?(path)).to be(false) }
    end
    expect(parse("hostname LAB\naaa-server AAA type tacacs+\n  secret cipher SYNTHETIC\nexit\n").known?("tacacs.servers")).to be(false)
    result = parse("hostname LAB\nntp server ntp.example.test\nntp server 2001:db8::1\n")
    expect(result.value("ntp.servers")).to eq(%w[ntp.example.test 2001:db8::1])
    expect(parse('hostname LAB' + "\nsnmp-server host 192.0.2.1 version 2c community \"\" ro\n").known?("snmp.write_enabled")).to be(false)
  end
end

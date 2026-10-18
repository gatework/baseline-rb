# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Audit do
  let(:policy) { Baseline::Policy.default }
  let(:audit) { described_class.new(policy: policy) }

  def fixture(platform) = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))
  def parse(platform, text = fixture(platform)) = audit.call(configuration: text, platform: platform, complete: true)

  %w[h3c huawei cisco_ios cisco_nxos].each do |platform|
    it "extracts #{platform} management facts and excludes all secret material from reports" do
      report = parse(platform)
      config = report.configuration
      expect(config).to be_complete
      expect(config.fact("ntp.servers")).to eq(%w[192.0.2.10 192.0.2.11])
      expect(config.fact("tacacs.servers")).to match_array(%w[192.0.2.30 192.0.2.31])
      expect(config.fact("tacacs.login")).to be(true)
      expect(config.fact("tacacs.authorization")).to be(true)
      expect(config.fact("tacacs.accounting")).to be(true)
      expect(config.fact("snmp.v3_auth_priv")).to be(true)
      expect(config.fact("management.acl.bound")).to be(true)
      expect(config.fact("management.acl.restricted")).to be(true)
      expect(report.to_h.to_json).not_to include("PRIVATE-", "password simple", "secret 9")
      expect(config.inspect).not_to include("PRIVATE-")
    end
  end

  {
    "h3c" => [ "sysname LAB", "ntp-service source" ],
    "huawei" => [ "sysname LAB", "ntp-service source-interface" ],
    "cisco_ios" => [ "hostname LAB", "ntp source" ],
    "cisco_nxos" => [ "hostname LAB", "ntp source-interface" ]
  }.each do |platform, (hostname, command)|
    it "retains the NTP source interface from #{platform} CLI syntax" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.source" => { "expected" => "Loopback0" } })
      report = described_class.new(policy: policy).call(configuration: "#{hostname}\n#{command} Loopback0\n", platform: platform, complete: true)
      expect(report.configuration.fact("ntp.source")).to eq("Loopback0")
      expect(report.findings.first.status).to eq(:pass)
    end
  end

  it "keeps nested interface statements and banner text out of global facts" do
    text = "banner motd ^C\nntp-service unicast-server 203.0.113.1\nssh server disable\n^C\n" + fixture("h3c")
    config = parse("h3c", text).configuration
    expect(config.fact("ntp.servers")).to eq(%w[192.0.2.10 192.0.2.11])
    expect(config.fact("ssh.enabled")).to be(true)
  end

  it "uses the last repeated setting and handles ordered ACL denies" do
    config = parse("h3c", fixture("h3c") + "ssh server disable\nssh server enable\n").configuration
    expect(config.fact("ssh.enabled")).to be(true)
    expect(config.fact("management.acl.sources")).to eq([ "198.51.100.0/25" ])
  end

  it "does not interpret the IPv6 family keyword as an IPv4 ACL identity" do
    text = fixture("h3c") + <<~CLI
      acl ipv6 advanced name MANAGEMENT
       rule 0 permit ipv6 source 2001:db8:: 64
      #
      acl ipv6 advanced name OTHER
       rule 0 deny ipv6
      #
    CLI
    config = parse("h3c", text).configuration
    expect(config.fact("acls").map { |acl| acl[:name] }).not_to include("ipv6")
    expect(config.issues.select { |issue| issue[:code] == :unsupported_acl_family }.size).to eq(2)
    expect(config.issues.map { |issue| issue[:code] }).not_to include(:duplicate_acl)
    expect(config.fact_known?("management.acl.sources")).to be(true)
    expect(config.fact("management.acl.sources")).to eq([ "198.51.100.0/25" ])
  end

  it "does not count dangling or inactive TACACS definitions as management authentication" do
    config = parse("h3c", fixture("h3c").sub("domain default enable OPS", "domain default enable UNUSED")).configuration
    expect(config.fact("tacacs.login")).to be(false)
    config = parse("cisco_ios", fixture("cisco_ios").sub("server name AAA2", "server name MISSING")).configuration
    expect(config.fact_known?("tacacs.login")).to be(false)
    config = parse("cisco_ios", fixture("cisco_ios").sub("login authentication default", "login local")).configuration
    expect(config.fact("tacacs.login")).to be(false)
  end

  it "resolves the named TACACS login lists selected by every VTY" do
    text = fixture("cisco_ios").sub("login default group OPS local", "login OPERATORS group OPS local")
      .sub("login authentication default", "login authentication OPERATORS")
    config = parse("cisco_ios", text).configuration
    expect(config.fact("tacacs.login")).to be(true)
    expect(config.fact_known?("tacacs.login")).to be(true)
    expect(config.sources.fetch("tacacs.login")).not_to be_empty

    text += "line vty 16 20\n login local\n transport input ssh\n!\n"
    expect(parse("cisco_ios", text).configuration.fact("tacacs.login")).to be(false)
  end

  it "keeps missing or unsupported active login lists unknown" do
    variants = [ fixture("cisco_ios").sub("login authentication default", "login authentication MISSING"),
      fixture("cisco_ios").sub("login default group OPS local", "login default group MISSING local"),
      fixture("cisco_ios").sub("login default group OPS local", "login default group OPS unsupported-method"),
      fixture("cisco_ios").sub("aaa new-model", "no aaa new-model") ]
    variants.each do |text|
      expect(parse("cisco_ios", text).configuration.fact_known?("tacacs.login")).to be(false)
    end
  end

  it "does not mistake an inactive named list or a later TACACS fallback for the primary login method" do
    text = fixture("cisco_ios").sub("login default group OPS local", "login default local\naaa authentication login UNUSED group OPS local")
    expect(parse("cisco_ios", text).configuration.fact("tacacs.login")).to be(false)
    text = fixture("cisco_ios").sub("login default group OPS local", "login default group radius group OPS local")
    expect(parse("cisco_ios", text).configuration.fact("tacacs.login")).to be(false)
  end

  it "resolves named Comware management ACL references and VTY bindings without a direction" do
    text = fixture("h3c").sub("acl basic 2000", "acl basic 2000 name MGMT")
      .sub("ssh server acl 2000", "ssh server acl name MGMT").sub("acl 2000 inbound", "acl name MGMT")
    config = parse("h3c", text).configuration
    expect(config.fact("management.acl.bound")).to be(true)
    expect(config.fact("management.acl.sources")).to eq([ "198.51.100.0/25" ])
    expect(config.fact_known?("management.acl.restricted")).to be(true)

    text = text.sub("ssh server acl name MGMT\n", "")
    expect(parse("h3c", text).configuration.fact("management.acl.bound")).to be(true)
    text = text.sub("acl name MGMT", "acl name MISSING")
    expect(parse("h3c", text).configuration.fact_known?("management.acl.restricted")).to be(false)
  end

  it "leaves unresolved, automatic-order and unsupported ACL syntax unknown" do
    variants = [ fixture("h3c").sub("ssh server acl 2000", "ssh server acl MISSING"),
      fixture("h3c").sub("acl basic 2000", "acl basic 2000 match-order auto"),
      fixture("h3c").sub("rule 10 permit source 198.51.100.0 0.0.0.255", "rule 10 permit tcp source 198.51.100.0 0.0.0.255 destination-port range 22 23") ]
    variants.each do |text|
      config = parse("h3c", text).configuration
      expect(config.fact_known?("management.acl.restricted")).to be(false)
      expect(config.issues).to include(hash_including(code: :acl_unresolved))
    end
  end

  it "evaluates ACL destination ports against SSH and SNMP requests without including HTTP or traps" do
    h3c = fixture("h3c").gsub("2000", "3000").sub(/acl basic 3000\n.*?\n#/m, <<~CONFIG.chomp)
      acl advanced 3000
       rule 5 permit udp source 198.51.100.0 0.0.0.255 destination-port eq snmp
       rule 10 permit tcp source 192.0.2.0 0.0.0.255 destination-port eq ssh
       rule 15 permit tcp source 203.0.113.0 0.0.0.255 destination-port eq 80
       rule 20 permit udp source 203.0.113.0 0.0.0.255 destination-port eq snmptrap
      #
    CONFIG
    ios = fixture("cisco_ios").sub(/ip access-list standard MGMT\n.*?\n!/m, <<~CONFIG.chomp)
      ip access-list extended MGMT
       5 permit udp 198.51.100.0 0.0.0.255 any eq snmp
       10 permit tcp 192.0.2.0 0.0.0.255 any eq 22
       15 permit tcp 203.0.113.0 0.0.0.255 any eq 80
       20 permit udp 203.0.113.0 0.0.0.255 any eq snmptrap
      !
    CONFIG
    { "h3c" => h3c, "cisco_ios" => ios }.each do |platform, text|
      config = parse(platform, text).configuration
      expect(config.fact("management.acl.sources")).to eq([ "192.0.2.0/24" ])
      expect(config.fact("snmp.acl.sources")).to eq([ "198.51.100.0/24" ])

      unknown_port = text.sub("eq snmp", "eq unrecognized-service")
      expect(parse(platform, unknown_port).configuration.fact_known?("management.acl.sources")).to be(false)
    end
    unknown_protocol = h3c.sub(" protocol inbound ssh\n", "")
    expect(parse("h3c", unknown_protocol).configuration.fact_known?("management.acl.sources")).to be(false)
  end

  it "uses explicit SSH and Telnet listening ports instead of granting an empty-source pass" do
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "management.acl_restricted" => { "expected" => true }, "management.sources" => { "expected" => [ "192.0.2.0/24" ] }
    })
    { "ssh" => 2222, "telnet" => 2323 }.each do |service, port|
      text = <<~CONFIG
        sysname LAB
        #{service} server port #{port}
        #{'ssh server acl 3000' if service == 'ssh'}
        acl advanced 3000
         rule 5 permit tcp destination-port eq #{port}
        #
        line vty 0 4
         authentication-mode scheme
         protocol inbound #{service}
         acl 3000 inbound
        #
      CONFIG
      report = described_class.new(policy: policy).call(configuration: text, platform: "h3c", complete: true)
      expect(report.configuration.fact("management.acl.sources")).to eq([ "0.0.0.0/0" ])
      expect(report.findings.map(&:status)).to eq([ :fail, :fail ])
      expect(report).not_to be_compliant

      unknown = parse("h3c", text.sub("server port #{port}", "server port invalid")).configuration
      expect(unknown.fact_known?("management.acl.sources")).to be(false)
      expect(unknown.fact_known?("management.acl.restricted")).to be(false)
    end
  end

  it "uses the SNMP agent listening port and does not confuse trap destination ports with it" do
    { "h3c" => "snmp-agent port", "huawei" => "snmp-agent udp-port" }.each do |platform, command|
      text = <<~CONFIG
        sysname LAB
        #{command} 2161
        snmp-agent community read simple PRIVATE-COMMUNITY acl 3000
        snmp-agent target-host trap address udp-domain 192.0.2.1 udp-port 162 params securityname PRIVATE-TRAP v2c
        acl number 3000
         rule 5 permit udp destination-port eq 2161
        #
      CONFIG
      config = parse(platform, text).configuration
      expect(config.fact("snmp.acl.sources")).to eq([ "0.0.0.0/0" ])
      expect(config.fact("snmp.acl.restricted")).to be(false)
      restored = text + "undo #{command}\n"
      expect(parse(platform, restored).configuration.fact("snmp.acl.sources")).to eq([])
    end
  end

  it "keeps Cisco rotary listeners and unsupported service-port changes unknown" do
    variants = [ fixture("cisco_ios") + "ip ssh port 2222 rotary 1\n",
      fixture("cisco_ios").sub(" transport input ssh", " rotary 1\n transport input telnet"),
      fixture("cisco_ios") + "telnet server port 2323\n",
      fixture("cisco_nxos") + "ssh port invalid\n" ]
    variants.each do |text|
      config = parse(text.include?("LAB-NXOS") ? "cisco_nxos" : "cisco_ios", text).configuration
      expect(config.fact_known?("management.acl.sources")).to be(false)
      expect(config.fact_known?("management.acl.restricted")).to be(false)
      expect(config.issues).to include(hash_including(code: :unsupported_service_port))
    end
    config = parse("cisco_ios", fixture("cisco_ios") + "snmp-server listen-port 2161\n").configuration
    expect(config.fact_known?("snmp.acl.sources")).to be(false)
    expect(config.fact_known?("snmp.acl.restricted")).to be(false)
  end

  it "does not infer disabled services from omitted configuration" do
    config = parse("h3c", "sysname LAB\nreturn\n").configuration
    expect(config.fact("services").values).to all(be_nil)
    expect(config.fact_known?("ssh.enabled")).to be(false)
  end

  it "resolves H3C VTY class inheritance and lets explicit line settings take priority" do
    text = "sysname LAB\nline class vty\n authentication-mode scheme\n protocol inbound ssh\n#\nline vty 0 4\n#\nline vty 5 15\n protocol inbound telnet\n#\n"
    config = parse("h3c", text).configuration
    expect(config.fact("ssh.vty_aaa")).to be(true)
    expect(config.fact("ssh.vty_ssh_only")).to be(false)
    expect(config.fact("ssh.vty").map { |row| row[:protocols] }).to eq([ [ "ssh" ], [ "telnet" ] ])
  end

  it "checks authentication independently of omitted VTY transport defaults" do
    config = parse("h3c", fixture("h3c").sub(" protocol inbound ssh\n", "")).configuration
    expect(config.fact("ssh.vty_aaa")).to be(true)
    expect(config.fact_known?("ssh.vty_ssh_only")).to be(false)
  end

  it "does not use an SSH-only ACL to claim that Telnet is restricted" do
    text = fixture("h3c").sub("protocol inbound ssh", "protocol inbound all").sub(" acl 2000 inbound\n", "")
    config = parse("h3c", text).configuration
    expect(config.fact("management.acl.bound")).to be(false)
    expect(config.fact_known?("management.acl.restricted")).to be(false)
  end

  it "does not mistake a local login method or an accounting-only server for TACACS login" do
    text = fixture("h3c").sub("authentication login hwtacacs-scheme OPS local", "authentication login local\n authentication default hwtacacs-scheme OPS")
    expect(parse("h3c", text).configuration.fact("tacacs.login")).to be(false)
    text = fixture("h3c").gsub(/^ (?:primary|secondary) authentication.*\n/, "")
    expect(parse("h3c", text).configuration.fact_known?("tacacs.login")).to be(false)
    text = fixture("cisco_ios").sub("login default group OPS local", "login default local group OPS")
    expect(parse("cisco_ios", text).configuration.fact("tacacs.login")).to be(false)
  end

  it "handles split NX-OS SNMP user ACL references and malformed syntax without inventing passes" do
    text = fixture("cisco_nxos").sub("PRIVATE-NXOS-PRIV use-ipv4acl MGMT", "PRIVATE-NXOS-PRIV\nsnmp-server user observer use-ipv4acl MGMT")
    config = parse("cisco_nxos", text).configuration
    expect(config.fact("snmp.v3_auth_priv")).to be(true)
    expect(config.fact("snmp.acl.bound")).to be(true)
    config = parse("cisco_nxos", text + "snmp-server user\nsnmp-server community\n").configuration
    expect(config.fact_known?("snmp.v3_auth_priv")).to be(false)
    expect(config.fact_known?("snmp.write_enabled")).to be(false)
  end

  it "requires complete SNMP authentication and privacy parameters before reporting authPriv" do
    variants = {
      "h3c" => [
        [ "authentication-mode sha cipher PRIVATE-SNMP-AUTH", "authentication-mode sha cipher" ],
        [ "authentication-mode sha cipher PRIVATE-SNMP-AUTH", "authentication-mode cipher PRIVATE-SNMP-AUTH" ],
        [ "privacy-mode aes128 cipher PRIVATE-SNMP-PRIV", "privacy-mode aes128 cipher" ],
        [ "privacy-mode aes128 cipher PRIVATE-SNMP-PRIV", "privacy-mode cipher PRIVATE-SNMP-PRIV" ]
      ],
      "cisco_ios" => [
        [ "auth sha PRIVATE-IOS-AUTH", "auth sha" ],
        [ "auth sha PRIVATE-IOS-AUTH", "auth PRIVATE-IOS-AUTH" ],
        [ "priv aes 128 PRIVATE-IOS-PRIV", "priv aes" ],
        [ "priv aes 128 PRIVATE-IOS-PRIV", "priv aes 128" ],
        [ "priv aes 128 PRIVATE-IOS-PRIV", "priv PRIVATE-IOS-PRIV" ]
      ],
      "cisco_nxos" => [
        [ "auth sha PRIVATE-NXOS-AUTH", "auth sha" ],
        [ "priv aes-128 PRIVATE-NXOS-PRIV", "priv aes" ],
        [ "priv aes-128 PRIVATE-NXOS-PRIV", "priv" ]
      ]
    }
    variants.each do |platform, replacements|
      replacements.each do |before, after|
        report = parse(platform, fixture(platform).sub(before, after))
        expect(report.configuration.fact_known?("snmp.v3_auth_priv")).to be(false)
        expect(report.findings.find { |finding| finding.id == "snmp.auth_priv" }.status).to eq(:unknown)
        expect(report.configuration.issues).to include(hash_including(code: :invalid_snmp_security))
        expect(report.to_h.to_json).not_to include("PRIVATE-")
      end
    end
  end

  it "supports the NX-OS saved privacy-secret form with localized keys" do
    text = fixture("cisco_nxos").sub("priv aes-128 PRIVATE-NXOS-PRIV", "priv PRIVATE-NXOS-PRIV localizedV2key")
    config = parse("cisco_nxos", text).configuration
    expect(config.fact_known?("snmp.v3_auth_priv")).to be(true)
    expect(config.fact("snmp.v3_auth_priv")).to be(true)
  end

  it "includes line passwords in weak credential checks and never serializes them" do
    report = parse("cisco_ios", fixture("cisco_ios") + "line con 0\n password 0 admin\n!")
    expect(report.findings.find { |finding| finding.id == "credentials.strength" }.reason).to eq(:weak_password)
    expect(report.configuration.fact("credentials.records")).to include(hash_including(kind: "line", storage: "plaintext", common: true))
    expect(report.to_h.to_json).not_to include("PRIVATE-", "password 0 admin")
  end

  it "resolves SNMPv3 group ACLs instead of treating them as missing user ACLs" do
    text = fixture("cisco_ios").sub("PRIVATE-IOS-PRIV access MGMT", "PRIVATE-IOS-PRIV") + "snmp-server group READONLY v3 priv access MGMT\n"
    expect(parse("cisco_ios", text).configuration.fact("snmp.acl.bound")).to be(true)
    text = text.sub("snmp-server group READONLY v3 priv access MGMT\n", "")
    expect(parse("cisco_ios", text).configuration.fact_known?("snmp.acl.bound")).to be(false)
    text = fixture("h3c").sub("PRIVATE-SNMP-PRIV acl 2000", "PRIVATE-SNMP-PRIV") + "snmp-agent group v3 readgroup privacy acl 2000\n"
    expect(parse("h3c", text).configuration.fact("snmp.acl.bound")).to be(true)
  end

  it "keeps truncated, invalid and unsupported input from producing passes" do
    partial = [ parse("h3c", fixture("h3c") + "-- More --\n"), parse("h3c", fixture("h3c") + "banner motd ^C\nunclosed\n"),
      audit.call(configuration: fixture("h3c"), platform: "h3c") ]
    partial.each do |result|
      expect(result.findings.select { |finding| finding.status == :fail }.map(&:id)).to eq(%w[credentials.storage credentials.strength])
      expect(result.findings.map(&:status)).not_to include(:pass)
      expect(result).not_to be_compliant
    end
    [ "\xff".b, "" ].each do |text|
      result = parse("h3c", text)
      expect(result.findings.map(&:status).uniq).to eq([ :unknown ])
      expect(result).not_to be_compliant
    end
    unsupported = audit.call(configuration: fixture("h3c"), platform: "unregistered", complete: true)
    expect(unsupported.configuration.status).to eq(:unsupported)
    expect(unsupported.findings.map(&:reason).uniq).to eq([ :unsupported_platform ])
  end

  it "supports platform aliases without guessing a parser for another vendor" do
    expect(audit.call(configuration: fixture("cisco_ios"), platform: "IOS-XE", complete: true).configuration.platform).to eq("cisco_ios")
    expect(audit.call(configuration: fixture("h3c"), platform: "h3c_wireless", complete: true).configuration.platform).to eq("h3c")
    { "hillstone" => %w[stoneos StoneOS stone_os Stone-OS], "palo_alto" => %w[paloalto PAN-OS pan_os panos] }.each do |platform, aliases|
      aliases.each do |name|
        configuration = audit.call(configuration: fixture(platform), platform: name, complete: true).configuration
        expect(configuration.platform).to eq(platform)
        expect(configuration).to be_complete
      end
    end
  end
end

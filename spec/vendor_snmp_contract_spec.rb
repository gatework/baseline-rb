# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Vendor-independent SNMPv3 assessment" do
  inputs = {
    "h3c" => [ "sysname LAB\nsnmp-agent group v3 MONITOR privacy read-view ALL\nsnmp-agent usm-user v3 USER MONITOR authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n", " privacy-mode aes128 cipher SYNTHETIC-PRIV" ],
    "huawei" => [ "sysname LAB\nsnmp-agent group v3 MONITOR privacy read-view ALL\nsnmp-agent usm-user v3 USER group MONITOR authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n", " privacy-mode aes128 cipher SYNTHETIC-PRIV" ],
    "cisco_ios" => [ "hostname LAB\nsnmp-server group MONITOR v3 priv read ALL\nsnmp-server user USER MONITOR v3 encrypted auth sha SYNTHETIC-AUTH priv aes 128 SYNTHETIC-PRIV\n", " priv aes 128 SYNTHETIC-PRIV" ],
    "cisco_nxos" => [ "hostname LAB\nsnmp-server user USER network-operator auth sha SYNTHETIC-AUTH priv aes-128 SYNTHETIC-PRIV\n", " priv aes-128 SYNTHETIC-PRIV" ],
    "hillstone" => [ "hostname LAB\nsnmp-server group MONITOR v3 auth-enc read-view ALL\nsnmp-server user USER group MONITOR v3 remote 192.0.2.10 auth-protocol sha SYNTHETIC-AUTH enc-protocol aes SYNTHETIC-PRIV\nsnmp-server host 192.0.2.10 version 3\n", " enc-protocol aes SYNTHETIC-PRIV" ],
    "palo_alto" => [ "set deviceconfig system hostname LAB\nset deviceconfig system snmp-setting access-setting version v3 users USER authpwd -AQ==SYNTHETIC-AUTH\nset deviceconfig system snmp-setting access-setting version v3 users USER privpwd -AQ==SYNTHETIC-PRIV\n", "set deviceconfig system snmp-setting access-setting version v3 users USER privpwd -AQ==SYNTHETIC-PRIV\n" ]
  }

  inputs.each do |platform, (source, privacy)|
    it "uses the same permission, security and incomplete-evidence contract on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => {
        "snmp.write_enabled" => { "expected" => false }, "snmp.auth_priv" => { "expected" => true }
      })
      audit = Baseline::Audit.new(policy: policy)
      report = audit.call(configuration: source, platform: platform, complete: true)
      expect(report.findings.map(&:status)).to eq([ :pass, :pass ])
      expect(report).to be_compliant
      expect(report.findings.last.lines).not_to be_empty
      expect(report.configuration.fact("credentials.records").select { |entry| entry[:kind] == "snmp_user" }.map { |entry| entry[:purpose] }).to eq(%w[authentication privacy])
      expect(report.to_h.to_json + report.to_text).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
      weak = audit.call(configuration: source.sub(privacy, ""), platform: platform, complete: true)
      expect(weak.findings.map(&:status)).to eq([ :pass, :fail ])
      partial = audit.call(configuration: source, platform: platform, complete: false)
      expect(partial.findings.map(&:status)).to eq([ :unknown, :unknown ])
    end
  end
end

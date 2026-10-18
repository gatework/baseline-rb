# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Comware command family boundaries" do
  def audit_commands(commands, platform: "h3c", checks:)
    policy = Baseline::Policy.new("version" => 1, "checks" => checks.transform_values { |value| { "expected" => value } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{commands}\nreturn\n", platform: platform, complete: true)
  end

  [ "ssh server acl-deny-log enable", "undo ssh server acl-deny-log enable" ].each do |logging|
    it "preserves an explicit SSH ACL binding with #{logging}" do
      report = audit_commands("ssh server acl 2000\n#{logging}\nline vty 0 4\n protocol inbound ssh",
        checks: { "management.acl_bound" => true })
      expect(report.findings.first.status).to eq(:pass)
    end

    it "does not conceal a missing SSH ACL binding with #{logging}" do
      report = audit_commands(logging, checks: { "management.acl_bound" => true })
      expect(report.findings.first.status).to eq(:fail)
    end
  end

  it "does not count Huawei source port settings as log destinations" do
    [ "info-center loghost source-port 10514", "undo info-center loghost source-port" ].each do |command|
      report = audit_commands("info-center loghost 192.0.2.20\n#{command}", platform: "huawei",
        checks: { "syslog.minimum_servers" => 2 })
      expect(report.configuration.fact("syslog.servers")).to eq([ "192.0.2.20" ])
      expect(report.findings.first.status).to eq(:fail)
    end
  end

  it "preserves the source interface when Huawei configures a source port" do
    report = audit_commands("info-center loghost source LoopBack0\ninfo-center loghost source-port 10514", platform: "huawei",
      checks: { "syslog.source" => "LoopBack0" })
    expect(report.findings.first.status).to eq(:pass)
  end

  it "extracts and cancels Huawei domain destinations in their VPN" do
    report = audit_commands("info-center loghost domain logs.example.test vpn-instance A\n" \
      "info-center loghost domain logs.example.test vpn-instance B\n" \
      "undo info-center loghost domain logs.example.test vpn-instance A", platform: "huawei",
      checks: { "syslog.servers" => [ "logs.example.test" ] })
    expect(report.configuration.fact("syslog.servers")).to eq([ "logs.example.test" ])
    expect(report.findings.first.status).to eq(:pass)
  end

  it "keeps a malformed Huawei domain destination unknown" do
    report = audit_commands("info-center loghost domain", platform: "huawei", checks: { "syslog.minimum_servers" => 1 })
    expect(report.configuration.fact("syslog.servers")).not_to include("domain")
    expect(report.findings.first.status).to eq(:unknown)
  end

  %w[h3c huawei].each do |platform|
    it "normalizes separated source interface type and number on #{platform}" do
      report = audit_commands("info-center loghost source LoopBack 0\nntp-service source-interface LoopBack 0", platform: platform,
        checks: { "syslog.source" => "LoopBack0", "ntp.source" => "LoopBack0" })
      expect(report.findings.map(&:status)).to eq([ :pass, :pass ])
    end

    it "keeps malformed source interface declarations unknown on #{platform}" do
      report = audit_commands("info-center loghost source LoopBack 0 extra\nntp-service source-interface LoopBack 0 extra", platform: platform,
        checks: { "syslog.source" => "LoopBack0", "ntp.source" => "LoopBack0" })
      expect(report.findings.map(&:status)).to eq([ :unknown, :unknown ])
    end

    it "recognizes resets with separated interface type and number on #{platform}" do
      report = audit_commands("info-center loghost source LoopBack0\nundo info-center loghost source LoopBack 0\n" \
        "ntp-service source-interface LoopBack0\nundo ntp-service source-interface LoopBack 0", platform: platform,
        checks: { "syslog.source" => "LoopBack0", "ntp.source" => "LoopBack0" })
      expect(report.findings.map(&:status)).to eq([ :unknown, :unknown ])
      expect(report.configuration.issues).not_to include(hash_including(code: :unsupported_syntax, fact: "syslog.source"))
      expect(report.configuration.issues).not_to include(hash_including(code: :unsupported_syntax, fact: "ntp.source"))
    end
  end
end

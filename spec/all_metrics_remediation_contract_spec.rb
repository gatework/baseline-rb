# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Full metric planning boundary" do
  # 独立列出全部批准值；不能从解析结果反推批准，也不能新增指标却遗漏原生入口验收。
  approvals = {
    "snmp.enabled" => true, "snmp.versions" => [ "v3" ], "snmp.write_enabled" => false, "snmp.auth_priv" => true,
    "snmp.acl_bound" => true, "snmp.acl_restricted" => true, "snmp.sources" => [ "192.0.2.0/24" ],
    "ntp.minimum_servers" => 2, "ntp.servers" => %w[192.0.2.10 192.0.2.11], "ntp.authentication" => true, "ntp.source" => "LoopBack0",
    "syslog.minimum_servers" => 2, "syslog.servers" => %w[192.0.2.20 192.0.2.21], "syslog.source" => "LoopBack0",
    "ssh.enabled" => true, "ssh.versions" => [ "2" ], "ssh.vty_ssh_only" => true, "ssh.vty_aaa" => true,
    "management.acl_bound" => true, "management.acl_restricted" => true, "management.sources" => [ "192.0.2.0/24" ],
    "services.disabled" => %w[telnet http], "credentials.storage" => true, "credentials.strength" => { "min_length" => 12, "min_classes" => 3 },
    "tacacs.minimum_servers" => 2, "tacacs.servers" => %w[192.0.2.30 192.0.2.31], "tacacs.login" => true,
    "tacacs.authorization" => true, "tacacs.accounting" => true, "tacacs.keys" => true,
    "syslog.destinations" => [], "ntp.associations" => [], "tacacs.endpoints" => []
  }

  def policy(values, enabled: true)
    Baseline::Policy.new("version" => 1, "checks" => values.transform_values { |expected| { "expected" => expected, "enabled" => enabled } })
  end

  def fixture(platform) = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))

  it "requires an explicit acceptance case for every public metric and the unchanged thirty default metrics" do
    expect(approvals.keys).to match_array(Baseline::Rule::DEFINITIONS.keys)
    expect(Baseline::Policy.default.rules.map(&:id)).to match_array(approvals.keys - %w[syslog.destinations ntp.associations tacacs.endpoints])
  end

  Baseline::Audit::PARSERS.each_key do |platform|
    it "retains all 33 #{platform} outcomes and emits no commands from partial input" do
      result = Baseline::Remediation.new(policy: policy(approvals)).call(configuration: fixture(platform), platform: platform, complete: false)
      expect(result.checks.map(&:id)).to eq(approvals.keys)
      expect(result.checks.map(&:status)).to all(eq(:blocked))
      expect(result.audit.findings.map(&:status)).not_to include(:pass)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
      expect(result.review[:persistence][:commands]).to be_empty
    end

    it "does not turn any #{platform} observed value into a missing organizational approval" do
      result = Baseline::Remediation.new(policy: policy(approvals.transform_values { nil })).call(configuration: fixture(platform), platform: platform, complete: true)
      expect(result.checks.map(&:id)).to eq(approvals.keys)
      expect(result.checks.map(&:status)).to all(eq(:blocked))
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end

    it "does not generate or silently enable any disabled #{platform} metric" do
      result = Baseline::Remediation.new(policy: policy(approvals, enabled: false)).call(configuration: fixture(platform), platform: platform, complete: true)
      expect(result.checks).to be_empty
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
      expect(result.review[:rollback][:status]).to eq(:not_applicable)
    end
  end

  %w[centec radware].each do |platform|
    it "keeps all metrics unsupported on #{platform} even when the input looks like a supported CLI" do
      result = Baseline::Remediation.new(policy: policy(approvals)).call(configuration: fixture("h3c"), platform: platform, complete: true)
      expect(result.checks.size).to eq(33)
      expect(result.checks.map(&:status)).to all(eq(:blocked))
      expect(result.audit.configuration.status).to eq(:unsupported)
      expect(result.configuration_commands).to be_empty
      expect(Baseline::Remediation.capabilities(platform: platform).values.map { |value| value[:status] }).to all(eq(:unsupported))
    end
  end

  it "keeps aliases on the identical parsing, planning and review path for every metric" do
    service = Baseline::Remediation.new(policy: policy(approvals.transform_values { nil }))
    Baseline::Audit::ALIASES.each do |name, canonical|
      source = fixture(canonical)
      expect(service.call(configuration: source, platform: name, complete: true).to_h).to eq(service.call(configuration: source, platform: canonical, complete: true).to_h)
    end
  end
end

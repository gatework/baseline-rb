# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Every baseline metric" do
  # 预期、通过值及偏离值独立声明；新增指标必须补齐业务样例。
  metrics = {
    "snmp.enabled" => [ "snmp.enabled", true, true, false ],
    "snmp.versions" => [ "snmp.versions", [ "v3" ], [ "v3" ], %w[v2c v3] ],
    "snmp.write_enabled" => [ "snmp.write_enabled", false, false, true ],
    "snmp.auth_priv" => [ "snmp.v3_auth_priv", true, true, false ],
    "snmp.acl_bound" => [ "snmp.acl.bound", true, true, false ],
    "snmp.acl_restricted" => [ "snmp.acl.restricted", true, true, false ],
    "snmp.sources" => [ "snmp.acl.sources", [ "198.51.100.0/24" ], [ "198.51.100.0/25" ], [ "203.0.113.0/24" ] ],
    "ntp.minimum_servers" => [ "ntp.servers", 2, %w[192.0.2.10 192.0.2.11], [ "192.0.2.10" ] ],
    "ntp.servers" => [ "ntp.servers", %w[192.0.2.10 192.0.2.11], %w[192.0.2.11 192.0.2.10], %w[192.0.2.10 192.0.2.12] ],
    "ntp.authentication" => [ "ntp.authentication", true, true, false ],
    "ntp.source" => [ "ntp.source", "LoopBack0", "LoopBack0", "LoopBack1" ],
    "syslog.minimum_servers" => [ "syslog.servers", 2, %w[192.0.2.20 192.0.2.21], [ "192.0.2.20" ] ],
    "syslog.servers" => [ "syslog.servers", %w[192.0.2.20 192.0.2.21], %w[192.0.2.21 192.0.2.20], %w[192.0.2.20 192.0.2.22] ],
    "syslog.source" => [ "syslog.source", "LoopBack0", "LoopBack0", "LoopBack1" ],
    "ssh.enabled" => [ "ssh.enabled", true, true, false ],
    "ssh.versions" => [ "ssh.versions", [ "2" ], [ "2" ], %w[1 2] ],
    "ssh.vty_ssh_only" => [ "ssh.vty_ssh_only", true, true, false ],
    "ssh.vty_aaa" => [ "ssh.vty_aaa", true, true, false ],
    "management.acl_bound" => [ "management.acl.bound", true, true, false ],
    "management.acl_restricted" => [ "management.acl.restricted", true, true, false ],
    "management.sources" => [ "management.acl.sources", [ "198.51.100.0/24" ], [ "198.51.100.0/25" ], [ "203.0.113.0/24" ] ],
    "services.disabled" => [ "services", %w[telnet http], { "telnet" => false, "http" => false }, { "telnet" => true, "http" => false } ],
    "credentials.storage" => [ "credentials.storage_safe", true, true, false ],
    "credentials.strength" => [ "credentials.records", { "min_length" => 12, "min_classes" => 3 },
      [ { storage: "plaintext", length: 12, character_classes: 3, common: false } ],
      [ { storage: "plaintext", length: 11, character_classes: 3, common: false } ] ],
    "tacacs.minimum_servers" => [ "tacacs.servers", 2, %w[192.0.2.30 192.0.2.31], [ "192.0.2.30" ] ],
    "tacacs.servers" => [ "tacacs.servers", %w[192.0.2.30 192.0.2.31], %w[192.0.2.31 192.0.2.30], %w[192.0.2.30 192.0.2.32] ],
    "tacacs.login" => [ "tacacs.login", true, true, false ],
    "tacacs.authorization" => [ "tacacs.authorization", true, true, false ],
    "tacacs.accounting" => [ "tacacs.accounting", true, true, false ],
    "tacacs.keys" => [ "tacacs.keys_present", true, true, false ]
  }

  def metric_report(id, expected:, facts:, complete: true, issues: [], **options)
    policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => expected, **options } })
    result = CtxParser::Result.new(status: complete ? :complete : :partial, records: [ { "facts" => facts } ], issues: issues)
    evidence = Baseline::Evidence.new(platform: "h3c", sha256: "synthetic", result: result, input_complete: complete)
    Baseline::Evaluator.new(policy: policy).call(configuration: evidence)
  end

  it "lists every metric explicitly so a new definition cannot silently miss acceptance coverage" do
    expect(metrics.keys).to match_array(Baseline::Rule::DEFINITIONS.keys)
    expect(Baseline::Policy.default.rules.map(&:id)).to match_array(metrics.keys)
  end

  metrics.each do |id, (fact, expected, passing, failing)|
    it "passes #{id} with complete sufficient evidence" do
      report = metric_report(id, expected: expected, facts: { fact => passing })
      expect(report.findings.first.status).to eq(:pass)
      expect(report).to be_compliant
    end

    it "fails #{id} when the observed configuration deviates" do
      report = metric_report(id, expected: expected, facts: { fact => failing })
      expect(report.findings.first.status).to eq(:fail)
      expect(report).not_to be_compliant
      expect(report.findings.first.actual).to eq(failing)
    end

    it "keeps #{id} unknown when evidence is missing" do
      report = metric_report(id, expected: expected, facts: {})
      expect(report.findings.first).to have_attributes(status: :unknown, reason: :fact_unavailable)
      expect(report).not_to be_compliant
    end

    it "does not use #{id} current values as approval when the policy value is missing" do
      report = metric_report(id, expected: nil, facts: { fact => passing })
      expect(report.findings.first).to have_attributes(status: :unknown, reason: :policy_missing)
    end

    it "excludes #{id} only for an explicit scope mismatch" do
      report = metric_report(id, expected: expected, facts: { fact => failing }, "applies_to" => { "vendor" => "cisco_ios" })
      expect(report.findings.first).to have_attributes(status: :not_applicable, reason: :scope_mismatch)
      expect(report).not_to be_compliant
    end

    it "never passes #{id} from an incomplete snapshot" do
      report = metric_report(id, expected: expected, facts: { fact => passing }, complete: false)
      expect(report.findings.first).to have_attributes(status: :unknown, reason: :input_incomplete)
    end

    it "withholds #{id} after a scoped parsing diagnostic despite a retained value" do
      report = metric_report(id, expected: expected, facts: { fact => passing }, issues: [ { code: :unsupported_syntax, fact: fact } ])
      expect(report.findings.first).to have_attributes(status: :unknown, reason: :fact_unavailable)
    end
  end

  %w[ntp syslog tacacs].each do |service|
    it "does not satisfy #{service} redundancy by counting the same server twice" do
      report = metric_report("#{service}.minimum_servers", expected: 2,
        facts: { "#{service}.servers" => %w[192.0.2.10 192.0.2.10] })
      expect(report.findings.first.status).to eq(:fail)
      expect(report.findings.first.details).to eq(minimum: 2, actual_count: 1)
    end

    it "compares #{service} approved servers as a set despite duplicate observations" do
      report = metric_report("#{service}.servers", expected: [ "192.0.2.10" ],
        facts: { "#{service}.servers" => %w[192.0.2.10 192.0.2.10] })
      expect(report.findings.first.status).to eq(:pass)
    end
  end

  it "does not exclude SNMP security checks because a boolean scope fact has the wrong type" do
    [ "true", "false", 0, 1, nil, [] ].each do |value|
      report = metric_report("snmp.auth_priv", expected: true,
        facts: { "snmp.enabled" => value, "snmp.v3_auth_priv" => false },
        "applies_to" => { "facts" => { "snmp.enabled" => true } })
      expect(report.findings.first).to have_attributes(status: :unknown, reason: :scope_unknown)
    end
  end

  it "does not exclude a hostname-scoped metric because the hostname is malformed" do
    report = metric_report("ssh.enabled", expected: true, facts: { "hostname" => false, "ssh.enabled" => false },
      "applies_to" => { "facts" => { "hostname" => "LAB" } })
    expect(report.findings.first).to have_attributes(status: :unknown, reason: :scope_unknown)
  end
end

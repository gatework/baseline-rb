# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Report do
  def assess(checks, text: "sysname LAB\nssh server enable\n", context: {})
    policy = Baseline::Policy.new("version" => 1, "checks" => checks)
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: "h3c", complete: true, context: context)
  end

  it "explains the selected policy branch and the missing and unexpected servers" do
    report = assess({ "ntp.servers" => { "expected" => { "by_site" => { "HQ" => [ "192.0.2.1" ] } } } },
      text: "sysname LAB\nntp-service unicast-server 192.0.2.2\n", context: { site: "HQ" })
    finding = report.findings.first
    expect(finding.policy_path).to eq(%w[by_site HQ])
    expect(finding.details).to eq(missing: [ "192.0.2.1" ], unexpected: [ "192.0.2.2" ])
    expect(finding.lines).to eq([ 2 ])
    expect(report.to_text).to include("ntp.servers", finding.title, "192.0.2.1", "192.0.2.2", "by_site", "HQ", "行号: 2")
    expect(report.to_h[:findings].first[:explanation]).not_to be_empty
  end

  it "attaches parser diagnostics to the fact they prevent checking" do
    text = "sysname LAB\nuser-interface vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n acl 2000 inbound\nacl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.255 time-range WORK\n"
    report = assess({ "management.sources" => { "expected" => [ "192.0.2.0/24" ] } }, text: text)
    finding = report.findings.first
    expect(finding.status).to eq(:unknown)
    expect(finding.diagnostics).not_to be_empty
    expect(report.to_text).to include("fact_unavailable", finding.diagnostics.first[:code].to_s)
  end

  it "builds the compact summary without serializing configuration facts or full findings" do
    original = assess({ "ssh.enabled" => { "expected" => true } })
    configuration = instance_double(Baseline::Configuration, complete?: true, platform: "h3c", sha256: "a" * 64, status: :complete, issues: [])
    finding = instance_double(Baseline::Report::Finding, status: :pass, summary: original.findings.first.summary)
    report = described_class.new(configuration: configuration, policy_sha256: original.policy_sha256, findings: [ finding ], context: {})
    expect(configuration).not_to receive(:to_h)
    expect(finding).not_to receive(:to_h)
    expect(report.summary).to include(status: :pass, compliant: true, coverage: 100.0)
    expect(report.summary[:findings].first.keys).not_to include(:actual, :expected, :lines, :details, :diagnostics)
  end

  it "keeps cached statistics and policy diagnostics immutable without freezing the caller array" do
    original = assess({ "ssh.enabled" => { "expected" => true } })
    input = original.findings.dup
    report = described_class.new(configuration: original.configuration, policy_sha256: original.policy_sha256,
      findings: input, context: original.context)
    input.clear
    expect(report.counts).to eq(pass: 1)
    expect(report).to be_compliant
    expect { report.counts[:pass] = 9 }.to raise_error(FrozenError)
    expect { report.findings.first.policy_path << "changed" }.to raise_error(FrozenError)
  end

  it "never includes credential tokens in text or structured output" do
    report = assess({ "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } },
      text: "sysname LAB\nlocal-user admin class manage\n password hash PRIVATE-SYNTHETIC-TOKEN\n")
    expect(report.to_text).to include("password_strength_unobservable")
    expect(report.to_text + JSON.generate(report.to_h) + JSON.generate(report.summary)).not_to include("PRIVATE-SYNTHETIC-TOKEN")
  end

  it "does not treat an unrecognized finding state as evidence of compliance" do
    original = assess({ "ssh.enabled" => { "expected" => true } })
    report = described_class.new(configuration: original.configuration, policy_sha256: original.policy_sha256,
      findings: [ original.findings.first.with(status: :error) ], context: {})
    expect(report).not_to be_compliant
    expect(report).not_to be_complete
    expect(report.status).to eq(:unknown)
  end

  it "escapes terminal controls even for an unsupported caller-supplied platform" do
    report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: "sysname LAB\n", platform: "unknown\e[2Jinjected\nline", complete: true)
    expect(report.to_text).not_to include("\e", "injected\nline")
    expect(report.to_text).to include("unsupported_platform")
  end

  it "accepts existing finding keywords and snapshots caller-owned evidence" do
    actual = [ "192.0.2.1" ]
    finding = described_class::Finding.new(id: "ntp.servers", title: "NTP", severity: "medium", status: :pass,
      reason: nil, actual: actual, expected: [ "192.0.2.1" ], lines: [ 1 ])
    actual.clear
    expect(finding.actual).to eq([ "192.0.2.1" ])
    expect(finding.policy_path).to eq([])
    expect { finding.actual << "192.0.2.2" }.to raise_error(FrozenError)
  end
end

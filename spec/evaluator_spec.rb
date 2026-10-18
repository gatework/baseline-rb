# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Evaluator do
  def evaluate(checks, text: "sysname LAB\nssh server enable\n", complete: true, context: {})
    policy = Baseline::Policy.new("version" => 1, "checks" => checks)
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: "h3c", complete: complete, context: context)
  end

  it "keeps pass, fail, unknown and not-applicable separate in coverage and score" do
    report = evaluate({ "ssh.enabled" => { "expected" => true },
      "ntp.minimum_servers" => { "expected" => 2 },
      "ntp.servers" => { "expected" => nil },
      "snmp.auth_priv" => { "expected" => true, "applies_to" => { "facts" => { "snmp.enabled" => true } } } })
    expect(report.counts).to eq(pass: 1, fail: 1, unknown: 1, not_applicable: 1)
    expect(report.status).to eq(:fail)
    expect(report.score).to eq(33.3)
    expect(report.coverage).to eq(66.7)
    expect(report).not_to be_complete
    expect(report).not_to be_compliant
  end

  it "does not grant compliance for disabled or entirely out-of-scope checks" do
    report = evaluate({ "ssh.enabled" => { "enabled" => false },
      "ntp.servers" => { "applies_to" => { "vendor" => "cisco_ios" } } })
    expect(report.findings.map(&:status)).to eq([ :not_applicable ])
    expect(report.status).to eq(:unknown)
    expect(report.score).to eq(0)
    expect(report).not_to be_compliant
  end

  it "never marks incomplete input compliant even when visible facts match" do
    report = evaluate({ "ssh.enabled" => { "expected" => true } }, complete: false)
    expect(report.findings.first.reason).to eq(:input_incomplete)
    expect(report.coverage).to eq(0)
    expect(report).not_to be_compliant
  end

  it "can produce a complete passing report for checks with sufficient evidence" do
    report = evaluate({ "ssh.enabled" => { "expected" => true } })
    expect(report).to be_compliant
    expect(report).to be_complete
    expect(report.score).to eq(100)
  end

  it "distinguishes missing scope and policy values from facts" do
    report = evaluate({ "ssh.enabled" => { "expected" => true, "applies_to" => { "site" => "HQ" } },
      "ntp.servers" => { "expected" => nil }, "ntp.source" => { "expected" => "Loopback0" } })
    expect(report.findings.map(&:reason)).to eq(%i[scope_unknown policy_missing fact_unavailable])
  end

  it "does not count unknown service defaults as disabled and reports a known enabled service" do
    checks = { "services.disabled" => { "expected" => %w[http telnet] } }
    expect(evaluate(checks).findings.first.reason).to eq(:service_state_unknown)
    expect(evaluate(checks, text: "sysname LAB\nip http enable\n").findings.first.status).to eq(:fail)
    expect(evaluate(checks, text: "sysname LAB\nundo ip http enable\nundo telnet server enable\n")).to be_compliant
  end

  it "compares address coverage rather than literal CIDR strings" do
    checks = { "management.sources" => { "expected" => [ "198.51.100.0/24" ] } }
    text = File.read(File.expand_path("fixtures/baseline/h3c.cfg", __dir__))
    expect(evaluate(checks, text: text)).to be_compliant
    checks["management.sources"]["expected"] = [ "198.51.100.128/25" ]
    expect(evaluate(checks, text: text).findings.first.status).to eq(:fail)
  end

  it "retains ordered network deviations and keeps unsupported address evidence unknown" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "management.sources" => { "expected" => [ "192.0.2.0/24" ] } })
    evaluate_sources = lambda do |sources|
      result = CtxParser::Result.new(status: :complete, records: [ { "facts" => { "management.acl.sources" => sources } } ])
      configuration = Baseline::Evidence.new(platform: "h3c", sha256: "synthetic", result: result)
      described_class.new(policy: policy).call(configuration: configuration).findings.first
    end
    finding = evaluate_sources.call(%w[203.0.113.0/24 192.0.2.0/25 198.51.100.0/24 203.0.113.0/24])
    expect(finding.status).to eq(:fail)
    expect(finding.details).to eq(outside_approved: %w[203.0.113.0/24 198.51.100.0/24 203.0.113.0/24])
    expect(evaluate_sources.call([]).status).to eq(:pass)
    finding = evaluate_sources.call([ "2001:db8::/32" ])
    expect([ finding.status, finding.reason, finding.details ]).to eq([ :unknown, :unsupported_address_family, {} ])
  end

  it "fails known weak plaintext but keeps opaque password strength unknown" do
    checks = { "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } }
    prefix = "sysname LAB\nlocal-user admin class manage\n"
    opaque = evaluate(checks, text: prefix + " password hash PRIVATE-OPAQUE-SECRET\n")
    expect(opaque.findings.first.reason).to eq(:password_strength_unobservable)
    weak = evaluate(checks, text: prefix + " password simple admin\n password hash PRIVATE-OPAQUE-SECRET\n")
    expect(weak.findings.first.reason).to eq(:weak_password)
    strong = evaluate(checks, text: prefix + " password simple Synthetic-Strong-123!\n")
    expect(strong).to be_compliant
    [ opaque, weak, strong ].each { |report| expect(report.to_h.to_json).not_to include("PRIVATE-OPAQUE-SECRET", "Synthetic-Strong-123!") }
  end

  it "rejects invented context and prevents overriding the parser platform" do
    expect { evaluate({ "ssh.enabled" => {} }, context: { "unexpected" => "value" }) }.to raise_error(ArgumentError)
    report = evaluate({ "ssh.enabled" => { "expected" => true, "applies_to" => { "vendor" => "h3c" } } }, context: { vendor: "cisco_ios" })
    expect(report).to be_compliant
    expect(report.context["vendor"]).to eq("h3c")
  end

  it "keeps malformed credential attributes unknown without hiding another confirmed weak password" do
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } }
    })
    evaluate_records = lambda do |records|
      result = CtxParser::Result.new(status: :complete, records: [ { "facts" => { "credentials.records" => records } } ])
      configuration = Baseline::Evidence.new(platform: "h3c", sha256: "synthetic", result: result)
      described_class.new(policy: policy).call(configuration: configuration).findings.first
    end
    strong = { storage: "plaintext", common: false, length: 20, character_classes: 4 }
    malformed = [ {}, "unexpected", { storage: "invented" }, { storage: "plaintext" },
      strong.merge(length: "20"), strong.merge(length: -1), strong.merge(character_classes: 5), strong.merge(common: nil) ]
    malformed.each do |record|
      finding = evaluate_records.call([ strong, record ])
      expect([ finding.status, finding.reason ]).to eq([ :unknown, :fact_type_mismatch ])
      finding = evaluate_records.call([ record, strong.merge(length: 3) ])
      expect([ finding.status, finding.reason ]).to eq([ :fail, :weak_password ])
    end
  end
end

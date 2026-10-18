# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Baseline remediation plans" do
  def plan(checks, text: "sysname LAB\n", platform: "h3c", complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => checks.transform_values { |expected| { "expected" => expected } })
    Baseline::Remediation.new(policy: policy).call(configuration: text, platform: platform, complete: complete)
  end

  it "retains the exact audit and policy identities without changing the input" do
    text = +"sysname LAB\ninfo-center loghost source LoopBack1\n"
    result = plan({ "syslog.source" => "LoopBack0" }, text: text)
    expect(result.audit.configuration.sha256).to eq(Digest::SHA256.hexdigest(text))
    expect(text).not_to be_frozen
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(1)
    expect(result.configuration_commands).to eq([ "system-view", "info-center loghost source LoopBack0", "return" ])
    expect(result).to be_requires_review
    expect(result.checks.first.status).to eq(:planned)
  end

  it "returns noop when the requested source already matches" do
    result = plan({ "syslog.source" => "LoopBack0" }, text: "sysname LAB\ninfo-center loghost source LoopBack0\n")
    expect(result.status).to eq(:noop)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
    expect(result).not_to be_requires_review
  end

  it "keeps unresolved checks visible when an independent change can be generated" do
    result = plan({ "syslog.source" => "LoopBack0", "ntp.servers" => nil }, text: "sysname LAB\ninfo-center loghost source LoopBack1\n")
    expect(result.status).to eq(:partial)
    expect(result.checks.map(&:status)).to eq([ :planned, :blocked ])
    expect(result.checks.last.reason).to eq(:policy_missing)
    expect(result.configuration_commands).to include("info-center loghost source LoopBack0")
    expect(result.to_text).to include("未定义当前范围的批准值")
  end

  it "does not produce changes from an incomplete backup" do
    result = plan({ "syslog.source" => "LoopBack0" }, text: "sysname LAB\ninfo-center loghost source LoopBack1\n", complete: false)
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
    expect(result.checks.first.reason).to eq(:input_incomplete)
  end

  it "rejects command injection in approved interface values" do
    [ "LoopBack0\nsave", "LoopBack0;save", "LoopBack0\0", "Loopback" + "0" * 254 ].each do |value|
      result = plan({ "syslog.source" => value }, text: "sysname LAB\ninfo-center loghost source LoopBack1\n")
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
      expect(result.checks.first.reason).to eq(:invalid_command_parameter)
    end
  end

  it "generates only the explicitly enabled services that need disabling" do
    result = plan({ "services.disabled" => %w[telnet http] }, text: "sysname LAB\ntelnet server enable\nundo ip http enable\n")
    expect(result.configuration_commands).to eq([ "system-view", "undo telnet server enable", "return" ])
    expect(result.status).to eq(:ready)
  end

  it "keeps the service metric blocked if some required service states remain unknown" do
    result = plan({ "services.disabled" => %w[telnet http] }, text: "sysname LAB\ntelnet server enable\n")
    expect(result.status).to eq(:partial)
    expect(result.checks.first.status).to eq(:blocked)
    expect(result.checks.first.requirements).to include("service_state:http")
    expect(result.configuration_commands).to include("undo telnet server enable")
  end

  it "provides one planning result for every enabled baseline metric" do
    result = Baseline::Remediation.new(policy: Baseline::Policy.default).call(configuration: "sysname LAB\n", platform: "h3c", complete: true)
    expect(result.checks.map(&:id)).to eq(result.audit.findings.map(&:id))
    expect(result.checks.size).to eq(30)
    expect(result.status).to eq(:blocked)
  end

  it "is deterministic and returns immutable operations and checks" do
    checks = { "syslog.source" => "LoopBack0" }
    text = "sysname LAB\ninfo-center loghost source LoopBack1\n"
    first = plan(checks, text: text)
    second = plan(checks, text: text)
    expect(first.to_h).to eq(second.to_h)
    expect(first.operations.first).to be_frozen
    expect(first.operations).to be_frozen
    expect(first.checks).to be_frozen
    expect(first.to_text).to include("人工审核", "syslog.source")
  end

  it "rejects invalid operation values and command phases before rendering" do
    expect do
      Baseline::ConfigurationOperation.new(kind: "setting", identity: { "rule" => "syslog.source" }, before: "LoopBack1", after: nil)
    end.to raise_error(ArgumentError)
    expect do
      Baseline::CommandStep.new(view: [], command: "info-center loghost source LoopBack0", phase: :execute, operation_id: "synthetic")
    end.to raise_error(ArgumentError)
  end
end

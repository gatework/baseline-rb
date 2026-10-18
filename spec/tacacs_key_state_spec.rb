# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Comware and VRP TACACS key state" do
  def report(body, platform: "h3c")
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.keys" => { "expected" => true } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{body}\n", platform: platform, complete: true)
  end

  def scheme(keys = "")
    "hwtacacs scheme OPS\n primary authentication 192.0.2.30\n#{keys}"
  end

  def all_keys(format = "cipher")
    %w[authentication authorization accounting].map { |role| " key #{role} #{format} SYNTHETIC-#{role.upcase}\n" }.join
  end

  it "does not retain a key or its credential after withdrawal" do
    result = report(scheme(all_keys + " undo key authentication\n"))
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.lines).to include(7)
    expect(result.configuration.fact("credentials.records").map { |row| row[:purpose] }).to eq(%w[authorization accounting])
  end

  it "records only the final storage attributes of replacement keys" do
    result = report(scheme(all_keys("simple") + all_keys("cipher")))
    expect(result.configuration.fact("credentials.records").size).to eq(3)
    expect(result.configuration.fact("credentials.storage_safe")).to be(true)
  end

  it "invalidates a missing-value update instead of certifying an old key" do
    result = report(scheme(all_keys + " key authentication cipher\n"))
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.fact("credentials.records").none? { |row| row[:purpose] == "authentication" && row[:storage] == "protected" }).to be(true)
    restored = report(scheme(all_keys + " key authentication cipher\n key authentication cipher SYNTHETIC-NEW\n"))
    expect(restored.findings.first.status).to eq(:pass)
  end

  it "merges reopened schemes and removes an entire withdrawn scheme before deriving resources" do
    result = report(scheme(all_keys) + "#\nhwtacacs scheme OPS\n secondary authentication 192.0.2.31\n")
    expect(result.findings.first.status).to eq(:pass)
    expect(result.configuration.fact("tacacs.servers")).to contain_exactly("192.0.2.30", "192.0.2.31")
    removed = report(scheme(all_keys) + "#\nundo hwtacacs scheme OPS\n")
    expect(removed.configuration.fact("tacacs.servers")).to eq([])
    expect(removed.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }).to eq([])
    expect(removed.configuration.fact("credentials.records")).to eq([])
  end

  it "handles Huawei shared key withdrawal and replacement in order" do
    base = "hwtacacs-server template OPS\n hwtacacs-server authentication 192.0.2.30\n hwtacacs-server shared-key cipher SYNTHETIC-OLD\n"
    expect(report(base + " undo hwtacacs-server shared-key\n", platform: "huawei").findings.first.status).to eq(:fail)
    replaced = report(base + " hwtacacs-server shared-key cipher SYNTHETIC-NEW\n", platform: "huawei")
    expect(replaced.configuration.fact("credentials.records").size).to eq(1)
    expect(replaced.findings.first.status).to eq(:pass)
  end

  it "provides nonsecret slot evidence for every required scheme key responsibility" do
    result = report(scheme(" key authentication cipher SYNTHETIC-AUTH\n"))
    slots = result.configuration.fact("tacacs.key_slots")
    expect(slots).to contain_exactly(include(group: "OPS", role: "authentication", present: true, complete: true),
      include(group: "OPS", role: "authorization", present: false, complete: true), include(group: "OPS", role: "accounting", present: false, complete: true))
    expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH")
    expect(slots).to all(be_frozen)
  end

  it "does not fabricate observed credentials from unobserved partial key slots" do
    result = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: "sysname LAB\n#{scheme}", platform: "h3c", complete: false)
    expect(result.configuration.fact("credentials.records")).to be_nil.or eq([])
    expect(result.configuration.fact("credentials.present")).not_to be(true)
  end
end

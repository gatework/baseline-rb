# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Huawei local username case evidence" do
  it "distinguishes local-case from local for both authentication and authorization while retaining local fallback" do
    text = File.read(File.expand_path("fixtures/baseline/huawei.cfg", __dir__))
    original = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: :huawei, complete: true).configuration
    changed = text.sub("authentication-mode hwtacacs local", "authentication-mode hwtacacs local-case")
      .sub("authorization-mode hwtacacs local", "authorization-mode hwtacacs local-case")
    result = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: changed, platform: :huawei, complete: true).configuration
    %w[authentication authorization].each do |role|
      before = original.fact("aaa.bindings").find { |row| row[:role] == role }
      after = result.fact("aaa.bindings").find { |row| row[:role] == role }
      expect(before[:methods]).to eq([ { kind: "tacacs", group: "OPS" }, { kind: "local" } ])
      expect(after[:methods]).to eq([ { kind: "tacacs", group: "OPS" }, { kind: "local", case_sensitive: true } ])
      expect(after).to include(local_fallback: true, complete: true, uses_tacacs: true)
    end
    expect(result.fact("aaa.bindings").to_s).not_to include("PRIVATE-VRP")
  end
  { "h3c" => [ "scheme", "aaa" ], "huawei" => [ "aaa", "scheme" ] }.each do |platform, (native, foreign)|
    it "does not certify #{platform} VTY authentication using the other vendor's mode" do
      text = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__)).sub("authentication-mode #{native}", "authentication-mode #{foreign}")
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_aaa" => { "expected" => true } })
      report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
      expect(report.findings.first.status).to eq(:unknown)
      expect(report.configuration.fact_known?("ssh.vty_aaa")).to be(false)
      expect(report.configuration.fact("tacacs.login")).not_to be(true)
    end
  end
end

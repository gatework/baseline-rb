# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "SSH service remediation" do
  {
    "h3c" => [ "sysname LAB", "ssh server enable", "undo ssh server enable", "system-view", "return" ],
    "huawei" => [ "sysname LAB", "stelnet server enable", "undo stelnet server enable", "system-view", "return" ],
    "cisco_nxos" => [ "hostname LAB", "feature ssh", "no feature ssh", "configure terminal", "end" ]
  }.each do |platform, (hostname, enabled, disabled, enter, leave)|
    it "generates an explicit approved #{platform} service shutdown without modifying keys" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => false } })
      engine = Baseline::Remediation.new(policy: policy)
      first = engine.call(configuration: "#{hostname}\n#{enabled}\n", platform: platform, complete: true)
      expect(first.configuration_commands).to eq([ enter, disabled, leave ])
      expect(first.operations.first.risk).to eq("high")
      second = engine.call(configuration: "#{hostname}\n#{disabled}\n", platform: platform, complete: true)
      expect(second.status).to eq(:noop)
    end
  end

  it "does not claim SSH enablement without existing key and endpoint evidence" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => true } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nundo ssh server enable\n", platform: "h3c", complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.requirements).to include("existing_key_material", "management_endpoint_scope")
  end

  it "does not break a passing SSH-only VTY requirement by shutting SSH down" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => false }, "ssh.vty_ssh_only" => { "expected" => true } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nssh server enable\nline vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n",
      platform: "h3c", complete: true)
    expect(result.checks.first.reason).to eq(:policy_conflict)
    expect(result.configuration_commands).to be_empty
  end
end

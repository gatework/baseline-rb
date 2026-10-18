# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "SNMP version remediation" do
  def policy(versions = [ "v3" ], extra = {})
    Baseline::Policy.new("version" => 1, "checks" => { "snmp.versions" => { "expected" => versions, "remediation" => { "existing_v3_access_verified" => true } } }.merge(extra))
  end

  def configuration(versions = "v1 v2c v3")
    "sysname LAB\nsnmp-agent\nsnmp-agent sys-info version #{versions}\n" \
      "snmp-agent group v3 ops privacy read-view iso\n" \
      "snmp-agent usm-user v3 observer ops authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV acl 2000\n"
  end

  it "removes only unapproved versions and preserves existing users and ACL bindings" do
    service = Baseline::Remediation.new(policy: policy)
    input = configuration
    plan = service.call(configuration: input, platform: "h3c", complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "system-view", "undo snmp-agent sys-info version v1 v2c", "return" ])
    expect(plan.operations.first.risk).to eq("high")
    expect(plan.to_h.to_json).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
    # 独立版本集合变换，不把渲染器输出当作结果配置。
    versions = input[/sys-info version (.+)/, 1].split - %w[v1 v2c]
    after = input.sub(/sys-info version .+/, "sys-info version #{versions.join(' ')}")
    expect(after).to include("observer ops", "acl 2000")
    expect(service.call(configuration: after, platform: "h3c", complete: true).status).to eq(:noop)
  end

  it "retains an already approved older version instead of over-tightening the allowed subset" do
    plan = Baseline::Remediation.new(policy: policy(%w[v2c v3])).call(configuration: configuration, platform: "h3c", complete: true)
    expect(plan.configuration_commands).to include("undo snmp-agent sys-info version v1")
    expect(plan.configuration_commands).not_to include("undo snmp-agent sys-info version v1 v2c")
  end

  it "blocks without existing authenticated and encrypted v3 users" do
    [ configuration.sub(/snmp-agent usm-user.+\n/, ""), configuration.sub(/ privacy-mode aes128 cipher SYNTHETIC-PRIV/, "") ].each do |input|
      plan = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
      expect(plan.status).to eq(:blocked)
      expect(plan.checks.first.requirements).to include("snmp.v3_auth_priv")
      expect(plan.operations).to be_empty
    end
  end

  it "blocks missing group references and user or group withdrawal evidence" do
    [ configuration.sub(/snmp-agent group.+\n/, ""), configuration + "undo snmp-agent usm-user v3 observer ops local\n",
      configuration + "undo snmp-agent group v3 ops\n" ].each do |input|
      plan = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
      expect(plan.status).to eq(:blocked)
      expect(plan.operations).to be_empty
    end
  end

  it "does not invent new v3 enablement or remove every active version" do
    [ [ configuration("v1 v2c"), policy ], [ configuration, policy([ "v2c" ]) ] ].each do |input, approved|
      plan = Baseline::Remediation.new(policy: approved).call(configuration: input, platform: "h3c", complete: true)
      expect(plan.status).to eq(:blocked)
      expect(plan.configuration_commands).to be_empty
    end
  end

  it "does not narrow versions while the approved policy requires SNMP disabled" do
    plan = Baseline::Remediation.new(policy: policy([ "v3" ], "snmp.enabled" => { "expected" => false })).call(configuration: configuration, platform: "h3c", complete: true)
    expect(plan.checks.first.reason).to eq(:policy_conflict)
    expect(plan.operations).to be_empty
  end

  it "requires confirmation of an existing working v3 access path before disabling legacy monitoring" do
    unconfirmed = Baseline::Policy.new("version" => 1, "checks" => { "snmp.versions" => { "expected" => [ "v3" ] } })
    plan = Baseline::Remediation.new(policy: unconfirmed).call(configuration: configuration, platform: "h3c", complete: true)
    expect(plan.configuration_commands).to be_empty
    expect(plan.checks.first.requirements).to include("existing_v3_access_verified")
  end

  it "accepts only a boolean v3 access confirmation on the SNMP versions rule" do
    expect { Baseline::Policy.new("version" => 1, "checks" => { "snmp.versions" => { "expected" => [ "v3" ], "remediation" => { "existing_v3_access_verified" => true } } }) }.not_to raise_error
    [ "yes", 1, nil ].each do |value|
      expect { Baseline::Policy.new("version" => 1, "checks" => { "snmp.versions" => { "expected" => [ "v3" ], "remediation" => { "existing_v3_access_verified" => value } } }) }.to raise_error(ArgumentError)
    end
    expect { Baseline::Policy.new("version" => 1, "checks" => { "ssh.versions" => { "expected" => [ "2" ], "remediation" => { "existing_v3_access_verified" => true } } }) }.to raise_error(ArgumentError)
  end

  it "publishes the explicit v3 access prerequisite separately from parser coverage" do
    capability = Baseline::Remediation.capabilities(platform: "h3c").fetch("snmp.versions")
    expect(capability[:status]).to eq(:conditional)
    expect(capability[:requirements]).to include("existing_v3_access_verified", "snmp_v3_group_reference")
  end

  it "does not reuse H3C version removal syntax for Huawei" do
    plan = Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: "huawei", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.operations).to be_empty
  end
end

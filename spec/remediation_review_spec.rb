# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Manual remediation review guidance" do
  def source_plan(platform = "h3c", before: "LoopBack1", after: "LoopBack0")
    header = platform.start_with?("cisco") ? "hostname LAB" : "sysname LAB"
    prefix = platform.start_with?("cisco") ? "logging source-interface" : "info-center loghost source"
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => after } })
    Baseline::Remediation.new(policy: policy).call(configuration: "#{header}\n#{prefix} #{before}\n", platform: platform, complete: true)
  end

  it "separates read-only inspection, manual persistence and unexecuted inverse intents from corrections" do
    plan = source_plan
    expect(plan.review[:validation]).to include(status: :not_executed, commands: [ "display current-configuration" ], requires_full_snapshot: true)
    expect(plan.review[:persistence]).to include(status: :manual_only, commands: [ "save" ])
    rollback = plan.review[:rollback]
    expect(rollback).to include(status: :requires_replanning, configuration_commands: [], requires_fresh_snapshot: true, requires_separate_approval: true)
    inverse = rollback[:inverse_operations].first
    expect(inverse).to include(kind: "setting", before: "LoopBack0", after: "LoopBack1", source_operation_id: plan.operations.first.id)
    expect(inverse[:id]).not_to eq(plan.operations.first.id)
    expect(plan.configuration_commands).to eq([ "system-view", "info-center loghost source LoopBack0", "return" ])
    expect(plan.to_h[:review]).to eq(plan.review)
    expect(plan.to_text).to include("人工保存/提交提示", "只读复查", "回退需重新规划")
    expect { plan.review[:validation][:commands] << "save" }.to raise_error(FrozenError)
  end

  it "records that an inverse restores old state rather than claiming the approved baseline remains satisfied" do
    plan = source_plan
    inverse = plan.review[:rollback][:inverse_operations].first
    expect(plan.review[:rollback][:restores_previous_state]).to be(true)
    expect(plan.review[:rollback][:approved_baseline_status]).to eq(:not_verified)
    expect(plan.review[:rollback][:requires_baseline_revalidation]).to be(true)
    prior = source_plan(before: inverse[:after])
    expect(prior.audit.findings.first.status).to eq(:fail)
  end

  %w[huawei cisco_ios cisco_nxos].each do |platform|
    it "uses #{platform} inspection entrypoints without assuming an unverified commit model" do
      plan = source_plan(platform)
      expect(plan.status).to eq(:ready)
      expect(plan.review[:validation][:commands]).to eq(platform == "huawei" ? [ "display current-configuration" ] : [ "show running-config" ])
      expect(plan.review[:persistence][:commands]).to eq(platform == "huawei" ? [] : [ "copy running-config startup-config" ])
      expect(plan.review[:validation][:requires_running_reaudit]).to be(true)
    end
  end

  it "marks no-op or fully blocked plans as having no change to persist or reverse" do
    [ source_plan(before: "LoopBack0"), source_plan(after: nil) ].each do |plan|
      expect(plan.review[:validation][:commands]).to be_empty
      expect(plan.review[:persistence]).to include(status: :not_needed, commands: [])
      expect(plan.review[:rollback]).to include(status: :not_applicable, inverse_operations: [], configuration_commands: [])
    end
  end

  it "does not invent inverse enable commands for service shutdown or authentication transitions" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "services.disabled" => { "expected" => [ "telnet" ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\ntelnet server enable\n", platform: :h3c, complete: true)
    expect(plan.review[:rollback]).to include(status: :manual_required, inverse_operations: [])
    expect(plan.review[:rollback][:unavailable]).to contain_exactly(include(operation_id: plan.operations.first.id, reason: :native_restore_not_modelled))
    expect(plan.review[:rollback][:configuration_commands]).to be_empty
  end

  it "keeps resource inverse intents typed but requires new capacity, reference and material validation" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "192.0.2.20" ], "remediation" => { "maximum_targets" => 2 } } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\ninfo-center loghost 192.0.2.10\n", platform: :h3c, complete: true)
    expect(plan.status).to eq(:ready)
    intents = plan.review[:rollback][:inverse_operations]
    expect(intents.size).to eq(plan.operations.size)
    expect(intents.map { |value| value[:source_operation_id] }).to eq(plan.operations.reverse.map(&:id))
    intents.each { |value| expect { Baseline::ConfigurationOperation.new(**value.except(:id, :source_operation_id)) }.not_to raise_error }
    expect(plan.review[:rollback][:requires_dependency_revalidation]).to be(true)
    expect(plan.review[:rollback][:configuration_commands]).to be_empty
  end

  it "separates PAN-OS candidate inspection and manual commit from the set-format audit input" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => "ethernet1/2" } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "set deviceconfig system hostname LAB\n" \
      "set deviceconfig system route service syslog source interface ethernet1/1\n", platform: :palo_alto, complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.review[:validation]).to include(commands: [ "show config diff", "show config candidate" ], scope: :candidate, audit_format: :set)
    expect(plan.review[:persistence]).to include(commands: [ "commit" ], view: :configuration)
    expect(plan.configuration_commands).not_to include("commit", "show config candidate")
  end

  it "provides StoneOS inspection and a routing-aware inverse intent without bypassing native NTP proofs" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "source" => "MGT0" } } ],
      "managed_scopes" => [ { "vrf" => "default" } ]
    } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\nntp server 192.0.2.10 source MGT1\n", platform: :hillstone, complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.review[:validation][:commands]).to eq([ "show configuration" ])
    expect(plan.review[:persistence][:commands]).to eq([ "save" ])
    inverse = plan.review[:rollback][:inverse_operations].first
    expect(inverse[:after]).to include("source" => "MGT1", "vrf" => "default", "vrf_explicit" => false)
    operation = Baseline::ConfigurationOperation.new(**inverse.except(:id, :source_operation_id))
    expect { Baseline::Hillstone::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "requires new authentication recovery planning rather than inverting a previously approved global switch" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.authentication" => { "expected" => false,
      "remediation" => { "ntp_peer_key_compatibility_verified" => true } } })
    source = "sysname LAB\nntp-service authentication enable\nntp-service unicast-server 192.0.2.10\n" \
      "snmp-agent community read cipher SYNTHETIC-SECRET\n"
    plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: :h3c, complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.review[:rollback]).to include(status: :manual_required, inverse_operations: [])
    expect(plan.review[:rollback][:unavailable]).to contain_exactly(include(reason: :authentication_or_material_reassessment_required))
    expect(plan.to_h.to_s).not_to include("SYNTHETIC-SECRET")
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "SNMP permission review requirements" do
  def plan(body, expected: false, complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "snmp.write_enabled" => { "expected" => expected } })
    Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nsnmp-agent\n#{body}", platform: "h3c", complete: complete)
  end

  let(:body) do
    "snmp-agent group v3 OPS privacy read-view READ write-view WRITE notify-view NOTIFY acl 2000\n" \
      "snmp-agent group v3 OPS authentication read-view READ\n" \
      "snmp-agent usm-user v3 observer OPS authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n" \
      "snmp-agent community write cipher SYNTHETIC-COMMUNITY\n"
  end

  it "identifies write grants, group security definitions and their known users without exporting material" do
    result = plan(body)
    expect(result.checks.first.reason).to eq(:snmp_permission_approval_required)
    grants = result.checks.first.details.fetch(:permission_grants)
    expect(grants).to contain_exactly(include(kind: "snmp.group", name: "OPS", action: "revoke_write", risk: "high"),
      include(kind: "snmp.community", name: "community:1", action: "replace_with_read_only", risk: "high"))
    group = grants.find { |grant| grant[:kind] == "snmp.group" }
    expect(group[:definitions]).to include(include(security: "privacy", write_view: "WRITE", read_view: "READ", notify_view: "NOTIFY", acl: "2000"))
    expect(group[:users]).to contain_exactly(include(name: "observer", auth: true, priv: true))
    expect(group[:requirements]).to include("preserve_read_notify_views", "preserve_security_and_acl", "verified_vendor_permission_transition")
    expect(grants.find { |grant| grant[:kind] == "snmp.community" }[:requirements]).to include("approved_replacement_credential", "nms_consumer_update")
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
    expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV", "SYNTHETIC-COMMUNITY")
    expect(grants).to all(be_frozen)
  end

  it "requests evidence for unresolved grants rather than asserting a writable principal" do
    result = plan("snmp-agent group v3 OPS privacy unsupported-option VALUE\n")
    expect(result.audit.findings.first.status).to eq(:unknown)
    expect(result.checks.first.reason).to eq(:snmp_permission_evidence_required)
    expect(result.checks.first.details.fetch(:permission_grants)).to contain_exactly(include(name: "OPS", action: "verify"))
  end

  it "does not grant write access or infer an action from missing policy and partial inputs" do
    expect(plan(body, complete: false).checks.first.details).to eq({})
    expect(plan(body, expected: nil).checks.first.details).to eq({})
    inverse = plan("snmp-agent group v3 OPS privacy\n", expected: true)
    expect(inverse.checks.first.reason).to eq(:unsupported_setting)
    expect(inverse.operations).to be_empty
  end

  it "distinguishes manual permission requirements from native command capability" do
    expect(Baseline::Remediation.capabilities(platform: "h3c").fetch("snmp.write_enabled")).to include(
      status: :unsupported, reason: :snmp_permission_approval_required,
      requirements: include("approved_snmp_principal_permissions", "verified_vendor_permission_transition"))
  end

  it "keeps a proven write grant while requiring a complete inventory for malformed principals" do
    result = plan(body + "snmp-agent usm-user v2c legacy\n")
    expect(result.checks.first.reason).to eq(:snmp_permission_approval_required)
    expect(result.checks.first.requirements).to include("resolved_snmp_permission_inventory")
    expect(result.checks.first.details[:inventory_complete]).to be(false)
    expect(result.operations).to be_empty
  end

  it "retains unresolved user-group references as evidence requests" do
    text = "snmp-agent usm-user v3 observer MISSING authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n"
    result = plan(text)
    expect(result.checks.first.details.fetch(:permission_grants)).to contain_exactly(include(kind: "snmp.user", name: "observer", action: "verify",
      requirements: include("resolved_snmp_group_reference")))
    expect(result.checks.first.reason).to eq(:snmp_permission_evidence_required)
  end
end

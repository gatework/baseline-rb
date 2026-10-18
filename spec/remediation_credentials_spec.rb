# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Credential remediation requirements" do
  def plan(text, checks, complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => checks.transform_values { |expected| { "expected" => expected } })
    Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\n#{text}", platform: "h3c", complete: complete)
  end

  let(:strength) { { "min_length" => 12, "min_classes" => 3 } }

  it "identifies unsafe storage objects and leaves protected unrelated credentials alone" do
    result = plan("local-user alice class manage\n password simple SYNTHETIC-PASSWORD\n#\nlocal-user bob class manage\n password cipher SYNTHETIC-CIPHER\n", { "credentials.storage" => true })
    check = result.checks.first
    expect(check.reason).to eq(:credential_rotation_required)
    expect(check.details.fetch(:credentials)).to contain_exactly(include(owner: "alice", kind: "local_user", lines: [ 3 ], action: "rotate", deviations: [ "plaintext_storage" ],
      requirements: include("approved_replacement_credential", "supported_protected_storage_format"), dependencies: include("local_fallback_access_verified")))
    expect(result.configuration_commands).to be_empty
    expect(result.to_h.to_s).not_to include("SYNTHETIC-PASSWORD", "SYNTHETIC-CIPHER")
    expect(check.details[:credentials].first).to be_frozen
  end

  it "separates observed weak passwords from opaque strength evidence" do
    result = plan("local-user alice class manage\n password simple admin\n#\nlocal-user bob class manage\n password cipher SYNTHETIC-CIPHER\n", { "credentials.strength" => strength })
    entries = result.checks.first.details.fetch(:credentials)
    expect(entries).to contain_exactly(include(owner: "alice", action: "rotate", deviations: %w[common_password minimum_length minimum_character_classes]),
      include(owner: "bob", action: "verify", deviations: [ "strength_unobservable" ], requirements: [ "external_password_strength_evidence" ]))
    expect(result.checks.first.reason).to eq(:credential_rotation_required)
  end

  it "requests external strength evidence without asserting opaque passwords require rotation" do
    result = plan("local-user bob class manage\n password cipher SYNTHETIC-CIPHER\n", { "credentials.strength" => strength })
    expect(result.audit.findings.first.status).to eq(:unknown)
    expect(result.checks.first.reason).to eq(:credential_strength_verification_required)
    expect(result.checks.first.requirements).to eq([ "external_password_strength_evidence" ])
    expect(result.checks.first.details.fetch(:credentials).first).to include(action: "verify")
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
  end

  it "does not recommend weakening already protected storage for an inverse policy" do
    result = plan("local-user bob class manage\n password cipher SYNTHETIC-CIPHER\n", { "credentials.storage" => false })
    expect(result.checks.first.reason).to eq(:unsupported_setting)
    expect(result.checks.first.details).to eq({})
    expect(result.configuration_commands).to be_empty
  end

  it "does not manufacture credential objects from absent, missing-policy or partial evidence" do
    [ plan("", { "credentials.strength" => strength }), plan("", { "credentials.storage" => nil }),
      plan("local-user alice class manage\n password simple admin\n", { "credentials.storage" => true }, complete: false) ].each do |result|
      expect(result.checks.first.details).to eq({})
      expect(result.operations).to be_empty
    end
  end

  it "distinguishes SNMP authentication and privacy material without retaining secrets" do
    result = plan("snmp-agent\nsnmp-agent group v3 OPS privacy\n" \
      "snmp-agent usm-user v3 observer OPS authentication-mode sha simple SYNTHETIC-AUTH privacy-mode aes128 simple SYNTHETIC-PRIV\n", { "credentials.storage" => true })
    entries = result.checks.first.details.fetch(:credentials)
    expect(entries.map { |entry| entry[:purpose] }).to eq(%w[authentication privacy])
    expect(entries.map { |entry| entry[:id] }.uniq.size).to eq(2)
    expect(entries).to all(include(owner: "snmp:observer", dependencies: include("snmp_manager_update")))
    expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV")
  end

  it "keeps TACACS key responsibilities distinct and includes peer and fallback dependencies" do
    result = plan("hwtacacs scheme ADMIN\n key authentication simple SYNTHETIC-AUTH\n key authorization simple SYNTHETIC-AUTHZ\n key accounting simple SYNTHETIC-ACCT\n", { "credentials.storage" => true })
    entries = result.checks.first.details.fetch(:credentials)
    expect(entries.map { |entry| entry[:purpose] }).to eq(%w[authentication authorization accounting])
    expect(entries).to all(include(owner: "tacacs:ADMIN", dependencies: include("tacacs_peer_update", "local_fallback_access_verified")))
  end

  it "requests storage evidence for unclassified material without inventing a replacement" do
    result = plan("local-user missing class manage\n#\n", { "credentials.storage" => true })
    expect(result.checks.first.reason).to eq(:credential_storage_verification_required)
    expect(result.checks.first.details.fetch(:credentials)).to contain_exactly(include(owner: "missing", action: "verify", deviations: [ "storage_unobservable" ],
      requirements: [ "credential_storage_evidence" ], dependencies: []))
  end

  it "keeps satisfied credentials noop and does not issue instructions outside policy scope" do
    result = plan("local-user safe class manage\n password simple Synthetic-Safe9!\n", { "credentials.strength" => strength })
    expect(result.status).to eq(:noop)
    expect(result.checks.first.details).to eq({})
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "credentials.storage" => { "expected" => true, "applies_to" => { "vendor" => [ "huawei" ] } }
    })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nlocal-user alice\n password simple admin\n", platform: "h3c", complete: true)
    expect(result.checks.first.status).to eq(:not_applicable)
    expect(result.checks.first.details).to eq({})
  end

  it "distinguishes material requirement support from executable command capability" do
    capabilities = Baseline::Remediation.capabilities(platform: "h3c")
    expect(capabilities.fetch("credentials.storage")).to include(status: :unsupported, reason: :credential_rotation_required,
      requirements: include("credential_object_evidence", "manual_rotation_procedure"))
  end
end

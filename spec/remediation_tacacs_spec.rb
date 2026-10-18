# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "TACACS key material requirements" do
  def plan(body, platform: "h3c", complete: true, expected: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.keys" => { "expected" => expected } })
    Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\n#{body}\n", platform: platform, complete: complete)
  end

  let(:body) do
    "hwtacacs scheme OPS\n primary authentication 192.0.2.30\n primary authorization 192.0.2.31\n" \
      " primary accounting 192.0.2.32\n key authentication cipher SYNTHETIC-AUTH\n"
  end

  it "identifies missing role material and its actual scheme endpoints" do
    result = plan(body)
    expect(result.checks.first.reason).to eq(:credential_material_required)
    slots = result.checks.first.details.fetch(:key_slots)
    expect(slots.map { |slot| slot[:role] }).to eq(%w[authorization accounting])
    expect(slots.map { |slot| slot[:group] }).to eq(%w[OPS OPS])
    expect(slots.first[:endpoints].first[:identity]).to include("address" => "192.0.2.31", "role" => "authorization")
    expect(slots).to all(include(action: "provision", risk: "high", requirements: include("approved_tacacs_key_material"),
      dependencies: include("tacacs_peer_key_update", "authentication_reference_evidence", "local_fallback_access_verified")))
    expect(result.status).to eq(:blocked)
    expect(result.configuration_commands).to be_empty
    expect(result.operations).to be_empty
    expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH")
    expect(slots).to all(be_frozen)
  end

  it "does not replace malformed key evidence with an assertion that material is missing" do
    text = body + " key authorization cipher SYNTHETIC-AUTHZ\n key accounting cipher SYNTHETIC-ACCT\n key authentication cipher\n"
    result = plan(text)
    expect(result.audit.findings.first.status).to eq(:unknown)
    expect(result.checks.first.reason).to eq(:credential_material_evidence_required)
    expect(result.checks.first.details.fetch(:key_slots)).to contain_exactly(include(role: "authentication", present: nil, action: "verify",
      requirements: [ "tacacs_key_state_evidence" ]))
  end

  it "distinguishes Huawei shared material from individual H3C roles" do
    result = plan("hwtacacs-server template OPS\n hwtacacs-server authentication 192.0.2.30\n hwtacacs-server accounting 192.0.2.31\n", platform: "huawei")
    slots = result.checks.first.details.fetch(:key_slots)
    expect(slots.size).to eq(1)
    expect(slots.first).to include(group: "OPS", role: "shared", source: "scheme", action: "provision")
    expect(slots.first[:endpoints].size).to eq(2)
  end

  it "requires approved scope when no scheme exists and does not suggest removing keys for inverse policy" do
    absent = plan("")
    expect(absent.checks.first.reason).to eq(:unresolved_prerequisites)
    expect(absent.checks.first.requirements).to include("approved_tacacs_scheme", "approved_tacacs_endpoints")
    keyed = body + " key authorization cipher SYNTHETIC-AUTHZ\n key accounting cipher SYNTHETIC-ACCT\n"
    expect(plan(keyed).status).to eq(:noop)
    expect(plan(keyed, expected: false).checks.first.reason).to eq(:unsupported_setting)
  end

  it "does not compile key requirements from a partial capture or missing policy" do
    expect(plan(body, complete: false).checks.first.details).to eq({})
    expect(plan(body, expected: nil).checks.first.details).to eq({})
  end

  it "reports manual key material handling without claiming secret command generation" do
    expect(Baseline::Remediation.capabilities(platform: "h3c").fetch("tacacs.keys")).to include(status: :unsupported, reason: :credential_material_required)
    expect(Baseline::Remediation.capabilities(platform: "huawei").fetch("tacacs.keys")).to include(status: :unsupported, reason: :credential_material_required)
  end
end

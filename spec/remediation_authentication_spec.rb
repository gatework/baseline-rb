# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Management AAA reference requirements" do
  def plan(text, id: "tacacs.login", complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => true } })
    Baseline::Remediation.new(policy: policy).call(configuration: text, platform: "h3c", complete: complete)
  end

  let(:source) do
    "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\n" \
      "domain ADMIN\n authentication login local\n#\ndomain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n"
  end

  it "requires approval for a specific domain role and keeps candidate groups distinct from approved references" do
    result = plan(source)
    check = result.checks.first
    expect(check.reason).to eq(:authentication_chain_approval_required)
    expect(check.details).to include(required_role: "authentication", risk: "high")
    expect(check.details[:bindings]).to contain_exactly(include(domain: "ADMIN", uses_tacacs: false, local_fallback: false))
    expect(check.details[:available_groups]).to contain_exactly(include(name: "OPS", role: "authentication", servers: [ "192.0.2.30" ]))
    expect(check.requirements).to include("approved_management_domain", "approved_ordered_method_chain", "approved_tacacs_group", "local_fallback_access_verified")
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
  end

  it "requests missing domain and VTY evidence without proposing to bind an arbitrary existing group" do
    result = plan(source.sub("domain default enable ADMIN", "domain default enable MISSING"))
    expect(result.checks.first.reason).to eq(:authentication_chain_evidence_required)
    expect(result.checks.first.requirements).to include("resolved_management_domain")
    expect(result.checks.first.details[:bindings].first).to include(domain: "MISSING", complete: false)
    expect(result.configuration_commands).to be_empty
  end

  it "retains VTY scope and a verified recovery prerequisite for AAA mode correction" do
    result = plan(source.sub("authentication-mode scheme", "authentication-mode password"), id: "ssh.vty_aaa")
    expect(result.checks.first.requirements).to include("approved_vty_scope", "approved_authentication_mode", "local_fallback_access_verified")
    expect(result.checks.first.details[:bindings].first[:vtys]).to contain_exactly(include(name: "line vty 0 4", authentication: "password"))
    expect(result.checks.first.requirements).not_to include("approved_tacacs_group", "existing_tacacs_key_evidence")
  end

  it "keeps requirements immutable and does not produce them from partial input" do
    expect(plan(source).checks.first.details.fetch(:bindings)).to be_frozen
    expect(plan(source, complete: false).checks.first.details).to eq({})
  end

  it "exposes conditional chain support with explicit native approval requirements" do
    capability = Baseline::Remediation.capabilities(platform: "h3c").fetch("tacacs.login")
    expect(capability).to include(status: :conditional, reason: :authentication_chain_approval_required,
      requirements: include("management_domain", "methods", "management_consumers_verified"))
  end
end

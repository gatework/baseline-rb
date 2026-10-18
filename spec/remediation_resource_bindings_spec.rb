# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Shared TACACS binding change requirements" do
  it "keeps shared domain references visible before changing a server object" do
    expected = { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" }, "scope" => { "group" => "OPS" }, "bindings" => [] }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => { "expected" => [ expected ] } })
    source = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\ndomain ADMIN\n authentication login hwtacacs-scheme OPS local\n#\n" \
      "domain OTHER\n authentication login hwtacacs-scheme OPS local\n#\ndomain default enable ADMIN\n"
    plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: "h3c", complete: true)
    check = plan.checks.first
    expect(check.reason).to eq(:resource_binding_changes_required)
    expect(check.requirements).to include("approved_binding_change_scope", "preserved_or_approved_reference_migration", "local_fallback_access_verified")
    current = check.details.fetch(:current_references)
    expect(current.first[:bindings].map { |binding| binding["domain"] }).to contain_exactly("admin", "other")
    expect(check.details[:differences][:binding_differences]).not_to be_empty
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
    expect(plan.operations).to be_empty
  end
end

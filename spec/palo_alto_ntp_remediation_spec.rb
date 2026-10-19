# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/palo_alto_ntp_state"

RSpec.describe "PAN-OS NTP slot remediation" do
  def slot(name, address, authenticated: false)
    { "identity" => { "name" => "#{name}-ntp-server" }, "scope" => {},
      "attributes" => { "address" => address, "authenticated" => authenticated } }
  end

  def service(targets, extra: {}, checks: {})
    rule = { "expected" => targets, "managed_scopes" => [ {} ], "remediation" => { "maximum_targets" => 2 }.merge(extra) }
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => rule }.merge(checks)))
  end

  def source(name, address, authentication = "none")
    prefix = "set deviceconfig system ntp-servers #{name}-ntp-server"
    "#{prefix} ntp-server-address #{address}\n#{prefix} authentication-type #{authentication}\n"
  end

  def plan(engine, text, complete: true)
    engine.call(configuration: "set deviceconfig system hostname LAB\n#{text}", platform: "palo_alto", complete: complete)
  end

  it "changes only the approved address leaf, retains the other slot and converges" do
    text = source("primary", "192.0.2.10").sub("primary-ntp-server ntp-server-address", '"primary-ntp-server" ntp-server-address') +
      source("secondary", "192.0.2.20") + "set deviceconfig system domain LAB.invalid\n"
    engine = service([ slot("primary", "2001:db8::30"), slot("secondary", "192.0.2.20") ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure", "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 2001:db8::30", "exit" ])
    state = PaloAltoNtpState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include(source("secondary", "192.0.2.20"), "set deviceconfig system domain LAB.invalid")
    expect(state.configuration).not_to include("ntp-server-address 192.0.2.10")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "adds an explicitly unauthenticated slot and removes only the unapproved slot" do
    engine = service([ slot("secondary", "time.EXAMPLE.test") ])
    text = source("primary", "192.0.2.10")
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure",
      "set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address time.example.test",
      "set deviceconfig system ntp-servers secondary-ntp-server authentication-type none",
      "delete deviceconfig system ntp-servers primary-ntp-server", "exit" ])
    state = PaloAltoNtpState.new(text).apply(result.configuration_commands)
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "retains existing authentication material only with external compatibility evidence for the new peer" do
    text = source("primary", "192.0.2.10", "symmetric-key algorithm sha1 authentication-key SYNTHETIC-KEY") +
      "set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key key-id 7\n"
    targets = [ slot("primary", "192.0.2.30", authenticated: true) ]
    blocked = plan(service(targets), text)
    expect(blocked.status).to eq(:blocked)
    expect(blocked.checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    engine = service(targets, extra: { "ntp_peer_key_compatibility_verified" => true })
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure", "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.30", "exit" ])
    state = PaloAltoNtpState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include("authentication-key SYNTHETIC-KEY", "key-id 7")
    expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "cannot invent authentication material for a new approved authenticated slot" do
    result = plan(service([ slot("primary", "192.0.2.10", authenticated: true) ]), "")
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.requirements).to include("approved_ntp_authentication_material")
    expect(result.configuration_commands).to be_empty
  end

  it "does not erase unmodelled settings when deleting a slot" do
    result = plan(service([]), source("primary", "192.0.2.10") + "set deviceconfig system ntp-servers primary-ntp-server unsupported-option opaque\n")
    expect(result.status).to eq(:blocked)
    expect(result.configuration_commands).to be_empty
    expect(result.audit.configuration.fact_known?("ntp.associations")).to be(false)
  end

  it "preserves an enabled authentication rule when removal would leave no authentication evidence" do
    result = plan(service([], checks: { "ntp.authentication" => { "expected" => false } }), source("primary", "192.0.2.10"))
    expect(result.status).to eq(:blocked)
    expect(result.configuration_commands).to be_empty
    expect(result.checks.find { |check| check.id == "ntp.associations" }.reason).to eq(:policy_conflict)
  end

  it "produces no operations from partial input" do
    result = plan(service([ slot("primary", "192.0.2.30") ]), source("primary", "192.0.2.10"), complete: false)
    expect(result.status).to eq(:blocked)
    expect(result.configuration_commands).to be_empty
  end

  it "does not let a direct renderer call bypass peer compatibility verification" do
    operation = Baseline::ConfigurationOperation.new(kind: "ntp.association", identity: { "name" => "primary-ntp-server" }, scope: {},
      action: :replace, phase: :update, risk: "medium", before: { "address" => "192.0.2.10", "authenticated" => true },
      after: { "address" => "192.0.2.30", "authenticated" => true })
    expect { Baseline::PaloAlto::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "cannot add an unkeyed slot beside an authenticated server" do
    result = plan(service([ slot("primary", "192.0.2.10", authenticated: true), slot("secondary", "192.0.2.20") ]),
      source("primary", "192.0.2.10", "autokey"))
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:ntp_authentication_dependency)
    expect(result.configuration_commands).to be_empty
  end

  it "requires an explicit authentication choice when creating a new slot" do
    target = slot("primary", "192.0.2.10")
    target["attributes"].delete("authenticated")
    result = plan(service([ target ]), "")
    expect(result.checks.first.requirements).to include("explicit_ntp_authentication_choice")
    expect(result.configuration_commands).to be_empty
  end
end

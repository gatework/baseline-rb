# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/stoneos_ntp_state"

RSpec.describe "StoneOS NTP remediation" do
  def object(address, vrf: "default", **attributes)
    { "identity" => { "address" => address, "role" => "server" }, "scope" => { "vrf" => vrf }, "attributes" => attributes.transform_keys(&:to_s) }
  end

  def service(targets, scopes: [ { "vrf" => "default" } ], checks: {}, **options)
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => {
      "ntp.associations" => { "expected" => targets, "managed_scopes" => scopes, "remediation" => { "maximum_targets" => 3 }.merge(options.transform_keys(&:to_s)) }
    }.merge(checks)))
  end

  def plan(engine, text, complete: true)
    engine.call(configuration: "hostname LAB\n#{text}", platform: :hillstone, complete: complete)
  end

  it "updates scoped fields and preserves other vrouter servers and unrelated configuration" do
    text = "ntp enable\nntp server 192.0.2.10 source MGT0 prefer vrouter OPS\nntp server 192.0.2.11 source MGT1 vrouter OTHER\nlogging syslog 192.0.2.99 udp 514\n"
    engine = service([ object("192.0.2.10", vrf: "OPS", source: "MGT2") ], scopes: [ { "vrf" => "OPS" } ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.operations.map(&:kind)).to eq([ "ntp.server" ])
    expect(result.configuration_commands).to eq([ "configure", "no ntp server 192.0.2.10", "ntp server 192.0.2.10 source MGT2 prefer vrouter OPS", "exit" ])
    after = StoneosNtpState.new(text).apply(result.configuration_commands).configuration
    expect(after).to include("ntp server 192.0.2.11 source MGT1 vrouter OTHER", "logging syslog 192.0.2.99 udp 514", "ntp enable")
    expect(plan(engine, after).status).to eq(:noop)
  end

  it "moves a global native address between explicitly managed routing scopes as one replacement" do
    text = "ntp server 192.0.2.10 source MGT0 vrouter OLD\n"
    engine = service([ object("192.0.2.10", vrf: "NEW", source: "MGT1") ], scopes: %w[OLD NEW].map { |vrf| { "vrf" => vrf } })
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(1)
    expect(result.operations.first.before).to include("vrf" => "OLD")
    expect(result.operations.first.after).to include("vrf" => "NEW")
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    expect(plan(service([ object("192.0.2.10", vrf: "NEW") ], scopes: [ { "vrf" => "NEW" } ]), text).operations).to be_empty
  end

  it "fits the native three-server limit at every step even when policy capacity is larger" do
    text = (10..12).map { |id| "ntp server 192.0.2.#{id}\n" }.join
    targets = (11..13).map { |id| object("192.0.2.#{id}") }
    engine = service(targets, maximum_targets: 10)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands.index("no ntp server 192.0.2.10")).to be < result.configuration_commands.index("ntp server 192.0.2.13")
    expect(result.operations.first.phase).to eq(:prepare)
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    expect(plan(service(targets + [ object("192.0.2.14") ], maximum_targets: 10), text).checks.first.reason).to eq(:capacity_exceeded)
  end

  it "reuses known implicit-trust material only with external peer compatibility verification" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7\n"
    engine = service([ object("192.0.2.20", key_id: 7) ], ntp_peer_key_compatibility_verified: true)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    after = StoneosNtpState.new(text).apply(result.configuration_commands).configuration
    expect(after).to include("ntp authentication-key 7 md5 SYNTHETIC-KEY")
    expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
    expect(plan(engine, after).status).to eq(:noop)
    expect(plan(service([ object("192.0.2.20", key_id: 7) ]), text).operations).to be_empty
    expect(plan(engine, text + "no ntp authentication-key 7\n").operations).to be_empty
  end

  it "keeps unsupported tails, partial input and conflicting global source constraints blocked" do
    text = "ntp server 192.0.2.10 source MGT0\n"
    engine = service([ object("192.0.2.10", source: "MGT1") ], checks: { "ntp.source" => { "expected" => "MGT0" } })
    expect(plan(engine, text).checks.find { |check| check.id == "ntp.associations" }.reason).to eq(:policy_conflict)
    expect(plan(engine, text, complete: false).operations).to be_empty
    expect(plan(engine, text + "ntp server 192.0.2.10 PRIVATE-TAIL\n").operations).to be_empty
  end

  it "plans a common source through approved scoped associations even from heterogeneous sources" do
    text = "ntp server 192.0.2.10 source MGT0\nntp server 192.0.2.11 source MGT1\n"
    engine = service([ object("192.0.2.10"), object("192.0.2.11") ], checks: { "ntp.source" => { "expected" => "MGT2", "severity" => "critical" } })
    result = plan(engine, text)
    expect(result.checks.find { |check| check.id == "ntp.source" }.status).to eq(:planned)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(2)
    expect(result.operations.map(&:risk).uniq).to eq([ "critical" ])
    after = StoneosNtpState.new(text).apply(result.configuration_commands).configuration
    expect(plan(engine, after).status).to eq(:noop)
  end

  it "does not derive source-change targets or routing approval from current servers" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.source" => { "expected" => "MGT2" } })
    result = plan(Baseline::Remediation.new(policy: policy), "ntp server 192.0.2.10 source MGT0\n")
    expect(result.checks.first.requirements).to include("approved_ntp_associations", "managed_scopes")
    expect(result.operations).to be_empty
  end

  it "can explicitly clear preference and converges without changing other servers" do
    text = "ntp server 192.0.2.10 prefer\nntp server 192.0.2.11\n"
    engine = service([ object("192.0.2.10", prefer: false), object("192.0.2.11") ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "preserves unspecified fields across a route move and revalidates the authenticated peer" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7 source MGT0 prefer vrouter OLD\n"
    targets = [ object("192.0.2.10", vrf: "NEW") ]
    scopes = %w[OLD NEW].map { |vrf| { "vrf" => vrf } }
    expect(plan(service(targets, scopes: scopes), text).checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    engine = service(targets, scopes: scopes, ntp_peer_key_compatibility_verified: true)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("ntp server 192.0.2.10 key 7 source MGT0 prefer vrouter NEW")
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "supports canonical DNS and IPv6 targets without treating textual aliases as new endpoints" do
    text = "ntp server TIME.EXAMPLE\nntp server 2001:0db8::10 source MGT0\n"
    engine = service([ object("time.example"), object("2001:db8::10", source: "MGT1") ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).not_to include("no ntp server time.example")
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    ambiguous = service([ object("192.0.2.10", vrf: "A"), object("192.0.2.10", vrf: "B") ], scopes: %w[A B].map { |vrf| { "vrf" => vrf } })
    expect(plan(ambiguous, "ntp server 192.0.2.11\n").checks.first.reason).to eq(:native_resource_identity_unresolved)
  end

  it "does not allow direct rendering to assume native inventory or material preconditions" do
    operation = Baseline::ConfigurationOperation.new(kind: "ntp.server", identity: { "address" => "192.0.2.10", "role" => "server" },
      before: nil, after: { "vrf" => "default" }, action: :add, phase: :create)
    renderer = Baseline::Hillstone::CommandRenderer.new
    expect { renderer.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { renderer.render(operation, verified_ntp_operation_ids: [ "a" * 64 ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect(renderer.render(operation, verified_ntp_operation_ids: [ operation.id ]).map(&:command)).to eq([ "ntp server 192.0.2.10" ])
    expect { Baseline::ConfigurationOperation.new(**operation.to_h.except(:id).merge(after: { "vrf" => "default", "secret" => "PRIVATE" })) }.to raise_error(ArgumentError)
  end

  it "verifies native updates before an unchanged terminal marker without a trailing newline" do
    text = "ntp server 192.0.2.10\nEnd"
    engine = service([ object("192.0.2.20") ])
    result = plan(engine, text)
    after = StoneosNtpState.new(text).apply(result.configuration_commands).configuration
    expect(after).to end_with("\nEnd")
    expect(plan(engine, after).status).to eq(:noop)
  end

  it "can explicitly configure a source whose implicit current selection remains unknown" do
    text = "ntp server 192.0.2.10\n"
    engine = service([ object("192.0.2.10", source: "MGT0") ])
    result = plan(engine, text)
    expect(result.audit.findings.first.reason).to eq(:resource_attribute_unresolved)
    expect(result.status).to eq(:ready)
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    expect(plan(engine, text + "ntp server 192.0.2.10 source PRIVATE extra\n").operations).to be_empty
  end

  it "can attach an explicit known key reference to an existing unkeyed server with verified peer evidence" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10\n"
    engine = service([ object("192.0.2.10", key_id: 7) ], ntp_peer_key_compatibility_verified: true)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    expect(plan(service([ object("192.0.2.10", key_id: 7) ]), text).operations).to be_empty
  end

  it "uses the documented global capacity when no redundant capacity value is supplied" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => [ object("192.0.2.10") ], "managed_scopes" => [ { "vrf" => "default" } ]
    } })
    result = plan(Baseline::Remediation.new(policy: policy), "")
    expect(result.status).to eq(:ready)
    expect(result.checks.first.details).to include(maximum_targets: 3, capacity_source: :native)
  end

  it "preserves an explicit vrouter named default instead of dropping its routing qualifier" do
    text = "ntp server 192.0.2.10 source MGT0 vrouter default\n"
    scope = { "vrf" => "default", "vrf_mode" => "named" }
    engine = service([ object("192.0.2.10", source: "MGT1").merge("scope" => scope) ], scopes: [ scope ])
    result = plan(engine, text)
    expect(result.configuration_commands).to include("ntp server 192.0.2.10 source MGT1 vrouter default")
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "does not include a named default router in the implicit default managed scope" do
    text = "ntp server 192.0.2.10 source MGT0 vrouter default\n"
    result = plan(service([]), text)
    expect(result.status).to eq(:noop)
    expect(result.operations).to be_empty
  end

  it "requires both scopes and peer verification when switching from named default to implicit routing" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7 vrouter default\n"
    scopes = [ { "vrf" => "default" }, { "vrf" => "default", "vrf_mode" => "named" } ]
    targets = [ object("192.0.2.10") ]
    expect(plan(service(targets, scopes: scopes), text).checks.first.requirements).to include("ntp_peer_key_compatibility_verified")
    engine = service(targets, scopes: scopes, ntp_peer_key_compatibility_verified: true)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("ntp server 192.0.2.10 key 7")
    expect(plan(engine, StoneosNtpState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end
end

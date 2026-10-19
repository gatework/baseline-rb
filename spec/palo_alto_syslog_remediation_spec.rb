# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/palo_alto_syslog_state"

RSpec.describe "PAN-OS Syslog server remediation" do
  def object(name, address, profile: "LOGS", **fields)
    { "identity" => { "name" => name }, "scope" => { "profile" => profile },
      "attributes" => { "address" => address, "protocol" => "udp", "port" => 514, "format" => "BSD", "facility" => "LOG_USER" }.merge(fields.transform_keys(&:to_s)) }
  end

  def definition(name, address, profile: "LOGS", **fields)
    value = object(name, address, profile: profile, **fields)
    prefix = "set shared log-settings syslog \"#{profile}\" server \"#{name}\""
    value["attributes"].map do |key, item|
      field = { "address" => "server", "protocol" => "transport" }.fetch(key, key)
      item = item.upcase if key == "protocol"
      "#{prefix} #{field} #{item}\n"
    end.join
  end

  def service(targets, scopes: [ { "profile" => "LOGS" } ], **options)
    rule = { "expected" => targets, "managed_scopes" => scopes, "remediation" => { "maximum_targets" => 10 }.merge(options.transform_keys(&:to_s)) }
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => rule }))
  end

  def plan(engine, text, complete: true)
    engine.call(configuration: "set deviceconfig system hostname LAB\n#{text}", platform: :palo_alto, complete: complete)
  end

  it "updates only approved leaves and preserves custom formatting, references and other profiles" do
    text = definition("FIRST", "192.0.2.10") + definition("OTHER", "192.0.2.10", profile: "UNMANAGED") +
      "set shared log-settings syslog LOGS format system 'PRIVATE-FORMAT'\n" \
      "set shared log-settings system match-list ALL send-syslog LOGS\n"
    engine = service([ object("FIRST", "2001:db8::20", port: 5514) ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure",
      'set shared log-settings syslog "LOGS" server "FIRST" server "2001:db8::20"',
      'set shared log-settings syslog "LOGS" server "FIRST" port 5514', "exit" ])
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include(definition("OTHER", "192.0.2.10", profile: "UNMANAGED"), "format system 'PRIVATE-FORMAT'", "match-list ALL send-syslog LOGS")
    expect(plan(engine, state.configuration).status).to eq(:noop)
    expect(result.to_h.to_s).not_to include("PRIVATE-FORMAT")
  end

  it "adds and removes complete server identities inside the same used profile" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog LOGS\n"
    engine = service([ object("NEW", "logs.EXAMPLE.test") ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands.last(2)).to eq([ 'delete shared log-settings syslog "LOGS" server "OLD"', "exit" ])
    expect(result.configuration_commands).to include('set shared log-settings syslog "LOGS" server "NEW" server "logs.example.test"')
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "does not orphan active or unused forwarding references by removing their last server" do
    [ "set shared log-settings system match-list ALL send-syslog LOGS\n",
      "set shared log-settings profiles UNUSED match-list TRAFFIC log-type traffic\nset shared log-settings profiles UNUSED match-list TRAFFIC send-syslog LOGS\n" ].each do |reference|
      result = plan(service([]), definition("FIRST", "192.0.2.10") + reference)
      expect(result.status).to eq(:blocked)
      expect(result.checks.first.reason).to eq(:syslog_profile_references_required)
      expect(result.configuration_commands).to be_empty
    end
  end

  it "deletes an unreferenced server without deleting its profile custom format" do
    text = definition("FIRST", "192.0.2.10") + "set shared log-settings syslog LOGS format system 'UNCHANGED'\n"
    engine = service([])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include("format system 'UNCHANGED'")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "requires explicit approval before activating a previously dangling profile reference" do
    text = "set shared log-settings system match-list ALL send-syslog LOGS\n"
    target = object("FIRST", "192.0.2.10")
    blocked = plan(service([ target ]), text)
    expect(blocked.checks.first.reason).to eq(:syslog_reference_approval_required)
    target["bindings"] = [ { "kind" => "syslog.device", "log_type" => "system", "match" => "ALL" } ]
    engine = service([ target ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "does not turn creation of a missing object into an unimplemented binding migration" do
    target = object("FIRST", "192.0.2.10")
    target["bindings"] = [ { "kind" => "syslog.device", "log_type" => "system", "match" => "NEW-PATH" } ]
    result = plan(service([ target ]), "")
    expect(result.checks.first.reason).to eq(:resource_binding_changes_required)
    expect(result.configuration_commands).to be_empty
  end

  it "fits native per-profile capacity before adding a fifth temporary server" do
    text = (1..4).map { |index| definition("S#{index}", "192.0.2.#{index}") }.join
    targets = (2..5).map { |index| object("S#{index}", "192.0.2.#{index}") }
    engine = service(targets)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands[1]).to eq('delete shared log-settings syslog "LOGS" server "S1"')
    expect(result.operations.find { |operation| operation.action == :remove }.phase).to eq(:prepare)
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    over_capacity = plan(service(targets + [ object("S6", "192.0.2.6") ]), text)
    expect(over_capacity.checks.first.reason).to eq(:capacity_exceeded)
    expect(over_capacity.configuration_commands).to be_empty
  end

  it "blocks unknown references, unsupported fields and partial input atomically" do
    engine = service([ object("FIRST", "192.0.2.20") ])
    text = definition("FIRST", "192.0.2.10")
    [ text + "set shared log-settings system send-syslog LOGS\n",
      text + "set shared log-settings syslog LOGS server FIRST unsupported-option opaque\n" ].each do |source|
      expect(plan(engine, source).configuration_commands).to be_empty
    end
    unknown = plan(engine, text + "set shared log-settings system send-syslog LOGS\n")
    expect(unknown.audit.configuration.fact_known?("syslog.declared_profile_references")).to be(false)
    expect(plan(engine, text, complete: false).configuration_commands).to be_empty
  end

  it "requires external TLS peer evidence before changing a protected endpoint" do
    text = definition("FIRST", "192.0.2.10", protocol: "ssl", port: 6514)
    targets = [ object("FIRST", "192.0.2.20", protocol: "ssl", port: 6514) ]
    blocked = plan(service(targets), text)
    expect(blocked.status).to eq(:blocked)
    expect(blocked.checks.first.requirements).to include("syslog_tls_peer_compatibility_verified")
    engine = service(targets, syslog_tls_peer_compatibility_verified: true)
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    expect { service(targets, syslog_tls_peer_compatibility_verified: "yes") }.to raise_error(ArgumentError)
  end

  it "does not let direct rendering bypass TLS endpoint verification" do
    operation = Baseline::ConfigurationOperation.new(kind: "syslog.destination", action: :add, phase: :create,
      identity: { "name" => "FIRST" }, scope: { "profile" => "LOGS" }, before: nil,
      after: object("FIRST", "192.0.2.20", protocol: "ssl", port: 6514)["attributes"])
    expect { Baseline::PaloAlto::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { Baseline::PaloAlto::CommandRenderer.new.render(operation, verified_syslog_operation_ids: [ "0" * 64 ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "keeps protected transport and certificate configuration for a format-only update" do
    text = definition("FIRST", "192.0.2.10", protocol: "ssl", port: 6514) + "set shared certificate CERT private-key SYNTHETIC-KEY\n"
    engine = service([ object("FIRST", "192.0.2.10", protocol: "ssl", port: 6514, format: "IETF") ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure", 'set shared log-settings syslog "LOGS" server "FIRST" format IETF', "exit" ])
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include("private-key SYNTHETIC-KEY")
    expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "reports required native parameters rather than copying options from another endpoint" do
    target = object("FIRST", "192.0.2.20")
    target["attributes"].delete("protocol")
    target["attributes"].delete("format")
    result = plan(service([ target ]), "")
    expect(result.checks.first.requirements).to include("syslog.protocol", "syslog.format")
    expect(result.configuration_commands).to be_empty
    changed_transport = object("FIRST", "192.0.2.20", protocol: "tcp")
    changed_transport["attributes"].delete("port")
    incomplete = "set shared log-settings syslog LOGS server FIRST server 192.0.2.10\nset shared log-settings syslog LOGS server FIRST transport UDP\n"
    missing_port = plan(service([ changed_transport ]), incomplete)
    expect(missing_port.checks.first.requirements).to include("syslog.port")
    expect(missing_port.configuration_commands).to be_empty
  end

  it "requires verified reference prerequisites even for a directly rendered plain server removal" do
    operation = Baseline::ConfigurationOperation.new(kind: "syslog.destination", action: :remove, phase: :remove,
      identity: { "name" => "FIRST" }, scope: { "profile" => "LOGS" }, before: object("FIRST", "192.0.2.10")["attributes"], after: nil)
    expect { Baseline::PaloAlto::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "quotes native names and cannot merge same-named servers in different profiles" do
    text = definition("Log Server", "192.0.2.10", profile: "Log Fleet") + definition("Log Server", "192.0.2.10", profile: "OTHER")
    engine = service([ object("Log Server", "192.0.2.20", profile: "Log Fleet") ], scopes: [ { "profile" => "Log Fleet" } ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure", 'set shared log-settings syslog "Log Fleet" server "Log Server" server "192.0.2.20"', "exit" ])
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include(definition("Log Server", "192.0.2.10", profile: "OTHER"))
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "enforces the documented native name grammar while retaining the 31-character boundary" do
    [ object("S" * 32, "192.0.2.20"), object("FIRST", "192.0.2.20", profile: "Log.Fleet") ].each do |target|
      result = plan(service([ target ], scopes: [ target["scope"] ]), "")
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
    end
    target = object("S" * 31, "192.0.2.20", profile: "P" * 31)
    engine = service([ target ], scopes: [ target["scope"] ])
    result = plan(engine, "")
    expect(result.status).to eq(:ready)
    expect(plan(engine, PaloAltoSyslogState.new("").apply(result.configuration_commands).configuration).status).to eq(:noop)
  end
end

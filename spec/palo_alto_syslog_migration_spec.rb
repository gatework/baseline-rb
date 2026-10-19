# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/palo_alto_syslog_state"

RSpec.describe "PAN-OS Syslog reference migration" do
  def server(profile, address)
    { "identity" => { "name" => "SERVER" }, "scope" => { "profile" => profile },
      "attributes" => { "address" => address, "protocol" => "udp", "port" => 514, "format" => "BSD", "facility" => "LOG_USER" } }
  end

  def definition(profile, address)
    "set shared log-settings syslog #{profile} server SERVER server #{address}\n" \
      "set shared log-settings syslog #{profile} server SERVER transport UDP\n" \
      "set shared log-settings syslog #{profile} server SERVER port 514\n" \
      "set shared log-settings syslog #{profile} server SERVER format BSD\n" \
      "set shared log-settings syslog #{profile} server SERVER facility LOG_USER\n"
  end

  def reference
    { "kind" => "syslog.device", "log_type" => "system", "match" => "ALL" }
  end

  def migration(from = "OLD", to = "NEW", **fields)
    { "from_profile" => from, "to_profile" => to, "reference" => reference }.merge(fields.transform_keys(&:to_s))
  end

  def service(targets, migrations, scopes: %w[OLD NEW], **options)
    rule = { "expected" => targets, "managed_scopes" => scopes.map { |profile| { "profile" => profile } },
      "remediation" => { "maximum_targets" => 10, "binding_migrations" => migrations }.merge(options.transform_keys(&:to_s)) }
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => rule }))
  end

  def plan(engine, text, complete: true)
    engine.call(configuration: "set deviceconfig system hostname LAB\n#{text}", platform: :palo_alto, complete: complete)
  end

  def target(profile = "NEW", bindings = [ reference ])
    server(profile, profile == "OLD" ? "192.0.2.10" : "192.0.2.20").merge("bindings" => bindings)
  end

  it "creates a target, adds its reference, removes the old membership, then removes the old server" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog [ OLD KEEP ]\n" \
      "set shared log-settings system match-list ALL filter 'PRIVATE-FILTER'\n" \
      "set shared log-settings system match-list ALL actions ACTION type tagging tags PRIVATE-ACTION\n"
    engine = service([ target ], [ migration ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    commands = result.configuration_commands
    add = 'set shared log-settings system match-list "ALL" send-syslog "NEW"'
    remove = 'delete shared log-settings system match-list "ALL" send-syslog "OLD"'
    expect(commands.index(add)).to be < commands.index(remove)
    expect(commands.index(remove)).to be < commands.index('delete shared log-settings syslog "OLD" server "SERVER"')
    expect(commands.join).not_to include("PRIVATE-FILTER", "PRIVATE-ACTION", "KEEP")
    state = PaloAltoSyslogState.new(text).apply(commands)
    expect(state.configuration).to include("PRIVATE-FILTER", "PRIVATE-ACTION")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "supports binding-only attachment to an existing match while retaining server objects" do
    text = definition("NEW", "192.0.2.20") + "set shared log-settings system match-list ALL filter 'All Logs'\n"
    engine = service([ target ], [ migration(nil) ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.operations.map(&:kind)).to eq([ "syslog.reference" ])
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "does not infer a missing match filter or accept partial input as migration evidence" do
    engine = service([ target ], [ migration(nil) ])
    result = plan(engine, definition("NEW", "192.0.2.20"))
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.requirements).to include("existing_syslog_reference_match")
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n"
    expect(plan(service([ target ], [ migration ]), text, complete: false).operations).to be_empty
  end

  it "rejects malformed migration paths, members and ambiguous source transitions" do
    [ migration("OLD", "OLD"), migration(nil, nil), migration(reference: reference.merge("filter" => "PRIVATE")),
      migration(to_profile: "NEW\ncommit"), migration(consumers: []) ].each do |value|
      expect { service([ target ], [ value ]) }.to raise_error(ArgumentError)
    end
    expect { service([ target ], [ migration, migration(to_profile: "OTHER") ]) }.to raise_error(ArgumentError)
  end

  def forwarding_reference
    { "kind" => "syslog.forwarding", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic" }
  end

  def consumers
    [ forwarding_reference.merge("context" => "local", "rulebase" => "security", "rule" => "ALLOW"),
      forwarding_reference.merge("kind" => "syslog.zone", "context" => "vsys", "vsys" => "BLUE", "zone" => "INSIDE") ]
  end

  def forwarded_text
    definition("OLD", "192.0.2.10") + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC filter 'PRIVATE-FILTER'\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog [ OLD KEEP ]\n" \
      "set rulebase security rules ALLOW log-setting FORWARD\nset rulebase security rules ALLOW log-end yes\n" \
      "set vsys BLUE zone INSIDE network log-setting FORWARD\n"
  end

  it "requires explicit approval of every shared rule and zone consumer including requested predicates" do
    change = migration(reference: forwarding_reference)
    result = plan(service([ target("NEW", consumers) ], [ change ]), forwarded_text)
    expect(result.checks.first.requirements).to include("approved_syslog_consumers")
    [ [], consumers.take(1), [ consumers.first.merge("log_end" => false), consumers.last ],
      [ consumers.first.merge("log_start" => true), consumers.last ] ].each do |approved|
      blocked = plan(service([ target("NEW", consumers) ], [ change.merge("consumers" => approved) ]), forwarded_text)
      expect(blocked.checks.first.requirements).to include("complete_matching_syslog_consumers")
      expect(blocked.operations).to be_empty
      expect(blocked.configuration_commands).to be_empty
    end
  end

  it "migrates the whole shared match while preserving its other receivers, filters and rule flags" do
    approved = [ consumers.first.merge("log_end" => true), consumers.last ]
    engine = service([ target("NEW", approved) ], [ migration(reference: forwarding_reference, consumers: approved) ])
    result = plan(engine, forwarded_text)
    expect(result.status).to eq(:ready)
    state = PaloAltoSyslogState.new(forwarded_text).apply(result.configuration_commands)
    expect(state.configuration).to include("PRIVATE-FILTER", "log-end yes", '"KEEP"')
    expect(result.configuration_commands.join).not_to include("PRIVATE-FILTER", "log-end", "zone", "KEEP")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "permits an explicitly approved unused forwarding match without inventing consumers" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog OLD\n"
    engine = service([ target("NEW", []) ], [ migration(reference: forwarding_reference, consumers: []) ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "detaches only the approved membership and retains the server and match filter" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n" \
      "set shared log-settings system match-list ALL filter 'All Logs'\n"
    engine = service([ target("OLD", []) ], [ migration("OLD", nil) ], scopes: [ "OLD" ])
    result = plan(engine, text)
    expect(result.operations.map(&:kind)).to eq([ "syslog.reference" ])
    state = PaloAltoSyslogState.new(text).apply(result.configuration_commands)
    expect(state.configuration).to include(definition("OLD", "192.0.2.10"), "filter 'All Logs'")
    expect(plan(engine, state.configuration).status).to eq(:noop)
  end

  it "requires managed profiles, explicit final bindings and a known source member" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n"
    expect(plan(service([ target ], [ migration ], scopes: [ "NEW" ]), text).checks.first.reason).to eq(:approved_scope_required)
    omitted = target.except("bindings")
    expect(plan(service([ omitted ], [ migration ]), text).checks.first.requirements).to include("explicit_projected_profile_bindings")
    missing = text.sub("send-syslog OLD", "send-syslog KEEP")
    expect(plan(service([ target ], [ migration ]), missing).checks.first.requirements).to include("known_syslog_reference_membership")
  end

  it "blocks projected bindings that differ from the approved target or point at an empty profile" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n"
    expect(plan(service([ target("NEW", []) ], [ migration ]), text).checks.first.reason).to eq(:resource_binding_changes_required)
    result = plan(service([], [ migration ]), text)
    expect(result.checks.first.requirements).to include("approved_referenced_syslog_server")
    expect(result.configuration_commands).to be_empty
  end

  it "applies changes for the same match simultaneously rather than chaining migrations" do
    text = definition("OLD", "192.0.2.10") + definition("NEW", "192.0.2.20") +
      "set shared log-settings system match-list ALL send-syslog [ OLD NEW ]\n"
    targets = [ target, server("LAST", "192.0.2.30").merge("bindings" => [ reference ]) ]
    engine = service(targets, [ migration, migration("NEW", "LAST") ], scopes: %w[OLD NEW LAST])
    result = plan(engine, text)
    change = result.operations.find { |operation| operation.kind == "syslog.reference" }
    expect(change.before).to eq("profiles" => %w[NEW OLD])
    expect(change.after).to eq("profiles" => %w[LAST NEW])
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "does not remove the last currently referenced server early to make capacity for migration" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n"
    result = plan(service([ target ], [ migration ], maximum_targets: 1), text)
    expect(result.checks.first.requirements).to include("capacity_for_reference_migration")
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
  end

  it "requires the complete reference operation fingerprint for direct rendering" do
    operation = Baseline::ConfigurationOperation.new(kind: "syslog.reference", identity: reference, before: { "profiles" => [ "OLD" ] },
      after: { "profiles" => [ "NEW" ] }, action: :replace, phase: :update, risk: "high")
    renderer = Baseline::PaloAlto::CommandRenderer.new
    expect { renderer.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { renderer.render(operation, verified_syslog_operation_ids: [ "a" * 64 ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect(renderer.render(operation, verified_syslog_operation_ids: [ operation.id ]).size).to eq(2)
  end

  it "retains migration idempotence while another approved server leaf still needs updating" do
    text = definition("NEW", "192.0.2.20") + "set shared log-settings system match-list ALL send-syslog NEW\n"
    expected = target
    expected["attributes"]["port"] = 5514
    engine = service([ expected ], [ migration ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(result.operations.map(&:kind)).to eq([ "syslog.destination" ])
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
  end

  it "does not silently ignore native migrations on another platform" do
    result = service([ target ], [ migration ]).call(configuration: "hostname LAB\nlogging host 192.0.2.10\n", platform: :cisco_ios, complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.first.reason).to eq(:unsupported_syslog_binding_migration)
  end

  it "does not emit a migration when the approved desired state is already compliant" do
    text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list ALL send-syslog OLD\n"
    result = plan(service([ target("OLD") ], [ migration ]), text)
    expect(result.status).to eq(:noop)
    expect(result.operations).to be_empty
  end

  it "does not let out-of-scope migration options block another applicable legacy policy" do
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "syslog.destinations" => { "expected" => [ target ], "managed_scopes" => [ { "profile" => "NEW" } ],
        "applies_to" => { "vendor" => "palo_alto" }, "remediation" => { "binding_migrations" => [ migration ] } },
      "syslog.servers" => { "expected" => [ "192.0.2.20" ], "remediation" => { "maximum_targets" => 2 } }
    })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\ninfo-center loghost 192.0.2.10\nreturn\n", platform: :h3c, complete: true)
    expect(result.checks.find { |check| check.id == "syslog.destinations" }.status).to eq(:not_applicable)
    expect(result.checks.find { |check| check.id == "syslog.servers" }.status).to eq(:planned)
    expect(result.operations).not_to be_empty
  end

  it "rejects foreign consumer approval and untyped reference operation payloads" do
    foreign = consumers.first.merge("forwarding_profile" => "UNRELATED")
    expect { service([ target ], [ migration(reference: forwarding_reference, consumers: [ foreign ]) ]) }.to raise_error(ArgumentError)
    base = { kind: "syslog.reference", identity: reference, before: { "profiles" => [ "OLD" ] }, after: { "profiles" => [ "NEW" ] }, action: :replace }
    [ { phase: :remove }, { scope: { "raw" => "PRIVATE" } }, { after: { "profiles" => [ "NEW", "NEW" ] } },
      { after: { "profiles" => [ "NEW" ], "filter" => "PRIVATE" } } ].each do |invalid|
      expect { Baseline::ConfigurationOperation.new(**base.merge(invalid)) }.to raise_error(ArgumentError)
    end
  end

  it "retains documented dotted match names and 64-character forwarding profile identities" do
    name = "F" * 64
    changed_reference = forwarding_reference.merge("forwarding_profile" => name, "match" => "TRAFFIC.LOGS")
    approved = consumers.map { |binding| binding.merge("forwarding_profile" => name, "match" => "TRAFFIC.LOGS") }
    text = forwarded_text.gsub("FORWARD", name).gsub("TRAFFIC", "TRAFFIC.LOGS")
    engine = service([ target("NEW", approved) ], [ migration(reference: changed_reference, consumers: approved) ])
    result = plan(engine, text)
    expect(result.status).to eq(:ready)
    expect(plan(engine, PaloAltoSyslogState.new(text).apply(result.configuration_commands).configuration).status).to eq(:noop)
    device = reference.merge("match" => "SYSTEM.LOGS")
    direct_text = definition("OLD", "192.0.2.10") + "set shared log-settings system match-list SYSTEM.LOGS send-syslog OLD\n"
    expect(plan(service([ target("NEW", [ device ]) ], [ migration(reference: device) ]), direct_text).status).to eq(:ready)
  end

  it "rejects an overlong native forwarding identity atomically" do
    name = "F" * 65
    changed_reference = forwarding_reference.merge("forwarding_profile" => name)
    approved = consumers.map { |binding| binding.merge("forwarding_profile" => name) }
    result = plan(service([ target("NEW", approved) ], [ migration(reference: changed_reference, consumers: approved) ]), forwarded_text.gsub("FORWARD", name))
    expect(result.checks.first.reason).to eq(:unsupported_setting)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
  end
end

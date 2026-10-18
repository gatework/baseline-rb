# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/h3c_configuration_state"

RSpec.describe "Syslog object remediation" do
  it "keeps generated targets inside the configuration after command output headers" do
    input = "display current-configuration\nCurrent configuration:\n#\nsysname LAB\ninfo-center loghost 192.0.2.20\nreturn\n"
    state = H3cConfigurationState.new(input)
    state.apply([ "system-view", "info-center loghost 192.0.2.40", "undo info-center loghost 192.0.2.20", "return" ])
    expect(state.configuration.index("info-center loghost 192.0.2.40")).to be > state.configuration.index("sysname LAB")
  end

  it "models indented global Comware blocks without deleting nested targets" do
    input = "#\n sysname LAB\n#\n info-center loghost 192.0.2.20\n#\ninterface GigabitEthernet1/0/1\n info-center loghost 203.0.113.9\n#\nreturn\n"
    state = H3cConfigurationState.new(input).apply([ "system-view", "info-center loghost 192.0.2.40", "undo info-center loghost 192.0.2.20", "return" ])
    expect(state.configuration).not_to include("info-center loghost 192.0.2.20")
    expect(state.configuration).to include("interface GigabitEthernet1/0/1\n info-center loghost 203.0.113.9\n")
  end

  def destination(address, port: 1514, vrf: "default")
    { "identity" => { "address" => address }, "scope" => { "vrf" => vrf }, "attributes" => { "port" => port } }
  end

  def service(checks = {}, capacity: 4, **keyword_checks)
    checks = checks.merge(keyword_checks)
    # 本组独立设备模型的硬件配置支持4个目标；该证据由测试明确提供。
    checks = checks.transform_values do |options|
      capacity ? options.merge("remediation" => { "maximum_targets" => capacity }.merge(options.fetch("remediation", {}))) : options
    end
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => checks))
  end

  def run_plan(engine, text, complete: true)
    engine.call(configuration: text, platform: "h3c", complete: complete)
  end

  it "adds approved targets before removing wrong ones and keeps correct options and nested configuration" do
    input = "sysname LAB\ninfo-center loghost 192.0.2.20 port 6514 facility local5\ninfo-center loghost 192.0.2.30 port 514\n" \
      "info-center loghost source LoopBack0\ninterface GigabitEthernet1/0/1\n description KEEP\n info-center loghost 203.0.113.9\n#\nreturn\n"
    engine = service("syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.40] })
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "system-view", "info-center loghost 192.0.2.40", "undo info-center loghost 192.0.2.30", "return" ])
    after = H3cConfigurationState.new(input).apply(plan.configuration_commands).configuration
    expect(after).to include("info-center loghost 192.0.2.20 port 6514 facility local5\n", "info-center loghost source LoopBack0\n",
      "interface GigabitEthernet1/0/1\n description KEEP\n info-center loghost 203.0.113.9\n")
    second = run_plan(engine, after)
    expect(second.audit).to be_compliant
    expect(second.status).to eq(:noop)
  end

  it "replaces a wrong port while retaining unmanaged facility and filter attributes" do
    input = "sysname LAB\ninfo-center loghost 192.0.2.20 port 514 facility local6 filter OPS\n"
    engine = service("syslog.destinations" => { "expected" => [ destination("192.0.2.20") ], "managed_scopes" => [ { "vrf" => "default" } ] })
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "system-view", "undo info-center loghost 192.0.2.20",
      "info-center loghost 192.0.2.20 port 1514 facility local6 filter OPS", "return" ])
    expect(plan.operations.first.action).to eq(:replace)
    after = H3cConfigurationState.new(input).apply(plan.configuration_commands).configuration
    expect(run_plan(engine, after).status).to eq(:noop)
  end

  it "does not guess a VPN for legacy address-only approval" do
    engine = service("syslog.servers" => { "expected" => [ "192.0.2.40" ] })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost vpn-instance OPS 192.0.2.30\n")
    expect(plan.status).to eq(:blocked)
    expect(plan.checks.first.reason).to eq(:approved_scope_required)
    expect(plan.operations).to be_empty
  end

  it "keeps all affected checks blocked for contradictory address and object approvals" do
    engine = service("syslog.servers" => { "expected" => [ "192.0.2.20" ] },
      "syslog.destinations" => { "expected" => [ destination("192.0.2.40") ], "managed_scopes" => [ { "vrf" => "default" } ] })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.30\n")
    expect(plan.checks.map(&:reason)).to eq([ :policy_conflict, :policy_conflict ])
    expect(plan.operations).to be_empty
  end

  it "does not break a passing address check or minimum-server rule to satisfy object approval" do
    [ { "syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.30] } },
      { "syslog.minimum_servers" => { "expected" => 2 } } ].each do |other|
      engine = service(other.merge("syslog.destinations" => { "expected" => [ destination("192.0.2.20") ], "managed_scopes" => [ { "vrf" => "default" } ] }))
      plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\ninfo-center loghost 192.0.2.30\n")
      expect(plan.checks.last.reason).to eq(:policy_conflict)
      expect(plan.operations).to be_empty
    end
  end

  it "shares one compatible operation set across count, address and structured rules" do
    checks = { "syslog.minimum_servers" => { "expected" => 2 }, "syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.40] },
      "syslog.destinations" => { "expected" => [ destination("192.0.2.20"), destination("192.0.2.40") ], "managed_scopes" => [ { "vrf" => "default" } ] } }
    engine = service(checks)
    input = "sysname LAB\ninfo-center loghost 192.0.2.20 port 514 facility local6\n"
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    expect(plan.checks.map(&:status)).to eq([ :planned, :planned, :planned ])
    expect(plan.operations.size).to eq(2)
    expect(plan.checks.map(&:operation_ids).uniq.size).to eq(1)
    expect(plan.configuration_commands.count("info-center loghost 192.0.2.40 port 1514")).to eq(1)
    expect(plan.configuration_commands).not_to include("info-center loghost 192.0.2.40")
    after = H3cConfigurationState.new(input).apply(plan.configuration_commands).configuration
    expect(run_plan(engine, after).status).to eq(:noop)
  end

  it "requires target addresses to repair server counts instead of inventing them" do
    engine = service("syslog.minimum_servers" => { "expected" => 2 })
    plan = run_plan(engine, "sysname LAB\n")
    expect(plan.checks.first.reason).to eq(:approved_targets_required)
    expect(plan.configuration_commands).to be_empty
  end

  it "keeps invalid and unsupported targets atomic without leaking unknown options" do
    engine = service("syslog.servers" => { "expected" => %W[192.0.2.40 invalid\ncommand] })
    expect(run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\n").operations).to be_empty
    engine = service("syslog.servers" => { "expected" => [ "192.0.2.40" ] })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20 unknown PRIVATE-OPTION\n")
    expect(plan.checks.first.reason).to eq(:resource_unresolved)
    expect(plan.operations).to be_empty
  end

  it "requires explicit managed scopes for structured object commands" do
    engine = service("syslog.destinations" => { "expected" => [ destination("192.0.2.20") ] })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20 port 514\n")
    expect(plan.checks.first.reason).to eq(:approved_scope_required)
    expect(plan.operations).to be_empty
  end

  it "retains the known UDP transport default after creating a structured target" do
    object = destination("192.0.2.20")
    object["attributes"]["protocol"] = "udp"
    engine = service("syslog.destinations" => { "expected" => [ object ], "managed_scopes" => [ { "vrf" => "default" } ] })
    input = "sysname LAB\n"
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    after = H3cConfigurationState.new(input).apply(plan.configuration_commands).configuration
    expect(run_plan(engine, after).status).to eq(:noop)
  end

  it "does not confuse an explicit VPN named default with the public routing domain" do
    engine = service("syslog.servers" => { "expected" => [ "192.0.2.40" ] })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost vpn-instance default 192.0.2.20\n")
    expect(plan.status).to eq(:blocked)
    expect(plan.operations).to be_empty
  end

  it "rejects reserved CLI keywords masquerading as approved DNS server names" do
    %w[source source-port vpn-instance ipv6 domain].each do |address|
      engine = service("syslog.servers" => { "expected" => [ address ] })
      plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\n")
      expect(plan.status).to eq(:blocked)
      expect(plan.operations).to be_empty
    end
  end

  it "requires capacity evidence before adding a target" do
    engine = service({ "syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.40] } }, capacity: nil)
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\n")
    expect(plan.checks.first.reason).to eq(:capacity_confirmation_required)
    expect(plan.operations).to be_empty
  end

  it "uses observed occupancy as a conservative lower bound for a pure swap without inventing a maximum" do
    engine = service({ "syslog.servers" => { "expected" => [ "192.0.2.40" ] } }, capacity: nil)
    input = "sysname LAB\ninfo-center loghost 192.0.2.20\n"
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    expect(plan.checks.first.details).to include(capacity_source: :observed_occupancy, capacity_lower_bound: 1, early_removals: 1)
    expect(plan.checks.first.details).not_to have_key(:maximum_targets)
    after = H3cConfigurationState.new(input, maximum_targets: 1).apply(plan.configuration_commands).configuration
    expect(run_plan(engine, after).status).to eq(:noop)
  end

  it "frees a wrong target first when the confirmed capacity is full" do
    input = "sysname LAB\n" + [ 20, 21, 22, 30 ].map { |last| "info-center loghost 192.0.2.#{last}\n" }.join
    engine = service("syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.21 192.0.2.22 192.0.2.40] })
    plan = run_plan(engine, input)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "system-view", "undo info-center loghost 192.0.2.30", "info-center loghost 192.0.2.40", "return" ])
    expect(plan.operations.first.phase).to eq(:prepare)
    expect(plan.operations.first.risk).to eq("high")
    expect(plan.checks.first.details).to include(maximum_targets: 4, early_removals: 1, capacity_source: :policy)
    expect(plan.to_text).to include("maximum_targets", "early_removals")
    after = H3cConfigurationState.new(input).apply(plan.configuration_commands).configuration
    expect(run_plan(engine, after).status).to eq(:noop)
  end

  it "withholds desired sets larger than the confirmed capacity" do
    engine = service({ "syslog.servers" => { "expected" => %w[192.0.2.20 192.0.2.40 192.0.2.41] } }, capacity: 2)
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\n")
    expect(plan.checks.first.reason).to eq(:capacity_exceeded)
    expect(plan.operations).to be_empty
  end

  it "honors an explicit remove-first policy and exposes its order" do
    engine = service("syslog.servers" => { "expected" => [ "192.0.2.40" ], "remediation" => { "order" => "remove_before_add" } })
    plan = run_plan(engine, "sysname LAB\ninfo-center loghost 192.0.2.20\n")
    expect(plan.configuration_commands).to eq([ "system-view", "undo info-center loghost 192.0.2.20", "info-center loghost 192.0.2.40", "return" ])
    expect(plan.checks.first.details).to include(order: "remove_before_add", early_removals: 1)
  end

  it "rejects invalid capacity and order parameters at policy construction" do
    [ { "maximum_targets" => 0 }, { "maximum_targets" => true }, { "maximum_targets" => "4" },
      { "order" => "guess" }, { "secret" => "PRIVATE" } ].each do |options|
      expect do
        Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [], "remediation" => options } })
      end.to raise_error(ArgumentError)
    end
  end
end

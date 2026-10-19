# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "PAN-OS Syslog definition and usage evidence" do
  let(:definition) { "set deviceconfig system hostname LAB\nset shared log-settings syslog LOGS server FIRST server 192.0.2.20\n" }

  def object(bindings = :omitted)
    value = { "identity" => { "name" => "FIRST" }, "scope" => { "profile" => "LOGS" } }
    value["bindings"] = bindings unless bindings == :omitted
    value
  end

  def device_binding
    { "kind" => "syslog.device", "log_type" => "system", "match" => "ALL" }
  end

  def forwarding_binding
    { "kind" => "syslog.forwarding", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic",
      "context" => "local", "rulebase" => "security", "rule" => "ALLOW" }
  end

  def audit(text, expected = object, complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => { "expected" => [ expected ] } })
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: :palo_alto, complete: complete)
  end

  it "inventories reference membership separately from server objects and receiver-independent consumers" do
    text = definition + "set shared log-settings system match-list ALL send-syslog [ OTHER LOGS ]\n" \
      "set shared log-settings system match-list ALL filter PRIVATE-FILTER\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC filter PRIVATE-ACTION\n" \
      "set rulebase security rules ALLOW log-setting FORWARD\nset zone INSIDE network log-setting FORWARD\n"
    evidence = audit(text).configuration
    expect(evidence.fact_known?("syslog.reference_sets")).to be(true)
    rows = evidence.fact("syslog.reference_sets")
    direct = rows.find { |row| row["identity"] == device_binding }
    expect(direct["profiles"]).to eq(%w[LOGS OTHER])
    expect(direct["consumers"]).to eq([ device_binding ])
    forward = rows.find { |row| row["identity"]["kind"] == "syslog.forwarding" }
    expect(forward["identity"]).to eq(forwarding_binding.slice("kind", "forwarding_profile", "match", "log_type"))
    expect(forward["profiles"]).to eq([])
    expect(forward["consumers"]).to contain_exactly(forwarding_binding,
      { "kind" => "syslog.zone", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic", "context" => "local", "zone" => "INSIDE" })
    expect(rows.to_s).not_to include("PRIVATE-FILTER", "PRIVATE-ACTION")
    expect(rows).to be_frozen
  end

  it "keeps partial and unsupported reference-set inventory unknown" do
    text = definition + "set shared log-settings system match-list ALL send-syslog LOGS\n"
    expect(audit(text, complete: false).configuration.fact_known?("syslog.reference_sets")).to be(false)
    expect(audit(text + "set log-settings system match-list ALL send-syslog LOGS\n").configuration.fact_known?("syslog.reference_sets")).to be(false)
  end

  it "keeps definitions without usage explicit and can require a device log reference" do
    expect(audit(definition).findings.first.details[:verification_scope]).to eq(:objects_only)
    result = audit(definition, object([ device_binding ]))
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details[:binding_differences].first[:missing]).to eq([ device_binding ])
    linked = definition + "set shared log-settings system match-list ALL send-syslog LOGS\n"
    expect(audit(linked, object([ device_binding ]))).to be_compliant
  end

  it "follows forwarding profiles through selected security rules and preserves explicit logging flags" do
    text = definition + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog [ LOGS OTHER ]\n" \
      "set rulebase security rules ALLOW log-setting FORWARD\nset rulebase security rules ALLOW log-end yes\n"
    expected = forwarding_binding.merge("log_end" => true)
    result = audit(text, object([ expected ]))
    expect(result).to be_compliant
    expect(result.configuration.resources.first.bindings).to eq([ expected ])
    absent_flag = audit(text.sub(" log-end yes", " log-end no"), object([ expected ]))
    expect(absent_flag.findings.first.status).to eq(:fail)
    unknown_flag = audit(text.lines.reject { |line| line.include?("log-end") }.join, object([ expected ]))
    expect(unknown_flag.findings.first.status).to eq(:unknown)
  end

  it "does not treat an unused forwarding profile as an attached output path" do
    text = definition + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS\n"
    expect(audit(text, object([ forwarding_binding ])).findings.first.status).to eq(:fail)
    expect(audit(text, object([]))).to be_compliant
  end

  it "keeps final rule selection and exact profile name identity across distinct virtual systems" do
    text = definition + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS\n" \
      "set shared log-settings profiles EMPTY match-list NONE log-type traffic\n" \
      "set vsys BLUE rulebase security rules ALLOW log-setting FORWARD\n" \
      "set vsys RED rulebase security rules ALLOW log-setting FORWARD\n" \
      "set vsys BLUE rulebase security rules ALLOW log-setting EMPTY\n"
    expected = forwarding_binding.merge("context" => "vsys", "vsys" => "RED")
    expect(audit(text, object([ expected ]))).to be_compliant
    wrong_case = text.sub("send-syslog LOGS", "send-syslog logs")
    expect(audit(wrong_case, object([ expected ])).findings.first.status).to eq(:fail)
  end

  it "retains unresolved or unsupported reference syntax without exporting filter or secret tails" do
    text = definition + "set shared log-settings system match-list ALL filter 'PRIVATE-FILTER'\n" \
      "set shared log-settings system match-list ALL send-syslog [ LOGS\n"
    result = audit(text, object([]))
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.resources.first.bindings).to be_nil
    expect(result.configuration.facts.to_s).not_to include("PRIVATE-FILTER")
    issue = result.configuration.issues.find { |entry| entry[:code] == :syslog_reference_inventory_unresolved }
    expect(issue[:lines]).to include(4)
    template = definition + "set template TEMPLATE config shared log-settings system match-list ALL send-syslog LOGS\n"
    expect(audit(template, object([])).findings.first.status).to eq(:unknown)
    expect(audit(definition, object([]), complete: false).findings.first.status).to eq(:unknown)
    multiline = definition + "set shared log-settings system match-list ALL send-syslog \"LOGS\n\"\n"
    expect(audit(multiline, object([])).findings.first.status).to eq(:unknown)
  end

  it "rejects duplicate or unsafe binding identities and advertises conditional binding evidence" do
    [ device_binding.merge("match" => "ALL\ncommit"), forwarding_binding.merge("raw_filter" => "PRIVATE"),
      forwarding_binding.merge("log_end" => "yes"), device_binding.merge("log_type" => "arbitrary") ].each do |binding|
      expect { audit(definition, object([ binding ])) }.to raise_error(ArgumentError)
    end
    expect { audit(definition, object([ device_binding, device_binding ])) }.to raise_error(ArgumentError)
    expect(Baseline::Audit.capabilities(platform: :palo_alto)["syslog.destinations"][:bindings]).to include(
      status: :conditional, kinds: %w[syslog.device syslog.forwarding syslog.zone])
  end

  it "does not prove absent references after a malformed or unmodelled reference family" do
    [ "set shared log-settings system send-syslog LOGS", "set shared log-settings system match-list ALL send-syslog LOGS extra",
      "set shared log-settings alarm high syslog LOGS" ].each do |line|
      expect(audit(definition + line + "\n", object([])).findings.first.status).to eq(:unknown)
    end
  end

  it "returns concrete binding prerequisites rather than treating a missing usage chain as an object-only fix" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
      "expected" => [ object([ device_binding ]) ], "managed_scopes" => [ { "profile" => "LOGS" } ] } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: definition, platform: :palo_alto, complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:resource_binding_changes_required)
    expect(result.checks.first.requirements).to include("approved_log_forwarding_binding_scope", "preserved_log_filters")
    expect(result.configuration_commands).to be_empty
  end

  it "preserves quoted native names rather than folding or splitting their identities" do
    text = definition.sub("syslog LOGS", 'syslog "Log Servers"') +
      "set shared log-settings system match-list \"All Logs\" send-syslog \"Log Servers\"\n"
    expected = object([ device_binding.merge("match" => "All Logs") ])
    expected["scope"]["profile"] = "Log Servers"
    result = audit(text, expected)
    expect(result).to be_compliant
    resource = result.configuration.resources.first
    expect(resource.bindings.first["match"]).to eq("All Logs")
    expect(resource.bindings.first["match"]).to be_frozen
  end

  it "does not confuse a firewall's Panorama management address with inherited templates" do
    text = definition + "set shared log-settings system match-list ALL send-syslog LOGS\n" \
      "set deviceconfig system panorama local-panorama panorama-server 192.0.2.100\n"
    expect(audit(text, object([ device_binding ]))).to be_compliant
  end

  it "does not let unrelated NAT or PBF disabled flags invent an unresolved forwarding reference" do
    text = definition + "set shared log-settings system match-list ALL send-syslog LOGS\n" \
      "set rulebase nat rules NAT disabled no\nset rulebase pbf rules ROUTE disabled yes\n"
    expect(audit(text, object([ device_binding ]))).to be_compliant
    expect(audit(text + "set rulebase pbf rules ROUTE log-setting FORWARD\n", object([])).findings.first.status).to eq(:unknown)
  end

  it "keeps implicit CLI context distinct from an explicitly named virtual system" do
    text = definition + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS\n" \
      "set rulebase security rules ALLOW log-setting FORWARD\nset vsys local rulebase security rules ALLOW log-setting FORWARD\n"
    bindings = audit(text).configuration.resources.first.bindings
    expect(bindings.size).to eq(2)
  end

  it "includes zone consumers and their final forwarding profile without requiring a policy rule" do
    text = definition + "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
      "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS\n" \
      "set zone INSIDE network log-setting FORWARD\n"
    expected = { "kind" => "syslog.zone", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic",
      "context" => "local", "zone" => "INSIDE" }
    expect(audit(text, object([])).findings.first.status).to eq(:fail)
    expect(audit(text, object([ expected ]))).to be_compliant
    explicit = text.sub("set zone INSIDE", "set vsys BLUE zone INSIDE")
    expect(audit(explicit, object([ expected.merge("context" => "vsys", "vsys" => "BLUE") ]))).to be_compliant
    malformed = text + "set zone INSIDE network log-setting FORWARD extra\n"
    expect(audit(malformed, object([])).findings.first.status).to eq(:unknown)
  end
end

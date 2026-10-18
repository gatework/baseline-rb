# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"
require "tempfile"

RSpec.describe Baseline::Policy do
  def policy(expected)
    described_class.new("version" => 1, "checks" => { "ntp.servers" => { "expected" => expected } })
  end

  it "names SNMP write permission with the same boolean meaning as its fact" do
    policy = described_class.new("version" => 1, "checks" => { "snmp.write_enabled" => { "expected" => false } })
    audit = Baseline::Audit.new(policy: policy)
    { "read" => :pass, "write" => :fail }.each do |permission, status|
      report = audit.call(platform: "h3c", complete: true,
        configuration: "sysname LAB\nsnmp-agent community #{permission} cipher SYNTHETIC\nreturn\n")
      expect(report.findings.first.status).to eq(status)
    end
    expect { described_class.new("version" => 1, "checks" => { "snmp.read_only" => { "expected" => true } }) }.to raise_error(ArgumentError)
  end

  it "selects approved values by host, model, site, role and vendor in order" do
    selectors = %w[host model site role vendor].to_h { |name| [ "by_#{name}", { "selected" => [ name ] } ] }
    definition = policy(selectors.merge("default" => [ "fallback" ]))
    context = %w[host model site role vendor].to_h { |name| [ name, "selected" ] }
    context.each_key do |scope|
      expect(definition.resolve(definition.rules.first, context)).to eq([ [ scope ], nil ])
      context[scope] = "unmatched"
    end
    expect(definition.resolve(definition.rules.first, context)).to eq([ [ "fallback" ], nil ])
  end

  it "keeps missing context and explicitly missing approved values unknown" do
    definition = policy("by_site" => { "HQ" => [ "192.0.2.1" ] }, "default" => [ "192.0.2.2" ])
    expect(definition.resolve(definition.rules.first, {})).to eq([ nil, :scope_unknown ])
    definition = policy("by_host" => { "192.0.2.1" => nil }, "default" => [ "192.0.2.2" ])
    expect(definition.resolve(definition.rules.first, { "host" => "192.0.2.1" })).to eq([ nil, :policy_missing ])
  end

  it "supports nested selectors and freezes policy values without freezing caller data" do
    input = { "by_vendor" => { "h3c" => { "by_role" => { "access" => [ "192.0.2.1" ] } } } }
    definition = policy(input)
    expect(definition.resolve(definition.rules.first, { "vendor" => "h3c", "role" => "access" })).to eq([ [ "192.0.2.1" ], nil ])
    input["by_vendor"].clear
    expect(definition.rules.first.expected.fetch("by_vendor").keys).to eq([ "h3c" ])
    expect { definition.rules.first.expected["new"] = true }.to raise_error(FrozenError)
  end

  it "explains the selected branch while preserving the two-value resolution interface" do
    definition = policy("by_vendor" => { "h3c" => { "by_site" => { "HQ" => [ "192.0.2.1" ] }, "default" => [ "192.0.2.2" ] } })
    rule = definition.rules.first
    selected = definition.resolve_with_path(rule, { "vendor" => "h3c", "site" => "HQ" })
    expect(selected.to_h).to eq(value: [ "192.0.2.1" ], reason: nil, path: %w[by_vendor h3c by_site HQ])
    fallback = definition.resolve_with_path(rule, { "vendor" => "h3c", "site" => "branch" })
    expect(fallback.to_h).to eq(value: [ "192.0.2.2" ], reason: nil, path: %w[by_vendor h3c default])
    expect(definition.resolve(rule, { "vendor" => "h3c", "site" => "branch" })).to eq([ fallback.value, fallback.reason ])
    expect { selected.path << "default" }.to raise_error(FrozenError)
    expect { selected.value.first.replace("changed") }.to raise_error(FrozenError)
  end

  it "distinguishes an unresolved selector, an explicitly missing value and an absent branch" do
    definition = policy("by_site" => { "HQ" => nil }, "default" => [ "192.0.2.1" ])
    rule = definition.rules.first
    expect(definition.resolve_with_path(rule, {}).to_h).to eq(value: nil, reason: :scope_unknown, path: [ "by_site" ])
    expect(definition.resolve_with_path(rule, { "site" => "HQ" }).to_h).to eq(value: nil, reason: :policy_missing, path: %w[by_site HQ])
    definition = policy("by_site" => { "HQ" => [ "192.0.2.1" ] })
    expect(definition.resolve_with_path(definition.rules.first, { "site" => "branch" }).to_h).to eq(value: nil, reason: :policy_missing, path: [])
    definition = policy(nil)
    expect(definition.resolve_with_path(definition.rules.first, {}).to_h).to eq(value: nil, reason: :policy_missing, path: [])
  end

  it "keeps false approved values and caller context distinct from a missing selection" do
    definition = described_class.new("version" => 1, "checks" => {
      "ssh.enabled" => { "expected" => { "by_site" => { "lab" => false }, "default" => true } }
    })
    site = +"lab"
    resolution = definition.resolve_with_path(definition.rules.first, { "site" => site })
    site.replace("HQ")
    expect(resolution.to_h).to eq(value: false, reason: nil, path: %w[by_site lab])
  end

  it "exposes deeply immutable named definitions without freezing caller-owned metadata" do
    definition = Baseline::Rule::DEFINITIONS.fetch("snmp.versions")
    expect(definition.to_h).to include(fact: "snmp.versions", operator: :subset, value_type: :enum_set, allowed_values: %w[v1 v2c v3])
    expect { definition.allowed_values << "v7" }.to raise_error(FrozenError)
    expect { definition.allowed_values.first.replace("v7") }.to raise_error(FrozenError)
    expect { definition.title.replace("Changed") }.to raise_error(FrozenError)
    id, severity = +"ssh.enabled", +"high"
    rule = Baseline::Rule.new(id, "expected" => true, "severity" => severity)
    id.replace("changed")
    severity.replace("changed")
    expect([ rule.id, rule.severity, rule.value_type ]).to eq([ "ssh.enabled", "high", :boolean ])
  end

  it "rejects malformed context scopes before they can exclude failing checks" do
    [ [], [ [ "h3c" ] ], true, [ true ], 1, " ", [ "h3c", " " ], nil ].each do |criterion|
      checks = { "ssh.enabled" => { "expected" => true },
        "ntp.minimum_servers" => { "expected" => 2, "applies_to" => { "vendor" => criterion } } }
      expect do
        audit = Baseline::Audit.new(policy: described_class.new("version" => 1, "checks" => checks))
        audit.call(configuration: "sysname LAB\nssh server enable\n", platform: "h3c", complete: true)
      end.to raise_error(ArgumentError, /applicability/)
    end
  end

  it "rejects unsupported fact names, collection predicates and mismatched scalar conditions" do
    [ {}, { "snmp.enabld" => true }, { " " => true }, { "snmp.versions" => [ "v3" ] },
      { "snmp.enabled" => [] }, { "snmp.enabled" => [ [ true ] ] }, { "snmp.enabled" => "false" },
      { "snmp.enabled" => 0 }, { "hostname" => true }, { "hostname" => [ " " ] } ].each do |facts|
      expect do
        described_class.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => true, "applies_to" => { "facts" => facts } } })
      end.to raise_error(ArgumentError, /applicability/)
    end
  end

  it "matches supported scalar alternatives and false facts without excluding a failing check" do
    definition = described_class.new("version" => 1, "checks" => {
      "ntp.minimum_servers" => { "expected" => 2, "applies_to" => {
        "vendor" => %w[h3c huawei], "facts" => { "snmp.enabled" => false, "hostname" => %w[LAB BRANCH] }
      } }
    })
    report = Baseline::Audit.new(policy: definition).call(configuration: "sysname LAB\n", platform: "h3c", complete: true)
    expect(report.findings.first.status).to eq(:fail)
    expect(report).not_to be_compliant
  end

  it "rejects invalid protocol and service sets while preserving deliberate empty server sets" do
    [ [ "snmp.versions", [] ], [ "snmp.versions", [ "v7" ] ], [ "ssh.versions", [ "3" ] ],
      [ "ssh.versions", [] ], [ "services.disabled", [] ], [ "services.disabled", [ "telnet", "telnet" ] ],
      [ "ntp.source", " " ], [ "ntp.servers", [ " " ] ] ].each do |id, expected|
      expect do
        described_class.new("version" => 1, "checks" => { id => { "expected" => expected } })
      end.to raise_error(ArgumentError, /expected value/)
    end
    report = Baseline::Audit.new(policy: policy([])).call(configuration: "sysname LAB\n", platform: "h3c", complete: true)
    expect(report).to be_compliant
  end

  it "rejects unknown rules, invalid options, values and selector shapes" do
    [ { "ntp.unknown" => {} }, { "ntp.servers" => { "unexpected" => true } },
      { "ssh.enabled" => { "expected" => "true" } }, { "ntp.minimum_servers" => { "expected" => 0 } },
      { "services.disabled" => { "expected" => [ "invented" ] } },
      { "management.sources" => { "expected" => [ "::/0" ] } },
      { "ntp.servers" => { "expected" => { "by_site" => [ "HQ" ] } } },
      { "ntp.servers" => { "expected" => { "by_site" => {} } } },
      { "ntp.servers" => { "expected" => { "by_site" => { " " => [] } } } },
      { "ntp.servers" => { "enabled" => "false" } } ].each do |checks|
      expect { described_class.new("version" => 1, "checks" => checks) }.to raise_error(ArgumentError)
    end
  end

  it "loads one safe YAML document and rejects duplicate keys and aliases" do
    invalid = [ "version: 1\nchecks: {}\n---\nversion: 1\nchecks: {}\n",
      "version: 1\nversion: 1\nchecks: {}\n",
      "version: 1\nchecks:\n  ntp.servers: {expected: [a], expected: [b]}\n",
      "version: 1\nchecks: &checks\n  ntp.servers: {expected: *checks}\n",
      "version: 1.0\nchecks:\n  ssh.enabled: {expected: true}\n",
      "version: 1\nchecks:\n  ntp.minimum_servers: {expected: 2, applies_to: {vendor: []}}\n",
      "version: 1\nchecks:\n  snmp.versions: {expected: [v7]}\n",
      "--- !ruby/object:Object {}\n" ]
    invalid.each do |content|
      Tempfile.create("baseline-policy") do |file|
        file.write(content)
        file.flush
        expect { described_class.load(file.path) }.to raise_error(ArgumentError)
      end
    end
    expect(described_class.default.rules.size).to eq(30)
  end
end

# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

source = "sysname LAB\nsnmp-agent\nsnmp-agent group v3 OPS privacy read-view READ write-view WRITE notify-view NOTIFY\n" \
  "snmp-agent usm-user v3 observer OPS authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n" \
  "snmp-agent community write cipher SYNTHETIC-COMMUNITY\n"
policy = Baseline::Policy.new("version" => 1, "checks" => { "snmp.write_enabled" => { "expected" => false } })
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: "h3c", complete: true)
raise "Unexpected permission execution" unless plan.status == :blocked && plan.configuration_commands.empty?
grants = plan.checks.first.details.fetch(:permission_grants)
raise "Missing write grant" unless grants.any? { |grant| grant[:kind] == "snmp.group" && grant[:name] == "OPS" && grant[:action] == "revoke_write" }
raise "Community identity exposed" unless grants.any? { |grant| grant[:kind] == "snmp.community" && grant[:name] == "community:1" }
raise "Secret exported" if %w[SYNTHETIC-AUTH SYNTHETIC-PRIV SYNTHETIC-COMMUNITY].any? { |secret| plan.to_h.to_s.include?(secret) }
puts plan.to_text

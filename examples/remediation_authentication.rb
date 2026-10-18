# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.login" => { "expected" => true } })
source = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\n" \
  "domain ADMIN\n authentication login local\n#\ndomain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n"
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: "h3c", complete: true)
check = plan.checks.first
raise "Candidate group was selected without approval" unless plan.status == :blocked && plan.operations.empty? && plan.configuration_commands.empty?
raise "Missing domain evidence" unless check.details.fetch(:bindings).first[:domain] == "ADMIN"
raise "Missing candidate group evidence" unless check.details.fetch(:available_groups).first[:name] == "OPS"
raise "Missing fallback requirement" unless check.requirements.include?("local_fallback_access_verified")
puts plan.to_text

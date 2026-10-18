# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.keys" => { "expected" => true } })
source = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n" \
  " primary authorization 192.0.2.31\n primary accounting 192.0.2.32\n key authentication cipher SYNTHETIC-AUTH\n"
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: "h3c", complete: true)
raise "Unexpected secret execution plan" unless plan.status == :blocked && plan.operations.empty? && plan.configuration_commands.empty?
slots = plan.checks.first.details.fetch(:key_slots)
raise "Missing key roles" unless slots.map { |slot| slot[:role] } == %w[authorization accounting]
raise "Secret exposed" if plan.to_h.to_s.include?("SYNTHETIC-AUTH")
puts plan.to_text

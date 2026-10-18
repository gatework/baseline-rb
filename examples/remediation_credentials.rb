# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

policy = Baseline::Policy.new("version" => 1, "checks" => {
  "credentials.storage" => { "expected" => true },
  "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } }
})
# 仅使用合成材料；普通审核方案只记录对象身份、偏差及轮换前提。
source = "sysname LAB\nlocal-user observer class manage\n password simple SYNTHETIC-WEAK\n#\n" \
  "local-user operator class manage\n password cipher SYNTHETIC-CIPHER\n"
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: "h3c", complete: true)
raise "Unexpected executable credential plan" unless plan.status == :blocked && plan.operations.empty? && plan.configuration_commands.empty?
raise "Missing object requirements" unless plan.checks.all? { |check| check.details.fetch(:credentials).any? }
raise "Secret exposed" if plan.to_h.to_s.include?("SYNTHETIC-WEAK") || plan.to_text.include?("SYNTHETIC-CIPHER")
puts plan.to_text

# frozen_string_literal: true

require "baseline"

# 版本及外部核验均为合成示例，密钥只存在于输入，不进入生成命令。
source = <<~CONFIG
  sysname LAB
  snmp-agent
  snmp-agent group v3 OPS privacy read-view READ write-view WRITE notify-view NOTIFY acl 2000
  snmp-agent usm-user v3 observer group OPS
  snmp-agent usm-user v3 observer authentication-mode sha cipher SYNTHETIC-AUTH
  snmp-agent usm-user v3 observer privacy-mode aes128 cipher SYNTHETIC-PRIV
CONFIG
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "snmp.write_enabled" => { "expected" => false, "remediation" => {
    "syntax_profile" => "vrp_v600", "snmp_group_migration_verified" => true,
    "available_group_slots" => 1,
    "snmp_user_group_transition_verified" => true,
    "group_migrations" => [ { "from_group" => "OPS", "to_group" => "OPS_READ", "users" => [ "observer" ] } ]
  } }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: :huawei, complete: true)
abort "Expected complete read-only group migration" unless plan.status == :ready && plan.operations.size == 3
abort "Secret exposed" if %w[SYNTHETIC-AUTH SYNTHETIC-PRIV].any? { |value| plan.to_h.to_s.include?(value) }
puts plan.to_text

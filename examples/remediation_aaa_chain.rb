# frozen_string_literal: true

require "baseline"

# 仅生成待人工审核命令；示例材料是合成输入，既不导出也不改写密钥。
configuration = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n" \
  " key authentication cipher SYNTHETIC-ONLY\n#\ndomain ADMIN\n authentication login local\n#\n" \
  "domain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n"
policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.login" => {
  "expected" => true, "remediation" => { "management_domain" => "ADMIN", "syntax_profile" => "comware7",
    "methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ],
    "management_consumers_verified" => true, "local_fallback_access_verified" => true, "tacacs_peer_compatibility_verified" => true }
} })
plan = Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: :h3c, complete: true)
raise "Expected approved login-chain plan" unless plan.status == :ready && plan.configuration_commands.include?("authentication login hwtacacs-scheme OPS local")
raise "Unexpected secret output" if plan.to_h.to_s.include?("SYNTHETIC-ONLY")
puts plan.to_text

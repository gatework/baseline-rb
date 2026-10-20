# frozen_string_literal: true

require "baseline"

# 全部身份、材料及批准均为合成示例；只生成待人工审核命令，不访问设备。
configuration = "hostname LAB\nfeature tacacs+\nno feature telnet\n" \
  "tacacs-server host 192.0.2.30 key 7 SYNTHETIC-ONLY\n" \
  "aaa group server tacacs+ OPS\n server 192.0.2.30\n use-vrf management\n!\n" \
  "aaa authentication login default none\nno aaa authentication login default fallback error local\n" \
  "aaa authentication login console local\naaa authorization commands default local\n" \
  "aaa authorization config-commands default local\naaa accounting default local\nline vty\n!\n"
checks = %w[tacacs.login tacacs.authorization tacacs.accounting ssh.vty_aaa].to_h do |id|
  methods = [ { "kind" => "tacacs", "group" => "OPS" } ]
  methods << { "kind" => "local" } if id == "tacacs.authorization"
  options = { "syntax_profile" => "nxos", "methods" => methods,
    "local_fallback_access_verified" => true, "management_consumers_verified" => true, "tacacs_peer_compatibility_verified" => true }
  options["local_fallback_on_error"] = true if %w[tacacs.login ssh.vty_aaa].include?(id)
  [ id, { "expected" => true, "remediation" => options } ]
end
policy = Baseline::Policy.new("version" => 1, "checks" => checks)
plan = Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: :cisco_nxos, complete: true)
raise "Expected native management-role corrections" unless plan.status == :ready && plan.operations.size == 4
raise "Unexpected secret output" if plan.to_h.to_s.include?("SYNTHETIC-ONLY")
puts plan.to_text

# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

# 合成配置；真实恢复访问和对端密钥兼容必须由人工在外部核实。
source = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30 49\n" \
  " secondary authentication 192.0.2.31 49\n key authentication cipher SYNTHETIC-KEY\n#\n" \
  "domain ADMIN\n authentication login hwtacacs-scheme OPS local\n#\ndomain default enable ADMIN\n" \
  "line vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n"
targets = [ [ "192.0.2.32", "primary" ], [ "192.0.2.31", "secondary" ] ].map do |address, priority|
  { "identity" => { "address" => address, "role" => "authentication", "priority" => priority },
    "scope" => { "group" => "OPS", "vrf" => "default" } }
end
policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => {
  "expected" => targets, "managed_scopes" => [ { "group" => "OPS", "vrf" => "default" } ],
  "remediation" => { "syntax_profile" => "comware7", "local_fallback_access_verified" => true, "tacacs_key_compatibility_verified" => true }
} })
service = Baseline::Remediation.new(policy: policy)
plan = service.call(configuration: source, platform: "h3c", complete: true)
raise "Missing native slot replacement" unless plan.status == :ready && plan.configuration_commands.include?("primary authentication 192.0.2.32 49")
raise "Secret exposed" if plan.to_h.to_s.include?("SYNTHETIC-KEY")
after = source.sub("primary authentication 192.0.2.30", "primary authentication 192.0.2.32")
raise "Not converged" unless service.call(configuration: after, platform: "h3c", complete: true).status == :noop
puts plan.to_text

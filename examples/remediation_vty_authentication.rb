# frozen_string_literal: true

require "baseline"

# 只生成审核产物；账户、消费者和恢复批准由外部验证提供，不生成材料。
configuration = "sysname LAB\nssh server enable\ndomain ADMIN\n authentication login local\n#\n" \
  "domain default enable ADMIN\nline vty 0 4\n authentication-mode password\n protocol inbound all\n#\n"
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ssh.vty_aaa" => { "expected" => true, "remediation" => { "management_domain" => "ADMIN", "methods" => [ { "kind" => "local" } ],
    "syntax_profile" => "comware7", "vty_ranges" => [ "line vty 0 4" ],
    "local_fallback_access_verified" => true, "management_consumers_verified" => true } },
  "ssh.vty_ssh_only" => { "expected" => true }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: :h3c, complete: true)
raise "Expected paired account-mode plan" unless plan.status == :ready && [ "authentication-mode scheme", "protocol inbound ssh" ].all? { |command| plan.configuration_commands.include?(command) }
raise "Expected shared operation proof" unless plan.checks.map(&:operation_ids).uniq.one?
puts plan.to_text

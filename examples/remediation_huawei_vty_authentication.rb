# frozen_string_literal: true

require "baseline"

# 仅使用既有方案，外部核验覆盖账户服务、大小写语义、所有职责及恢复路径。
configuration = "sysname LAB\nstelnet server enable\ndomain ADMIN admin\n#\naaa\n" \
  " authentication-scheme AUTH\n  authentication-mode local-case\n authorization-scheme AUTHZ\n  authorization-mode local\n" \
  " accounting-scheme ACCT\n  accounting-mode none\n domain ADMIN\n  authentication-scheme AUTH\n  authorization-scheme AUTHZ\n  accounting-scheme ACCT\n#\n" \
  "user-interface vty 0 4\n authentication-mode password\n protocol inbound all\n#\n"
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ssh.vty_aaa" => { "expected" => true, "remediation" => { "management_domain" => "ADMIN", "syntax_profile" => "vrp_s_series",
    "methods" => [ { "kind" => "local", "case_sensitive" => true } ], "vty_ranges" => [ "user-interface vty 0 4" ],
    "local_fallback_access_verified" => true, "management_consumers_verified" => true } },
  "ssh.vty_ssh_only" => { "expected" => true }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: :huawei, complete: true)
raise "Expected native Huawei account-mode plan" unless plan.status == :ready && plan.configuration_commands.include?("authentication-mode aaa")
raise "Shared AAA scheme must remain unchanged" if plan.configuration_commands.any? { |command| command.start_with?("authentication-scheme", "authentication-mode local") }
raise "AAA runtime checks are required" unless plan.review[:validation][:runtime_requirements].include?("aaa_roles_and_local_fallback")
puts plan.to_text

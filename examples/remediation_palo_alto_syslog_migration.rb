# frozen_string_literal: true

require "baseline"

# 设备日志迁移只批准既有匹配项；两个服务器对象继续保留，过滤式不进入方案。
source = <<~CONFIG
  set deviceconfig system hostname LAB
  set shared log-settings syslog OLD server SERVER server 192.0.2.10
  set shared log-settings syslog NEW server SERVER server 192.0.2.20
  set shared log-settings system match-list ALL filter 'All Logs'
  set shared log-settings system match-list ALL send-syslog OLD
CONFIG
reference = { "kind" => "syslog.device", "log_type" => "system", "match" => "ALL" }
targets = %w[OLD NEW].map do |profile|
  { "identity" => { "name" => "SERVER" }, "scope" => { "profile" => profile }, "bindings" => profile == "NEW" ? [ reference ] : [] }
end
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "syslog.destinations" => { "expected" => targets, "managed_scopes" => targets.map { |target| target["scope"] },
    "remediation" => { "binding_migrations" => [ { "from_profile" => "OLD", "to_profile" => "NEW", "reference" => reference } ] } }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: :palo_alto, complete: true)
abort "Expected reference-only review plan" unless plan.status == :ready && plan.operations.map(&:kind) == [ "syslog.reference" ]
abort "Filter leaked into review plan" if plan.configuration_commands.join.include?("All Logs")
puts plan.to_text
puts plan.configuration_commands

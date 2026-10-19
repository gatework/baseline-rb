# frozen_string_literal: true

require "baseline"

# 服务器对象与被批准的设备日志、规则转发链一起检查；不声称运行时日志已到达。
expected = { "identity" => { "name" => "FIRST" }, "scope" => { "profile" => "LOGS" }, "bindings" => [
  { "kind" => "syslog.device", "log_type" => "system", "match" => "ALL" },
  { "kind" => "syslog.forwarding", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic",
    "context" => "local", "rulebase" => "security", "rule" => "ALLOW", "log_end" => true, "disabled" => false }
] }
policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => { "expected" => [ expected ] } })
service = Baseline::Audit.new(policy: policy)
definition = "set deviceconfig system hostname LAB\nset shared log-settings syslog LOGS server FIRST server 192.0.2.20\n"
abort "Unused definition certified the output chain" if service.call(configuration: definition, platform: :palo_alto, complete: true).compliant?
configuration = definition + <<~CONFIG
  set shared log-settings system match-list ALL send-syslog LOGS
  set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic
  set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS
  set rulebase security rules ALLOW log-setting FORWARD
  set rulebase security rules ALLOW log-end yes
  set rulebase security rules ALLOW disabled no
CONFIG
report = service.call(configuration: configuration, platform: :palo_alto, complete: true)
abort "Configured Syslog references did not match" unless report.compliant?
abort "Partial evidence certified the chain" if service.call(configuration: configuration, platform: :palo_alto).compliant?
puts report.to_text

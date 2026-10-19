# frozen_string_literal: true

require "baseline"

# 只批准指定服务器的地址和端口；转发引用、自定义格式及其他叶子保留。
policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
  "expected" => [ { "identity" => { "name" => "FIRST" }, "scope" => { "profile" => "LOGS" },
    "attributes" => { "address" => "192.0.2.20", "port" => 5514 } } ],
  "managed_scopes" => [ { "profile" => "LOGS" } ], "remediation" => { "maximum_targets" => 4 }
} })
configuration = <<~CONFIG
  set deviceconfig system hostname LAB
  set shared log-settings syslog LOGS server FIRST server 192.0.2.10
  set shared log-settings syslog LOGS server FIRST transport UDP
  set shared log-settings syslog LOGS server FIRST port 514
  set shared log-settings syslog LOGS server FIRST format BSD
  set shared log-settings syslog LOGS server FIRST facility LOG_USER
  set shared log-settings syslog LOGS format system 'SYNTHETIC-FORMAT'
  set shared log-settings system match-list ALL send-syslog LOGS
CONFIG
engine = Baseline::Remediation.new(policy: policy)
plan = engine.call(configuration: configuration, platform: :palo_alto, complete: true)
expected = [ "configure", 'set shared log-settings syslog "LOGS" server "FIRST" server "192.0.2.20"',
  'set shared log-settings syslog "LOGS" server "FIRST" port 5514', "exit" ]
abort "Expected reviewed leaf updates" unless plan.status == :ready && plan.configuration_commands == expected
after = configuration.sub("server 192.0.2.10", "server 192.0.2.20").sub("port 514", "port 5514")
abort "Syslog leaf update did not converge" unless engine.call(configuration: after, platform: :palo_alto, complete: true).status == :noop
puts plan.to_text

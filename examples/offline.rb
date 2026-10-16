# frozen_string_literal: true

require "baseline"

# 批准值独立于本例的合成配置声明。
policy = Baseline::Policy.new(
  "version" => 1,
  "checks" => { "ssh.enabled" => { "expected" => true, "severity" => "high" } }
)
report = Baseline::Audit.new(policy: policy).call(
  configuration: "sysname EXAMPLE-SWITCH\nssh server enable\nreturn\n",
  platform: :h3c,
  complete: true,
  context: { host: "192.0.2.10" }
)
puts report.to_text
# 仅检查显式选择的 SSH 配置项；不据此判断设备可达性。

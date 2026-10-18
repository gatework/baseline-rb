# frozen_string_literal: true

require "baseline"

# 本例仅检查日志源接口，不代表整机全项合规，也不执行生成的命令。
policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => "LoopBack0", "severity" => "high" } })
plan = Baseline::Remediation.new(policy: policy).call(
  configuration: "sysname EXAMPLE\ninfo-center loghost source LoopBack1\n",
  platform: :h3c,
  complete: true
)
abort "Unexpected remediation result" unless plan.status == :ready && plan.requires_review?
puts plan.to_text

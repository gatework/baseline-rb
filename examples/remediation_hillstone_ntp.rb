# frozen_string_literal: true

require "baseline"

# 来源接口通过明确批准的关联和作用域规划，不从备份反推目标或路由授权。
source = <<~CONFIG
  hostname LAB
  ntp enable
  ntp server 192.0.2.10 source MGT1 prefer vrouter OPS
  ntp server 192.0.2.11 source MGT1
CONFIG
targets = [
  { "identity" => { "address" => "192.0.2.10", "role" => "server" }, "scope" => { "vrf" => "OPS" } },
  { "identity" => { "address" => "192.0.2.12", "role" => "server" }, "scope" => { "vrf" => "default" } }
]
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ntp.associations" => { "expected" => targets, "managed_scopes" => targets.map { |target| target["scope"] }, "remediation" => { "maximum_targets" => 3 } },
  "ntp.servers" => { "expected" => %w[192.0.2.10 192.0.2.12] },
  "ntp.minimum_servers" => { "expected" => 2 }, "ntp.source" => { "expected" => "MGT0" }, "ntp.authentication" => { "expected" => false }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: :hillstone, complete: true)
abort "Expected native NTP review plan" unless plan.status == :ready && plan.operations.all? { |operation| operation.kind == "ntp.server" }
puts plan.to_text

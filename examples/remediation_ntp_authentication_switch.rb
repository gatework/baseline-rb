# frozen_string_literal: true

require "baseline"

# 所有材料及外部批准均为合成演示；生成结果不包含材料，也不连接设备。
source = <<~CONFIG
  sysname LAB
  undo ntp-service authentication enable
  ntp-service authentication-keyid 7 authentication-mode hmac-sha-256 cipher SYNTHETIC-KEY
  ntp-service reliable authentication-keyid 7
  ntp-service unicast-server 192.0.2.10 vpn-instance OPS authentication-keyid 7 priority source LoopBack0
CONFIG
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ntp.authentication" => { "expected" => true, "remediation" => {
    "ntp_peer_key_compatibility_verified" => true, "ntp_association_recreation_approved" => true, "syntax_profile" => "comware7"
  } }
})
plan = Baseline::Remediation.new(policy: policy).call(configuration: source, platform: :h3c, complete: true)
abort "Expected complete guarded authentication plan" unless plan.status == :ready && plan.operations.size == 3
abort "Secret exposed" if plan.to_h.to_s.include?("SYNTHETIC-KEY")
abort "Missing temporary withdrawal warning" unless plan.checks.first.details[:temporary_association_withdrawal]
puts plan.to_text

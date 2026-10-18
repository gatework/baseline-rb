# frozen_string_literal: true

require "baseline"
require "baseline/remediation"

# 外部核验在此仅为合成假设；真实操作需先确认对端的 key ID、算法和材料相符。
source = "sysname LAB\nntp-service authentication enable\n" \
  "ntp-service authentication-keyid 7 authentication-mode md5 cipher SYNTHETIC-KEY\n" \
  "ntp-service reliable authentication-keyid 7\nntp-service unicast-server 192.0.2.10 authentication-keyid 7\n"
object = { "identity" => { "address" => "192.0.2.12", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "key_id" => 7 } }
policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
  "expected" => [ object ], "managed_scopes" => [ { "vrf" => "default" } ],
  "remediation" => { "maximum_targets" => 3, "ntp_peer_key_compatibility_verified" => true }
} })
service = Baseline::Remediation.new(policy: policy)
plan = service.call(configuration: source, platform: "h3c", complete: true)
raise "Missing authenticated association" unless plan.status == :ready && plan.configuration_commands.include?("ntp-service unicast-server 192.0.2.12 authentication-keyid 7")
raise "Secret exposed" if plan.to_h.to_s.include?("SYNTHETIC-KEY")
after = source.sub("unicast-server 192.0.2.10", "unicast-server 192.0.2.12")
raise "Not converged" unless service.call(configuration: after, platform: "h3c", complete: true).status == :noop
evidence = Baseline::Audit.new(policy: policy).call(configuration: after, platform: "h3c", complete: true).configuration
raise "Missing configuration evidence" unless evidence.fact("ntp.authentication_bindings").all? { |binding| binding[:configured_ready] == true }
puts plan.to_text

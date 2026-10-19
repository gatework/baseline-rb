# frozen_string_literal: true

require "baseline"

# 明确批准主备槽位；认证材料和设备提交均由人工负责。
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ntp.associations" => { "expected" => [
    { "identity" => { "name" => "primary-ntp-server" }, "scope" => {},
      "attributes" => { "address" => "192.0.2.30", "authenticated" => false } }
  ], "managed_scopes" => [ {} ], "remediation" => { "maximum_targets" => 2 } }
})
configuration = <<~CONFIG
  set deviceconfig system hostname LAB
  set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.10
  set deviceconfig system ntp-servers primary-ntp-server authentication-type none
CONFIG
service = Baseline::Remediation.new(policy: policy)
plan = service.call(configuration: configuration, platform: :palo_alto, complete: true)
expected = "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.30"
abort "Expected one reviewed address update" unless plan.status == :ready && plan.configuration_commands == [ "configure", expected, "exit" ]
after = configuration.sub("ntp-server-address 192.0.2.10", "ntp-server-address 192.0.2.30")
abort "Approved NTP slot did not converge" unless service.call(configuration: after, platform: :palo_alto, complete: true).status == :noop
puts plan.to_text

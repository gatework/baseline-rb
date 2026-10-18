# frozen_string_literal: true

require "baseline"

# 固件能力及来源是本例的合成批准参数，不能从设备现有地址自动推定。
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "snmp.enabled" => { "expected" => true }, "snmp.acl_bound" => { "expected" => true },
  "snmp.acl_restricted" => { "expected" => true }, "snmp.sources" => {
    "expected" => [ "192.0.2.0/24" ], "remediation" => {
      "global_acl_supported" => true,
      "access_targets" => [ { "endpoint" => "snmp.global", "acl" => "2005", "sources" => [ "192.0.2.10/32" ] } ]
    }
  }
})
configuration = "sysname EXAMPLE\nsnmp-agent\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY\n"
service = Baseline::Remediation.new(policy: policy)
plan = service.call(configuration: configuration, platform: "h3c", complete: true)
abort "Unexpected SNMP ACL plan" unless plan.status == :ready && plan.operations.map(&:phase) == %i[create update]
abort "Plan exposed a secret" if plan.to_h.to_s.include?("SYNTHETIC-COMMUNITY")
after = configuration + "acl basic 2005\n rule 5 permit source 192.0.2.10 0.0.0.0\n rule 10 deny\n#\nsnmp-agent acl 2005\n"
abort "SNMP ACL plan did not converge" unless service.call(configuration: after, platform: "h3c", complete: true).status == :noop
puts plan.to_text

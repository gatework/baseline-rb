# frozen_string_literal: true

require "baseline"

# 首次建立来源限制时，批准上限不等于应当开放的主机，必须另行声明实际目标。
cases = [
  { platform: "h3c", endpoint: "line vty 0 4", acl: "2002", header: "sysname EXAMPLE\nssh server enable",
    login: "authentication-mode scheme", protocol: "protocol inbound ssh", scope: {} },
  { platform: "huawei", endpoint: "user-interface vty 0 4", acl: "2002", header: "sysname EXAMPLE\nstelnet server enable",
    login: "authentication-mode aaa", protocol: "protocol inbound ssh", scope: {} },
  { platform: "cisco_ios", endpoint: "line vty 0 4", acl: "VTY_NEW", header: "hostname EXAMPLE\nip ssh version 2",
    login: "login local", protocol: "transport input ssh", scope: { "vrf_also" => false } }
]
cases.each do |item|
  target = { "endpoint" => item[:endpoint], "acl" => item[:acl], "sources" => [ "192.0.2.10/32" ] }.merge(item[:scope])
  policy = Baseline::Policy.new("version" => 1, "checks" => {
    "management.acl_bound" => { "expected" => true }, "management.acl_restricted" => { "expected" => true },
    "management.sources" => { "expected" => [ "192.0.2.0/24" ], "remediation" => { "access_targets" => [ target ] } }
  })
  plan = Baseline::Remediation.new(policy: policy).call(
    configuration: "#{item[:header]}\n#{item[:endpoint]}\n #{item[:login]}\n #{item[:protocol]}\n#\n",
    platform: item[:platform], complete: true
  )
  abort "Unexpected ACL remediation result" unless plan.status == :ready && plan.operations.map(&:phase) == %i[create update]
  puts "platform=#{item[:platform]}"
  puts plan.to_text
end

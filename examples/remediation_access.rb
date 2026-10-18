# frozen_string_literal: true

require "baseline"

# 首次建立来源限制时，批准上限不等于应当开放的主机，必须另行声明实际目标。
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "management.acl_bound" => { "expected" => true },
  "management.acl_restricted" => { "expected" => true },
  "management.sources" => { "expected" => [ "192.0.2.0/24" ], "remediation" => {
    "access_targets" => [ { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [ "192.0.2.10/32" ] } ]
  } }
})
plan = Baseline::Remediation.new(policy: policy).call(
  configuration: "sysname EXAMPLE\nssh server enable\nline vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n",
  platform: :h3c, complete: true
)
abort "Unexpected ACL remediation result" unless plan.status == :ready && plan.operations.map(&:phase) == %i[create update]
puts plan.to_text

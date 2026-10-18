# frozen_string_literal: true

require "baseline"

expected = { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" },
  "scope" => { "group" => "OPS" }, "bindings" => [ { "kind" => "aaa.domain", "domain" => "ADMIN", "role" => "authentication", "position" => "primary", "selected" => true } ] }
policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => { "expected" => [ expected ] } })
audit = Baseline::Audit.new(policy: policy)
before = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\ndomain ADMIN\n authentication login local\n#\ndomain default enable ADMIN\n"
raise "Definition alone certified a binding" unless audit.call(configuration: before, platform: "h3c", complete: true).findings.first.status == :fail
# 独立合成配置只验证域引用，不代表已经生成修改命令或验证密钥/VTY/后备访问。
after = before.sub("authentication login local", "authentication login hwtacacs-scheme OPS local")
report = audit.call(configuration: after, platform: "h3c", complete: true)
raise "Declared domain binding not assessed" unless report.compliant?
raise "Partial capture certified exact bindings" if audit.call(configuration: after, platform: "h3c", complete: false).compliant?
puts report.to_text

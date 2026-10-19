# frozen_string_literal: true

require "baseline"
puts RUBY_DESCRIPTION
puts "source=#{Baseline::Evaluator.instance_method(:call).source_location.first}"
# 固定合成输入，对同一调用路径取三次中位数。
def measure(label)
  samples = 3.times.map do
    GC.start
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end.sort
  puts "#{label}: #{samples[1].round(6)} seconds"
end

# 共享日志迁移同时核验每个匹配项的完整消费者，避免基准绕过审批及命令路径。
[ 10, 100 ].each do |size|
  configuration = "set deviceconfig system hostname LAB\n" \
    "set shared log-settings syslog OLD server S server 192.0.2.10\n" \
    "set shared log-settings syslog NEW server S server 192.0.2.20\n"
  bindings, migrations = [], []
  size.times do |index|
    profile = "FORWARD#{index / 64}"
    rule = "ALLOW#{index / 64}"
    configuration += "set rulebase security rules #{rule} log-setting #{profile}\n" if index % 64 == 0
    reference = { "kind" => "syslog.forwarding", "forwarding_profile" => profile, "match" => "M#{index}", "log_type" => "traffic" }
    binding = reference.merge("context" => "local", "rulebase" => "security", "rule" => rule)
    bindings << binding
    migrations << { "from_profile" => "OLD", "to_profile" => "NEW", "reference" => reference, "consumers" => [ binding ] }
    configuration += "set shared log-settings profiles #{profile} match-list M#{index} log-type traffic\n" \
      "set shared log-settings profiles #{profile} match-list M#{index} send-syslog OLD\n"
  end
  targets = %w[OLD NEW].map do |profile|
    { "identity" => { "name" => "S" }, "scope" => { "profile" => profile }, "bindings" => profile == "NEW" ? bindings : [] }
  end
  policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
    "expected" => targets, "managed_scopes" => targets.map { |target| target["scope"] }, "remediation" => { "binding_migrations" => migrations }
  } })
  service = Baseline::Remediation.new(policy: policy)
  measure("PAN-OS shared Syslog migration #{size} matches") do
    plan = service.call(configuration: configuration, platform: :palo_alto, complete: true)
    unless plan.status == :ready && plan.operations.size == size && plan.operations.all? { |operation| operation.kind == "syslog.reference" } && plan.steps.size == size * 2
      raise "Expected complete reference migration plan"
    end
  end
end
[ 1000, 4000 ].each do |size|
  actual = size.times.map { |i| "10.#{i / 256}.#{i % 256}.0/24" }
  approved = actual.reverse
  measure("coverage #{size}") { raise unless Baseline::Acl.networks_within?(actual, approved) }
  measure("credential lookup #{size}") do
    facts = Baseline::FactBuilder.new(complete: true)
    size.times do |i|
      facts.record_credential(Baseline::Credential.new(owner: "synthetic", kind: "snmp", format: "cipher", secret: "example", line: i))
      raise unless facts.credential_recorded?(i)
    end
  end
end

# 通过完整 Audit 调用测量违规报告，不能只验证网络完全获批的快路径。
[ 200, 800 ].each do |size|
  base = IPAddr.new("10.0.0.0").to_i
  approved_base = IPAddr.new("172.16.0.0").to_i
  networks = size.times.map { |index| "#{IPAddr.new(approved_base + index * 2, Socket::AF_INET)}/32" }
  rules = size.times.map { |index| " #{index + 1} permit host #{IPAddr.new(base + index * 2, Socket::AF_INET)}\n" }.join
  configuration = "hostname LAB\nip access-list standard MGMT\n#{rules}line vty 0 4\n transport input ssh\n login local\n access-class MGMT in\nend\n"
  policy = Baseline::Policy.new("version" => 1, "checks" => { "management.sources" => { "expected" => networks } })
  audit = Baseline::Audit.new(policy: policy)
  measure("unapproved source report #{size}") do
    report = audit.call(configuration: configuration, platform: :cisco_ios, complete: true)
    finding = report.findings.fetch(0)
    raise "Missing deviation evidence" unless finding.status == :fail && finding.details.fetch(:outside_approved).size == size
  end
end

# 多账号导出会反复查询词元前缀，同时验证最终声明与凭据脱敏。
[ 200, 800 ].each do |size|
  accounts = size.times.map { |index| "set mgt-config users USER-#{index} phash '$5$synthetic$opaque'\n" }.join
  configuration = "set deviceconfig system hostname LAB\n#{accounts}"
  measure("PAN-OS accounts #{size}") do
    result = Baseline::PaloAlto::Parser.parse(configuration, complete: true)
    credentials = result.records.fetch(0).fetch("facts").fetch("credentials.records")
    raise "Missing account evidence" unless credentials.size == size && credentials.all? { |value| value[:storage] == "protected" }
  end
end

# 快照构建覆盖嵌套凭据和服务器事实；每次都必须产出独立、冻结的结果。
[ 200, 800 ].each do |size|
  facts = Baseline::FactBuilder.new(complete: true)
  facts.record_fact("hostname", "LAB")
  facts.record_fact("ntp.servers", size.times.map { |index| "time-#{index}.example.test" })
  size.times do |index|
    facts.record_credential(Baseline::Credential.new(owner: "USER-#{index}", kind: "local_user", format: "cipher", secret: "synthetic", line: index + 1))
  end
  measure("fact snapshots #{size} x30") do
    30.times do
      result = facts.build
      records = result.records.fetch(0).fetch("facts").fetch("credentials.records")
      raise "Missing frozen snapshot evidence" unless records.size == size && records.frozen? && records.first.frozen?
    end
  end
end

# 全域引用规模测试保留相同共享服务器组，不用选中域快路径冒充完整库存。
[ 10, 100 ].each do |size|
  domains = size.times.map do |index|
    "domain D#{index}\n authentication login hwtacacs-scheme OPS local\n authorization login hwtacacs-scheme OPS local\n accounting login hwtacacs-scheme OPS local\n#\n"
  end.join
  configuration = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n primary authorization 192.0.2.31\n primary accounting 192.0.2.32\n#\n" \
    "#{domains}domain default enable D0\nline vty 0 4\n authentication-mode scheme\n#\n"
  bindings = size.times.map { |index| { "kind" => "aaa.domain", "domain" => "D#{index}", "role" => "authentication", "position" => "primary", "selected" => index.zero? } }
  expected = { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" }, "scope" => { "group" => "OPS" }, "bindings" => bindings }
  policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => { "expected" => [ expected ] } })
  audit = Baseline::Audit.new(policy: policy)
  measure("shared TACACS domain bindings #{size}") do
    report = audit.call(configuration: configuration, platform: "h3c", complete: true)
    raise "Missing complete domain binding evidence" unless report.compliant? && report.configuration.fact("aaa.domain_bindings").size == size * 3
  end
end

# 密钥、可信引用及关联按索引连接，合成规模只测本地配置证据构建。
[ 10, 100 ].each do |size|
  rows = size.times.map do |index|
    id = index + 1
    "ntp-service authentication-keyid #{id} authentication-mode md5 cipher SYNTHETIC-KEY\n" \
      "ntp-service reliable authentication-keyid #{id}\nntp-service unicast-server 192.0.2.#{id} authentication-keyid #{id}\n"
  end.join
  configuration = "sysname LAB\nntp-service authentication enable\n#{rows}"
  policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.authentication" => { "expected" => true } })
  audit = Baseline::Audit.new(policy: policy)
  measure("NTP material and trust bindings #{size}") do
    report = audit.call(configuration: configuration, platform: "h3c", complete: true)
    bindings = report.configuration.fact("ntp.authentication_bindings")
    raise "Missing complete NTP key evidence" unless report.compliant? && bindings.size == size && bindings.all? { |binding| binding[:configured_ready] }
  end
end

# 无关策略行不进入日志词元索引；完整审计仍须解析并验证实际使用链。
[ 200, 800 ].each do |size|
  rules = size.times.map do |index|
    %w[source destination application service].map { |field| "set vsys LAB rulebase security rules RULE#{index} #{field} any\n" }.join
  end.join
  configuration = "set deviceconfig system hostname LAB\nset shared log-settings syslog LOGS server FIRST server 192.0.2.20\n#{rules}" \
    "set shared log-settings profiles FORWARD match-list TRAFFIC log-type traffic\n" \
    "set shared log-settings profiles FORWARD match-list TRAFFIC send-syslog LOGS\n" \
    "set vsys LAB rulebase security rules RULE1 log-setting FORWARD\nset vsys LAB rulebase security rules RULE1 log-end yes\n"
  object = { "identity" => { "name" => "FIRST" }, "scope" => { "profile" => "LOGS" }, "bindings" => [
    { "kind" => "syslog.forwarding", "forwarding_profile" => "FORWARD", "match" => "TRAFFIC", "log_type" => "traffic",
      "context" => "vsys", "vsys" => "LAB", "rulebase" => "security", "rule" => "RULE1", "log_end" => true }
  ] }
  policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => { "expected" => [ object ] } })
  audit = Baseline::Audit.new(policy: policy)
  measure("PAN-OS Syslog references with unrelated rules #{size}") do
    report = audit.call(configuration: configuration, platform: :palo_alto, complete: true)
    raise "Missing configured output chain" unless report.compliant? && report.configuration.resources.first.bindings.one?
  end
end

# 跨 profile 的原生容量协调与操作核验使用索引，不反复扫描全部对象。
[ 10, 100 ].each do |size|
  targets, scopes, declarations = [], [], []
  size.times do |index|
    profile = "PROFILE#{index}"
    scopes << { "profile" => profile }
    (1..4).each do |server|
      prefix = "set shared log-settings syslog #{profile} server S#{server}"
      declarations << "#{prefix} server 192.0.2.#{server}\n#{prefix} transport UDP\n#{prefix} port 514\n#{prefix} format BSD\n#{prefix} facility LOG_USER\n"
    end
    (2..5).each do |server|
      targets << { "identity" => { "name" => "S#{server}" }, "scope" => { "profile" => profile },
        "attributes" => { "address" => "192.0.2.#{server}", "protocol" => "udp", "port" => 514, "format" => "BSD", "facility" => "LOG_USER" } }
    end
  end
  configuration = "set deviceconfig system hostname LAB\n#{declarations.join}"
  policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
    "expected" => targets, "managed_scopes" => scopes, "remediation" => { "maximum_targets" => size * 5 }
  } })
  service = Baseline::Remediation.new(policy: policy)
  measure("PAN-OS native Syslog capacity #{size} profiles") do
    plan = service.call(configuration: configuration, platform: :palo_alto, complete: true)
    unless plan.status == :ready && plan.operations.size == size * 2 && plan.operations.count { |operation| operation.phase == :prepare } == size
      raise "Native profile capacity was not preserved"
    end
  end
end

# 原生三服务器场景同时规划关联和共同来源，重复指标必须复用同一操作集合。
configuration = "hostname LAB\n" + 3.times.map { |index| "ntp server 192.0.2.#{index + 10} source MGT#{index}\n" }.join
targets = 3.times.map do |index|
  { "identity" => { "address" => "192.0.2.#{index + 10}", "role" => "server" }, "scope" => { "vrf" => "default" } }
end
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ntp.associations" => { "expected" => targets, "managed_scopes" => [ { "vrf" => "default" } ] },
  "ntp.source" => { "expected" => "MGT3" }
})
service = Baseline::Remediation.new(policy: policy)
measure("StoneOS native NTP common source 3 servers") do
  plan = service.call(configuration: configuration, platform: :hillstone, complete: true)
  unless plan.status == :ready && plan.operations.size == 3 && plan.steps.size == 6 && plan.operations.all? { |operation| operation.kind == "ntp.server" }
    raise "Expected complete native NTP source plan"
  end
end

# 全局认证包含完整消费者扫描、材料依赖及先撤下再重建的事务；不省略规划和呈现。
configuration = +"sysname LAB\nntp-service authentication-keyid 7 authentication-mode hmac-sha-256 cipher SYNTHETIC-ONLY\n" \
  "ntp-service reliable authentication-keyid 7\n"
3.times { |index| configuration << "ntp-service unicast-server 192.0.2.#{index + 10} authentication-keyid 7\n" }
policy = Baseline::Policy.new("version" => 1, "checks" => {
  "ntp.authentication" => { "expected" => true, "remediation" => {
    "ntp_peer_key_compatibility_verified" => true, "ntp_association_recreation_approved" => true, "syntax_profile" => "comware7"
  } }
})
service = Baseline::Remediation.new(policy: policy)
measure("Comware global NTP authentication 3 associations") do
  plan = service.call(configuration: configuration, platform: :h3c, complete: true)
  raise "Expected complete global authentication transaction" unless plan.status == :ready && plan.operations.size == 7 && plan.steps.size == 7
end

# 共享用户集合按组索引，完整经历只读目标组、用户归属和旧组撤回的规划与呈现。
[ 1, 8 ].each do |size|
  configuration = +"sysname LAB\nsnmp-agent\n"
  migrations = size.times.map do |index|
    configuration << "snmp-agent group v3 G#{index} privacy read-view READ write-view WRITE notify-view NOTIFY\n" \
      "snmp-agent usm-user v3 U#{index} group G#{index}\n" \
      "snmp-agent usm-user v3 U#{index} authentication-mode sha cipher SYNTHETIC-AUTH\n" \
      "snmp-agent usm-user v3 U#{index} privacy-mode aes128 cipher SYNTHETIC-PRIV\n"
    { "from_group" => "G#{index}", "to_group" => "RO#{index}", "users" => [ "U#{index}" ] }
  end
  policy = Baseline::Policy.new("version" => 1, "checks" => {
    "snmp.write_enabled" => { "expected" => false, "remediation" => { "group_migrations" => migrations,
      "syntax_profile" => "vrp_v600", "available_group_slots" => size,
      "snmp_group_migration_verified" => true, "snmp_user_group_transition_verified" => true } }
  })
  service = Baseline::Remediation.new(policy: policy)
  measure("VRP read-only SNMP migration #{size} groups") do
    plan = service.call(configuration: configuration, platform: :huawei, complete: true)
    raise "Incomplete SNMP permission transaction" unless plan.status == :ready && plan.operations.size == size * 3
  end
end

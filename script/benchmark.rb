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

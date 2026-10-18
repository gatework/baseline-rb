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

# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Remediation setting commands" do
  sources = {
    "h3c" => [ "sysname LAB", "ntp-service source", "info-center loghost source", "system-view", "return" ],
    "huawei" => [ "sysname LAB", "ntp-service source-interface", "info-center loghost source", "system-view", "return" ],
    "cisco_ios" => [ "hostname LAB", "ntp source", "logging source-interface", "configure terminal", "end" ],
    "cisco_nxos" => [ "hostname LAB", "ntp source-interface", "logging source-interface", "configure terminal", "end" ],
    "palo_alto" => [ "set deviceconfig system hostname LAB", "set deviceconfig system route service ntp source interface",
      "set deviceconfig system route service syslog source interface", "configure", "exit" ]
  }

  sources.each do |platform, (hostname, ntp, syslog, enter, leave)|
    { "ntp.source" => ntp, "syslog.source" => syslog }.each do |id, prefix|
      it "renders and converges #{id} on #{platform} without touching the other source" do
        other = prefix == ntp ? syslog : ntp
        before, target, untouched = platform == "palo_alto" ? %w[loopback.1 loopback.0 loopback.9] : %w[Loopback1 Loopback0 Loopback9]
        input = "#{hostname}\n#{prefix} #{before}\n#{other} #{untouched}\n"
        policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => target } })
        service = Baseline::Remediation.new(policy: policy)
        plan = service.call(configuration: input, platform: platform, complete: true)
        expect(plan.status).to eq(:ready)
        expect(plan.configuration_commands).to eq([ enter, "#{prefix} #{target}", leave ])
        # 独立的标量设备状态模型：命令替换同族声明，其他配置逐字保留。
        lines = input.lines.reject { |line| line.start_with?("#{prefix} ") }
        lines << "#{prefix} #{target}\n"
        after = lines.join
        expect(after).to include("#{other} #{untouched}\n")
        second = service.call(configuration: after, platform: platform, complete: true)
        expect(second.audit).to be_compliant
        expect(second.status).to eq(:noop)
        expect(second.configuration_commands).to be_empty
      end
    end
  end

  it "rejects router-style interface spelling for a PAN-OS source route" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => "Loopback0" } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "set deviceconfig system hostname LAB\n" \
      "set deviceconfig system route service syslog source interface loopback.1\n", platform: "palo_alto", complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:invalid_command_parameter)
  end

  it "requires a source-address review before changing a PAN-OS route interface" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => "loopback.0" } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "set deviceconfig system hostname LAB\n" \
      "set deviceconfig system route service syslog source interface loopback.1\n" \
      "set deviceconfig system route service syslog source address 192.0.2.10\n", platform: "palo_alto", complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:unresolved_prerequisites)
    expect(result.configuration_commands).to be_empty
  end

  it "normalizes an approved split interface before generation and recheck" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.source" => { "expected" => "LoopBack 0" } })
    service = Baseline::Remediation.new(policy: policy)
    first = service.call(configuration: "sysname LAB\ninfo-center loghost source LoopBack1\n", platform: "h3c", complete: true)
    expect(first.configuration_commands).to include("info-center loghost source LoopBack0")
    second = service.call(configuration: "sysname LAB\ninfo-center loghost source LoopBack0\n", platform: "h3c", complete: true)
    expect(second.status).to eq(:noop)
  end

  it "returns booleans from every renderer capability predicate" do
    Baseline::Remediation::RENDERERS.each_value do |type|
      renderer = type.new
      Baseline::Rule::DEFINITIONS.each_key do |id|
        expect([ true, false ]).to include(renderer.supports?(id))
      end
    end
  end

  it "keeps command capabilities separate from parser capabilities for every metric and alias" do
    Baseline::Audit::PARSERS.each_key do |platform|
      capabilities = Baseline::Remediation.capabilities(platform: platform)
      expect(capabilities.keys).to eq(Baseline::Rule::DEFINITIONS.keys)
      expect(capabilities).to be_frozen
      expect(capabilities.values).to all(include(:status, :reason, :requirements))
    end
    Baseline::Audit::ALIASES.each do |alias_name, canonical|
      expect(Baseline::Remediation.capabilities(platform: alias_name)).to eq(Baseline::Remediation.capabilities(platform: canonical))
    end
    expect(Baseline::Remediation.capabilities(platform: "unknown").values).to all(include(status: :unsupported, reason: :unsupported_platform))
    expect(Baseline::Remediation.capabilities(platform: "palo_alto").fetch("ssh.vty_aaa")).to include(status: :unsupported)
  end
end

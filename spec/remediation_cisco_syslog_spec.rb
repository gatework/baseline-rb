# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Cisco syslog commands" do
  {
    "cisco_ios" => [ "logging host 192.0.2.20 vrf OPS transport tcp port 514", "logging host 192.0.2.20 vrf OPS transport tcp port 1514",
      "no logging host 192.0.2.20 vrf OPS", { "protocol" => "tcp", "port" => 1514 } ],
    "cisco_nxos" => [ "logging server 192.0.2.20 6 use-vrf OPS facility local6", "logging server 192.0.2.20 5 use-vrf OPS facility local6",
      "no logging server 192.0.2.20 use-vrf OPS", { "severity" => 5 } ]
  }.each do |platform, (before, after, removal, attributes)|
    it "replaces #{platform} target attributes within the approved VRF and converges" do
      object = { "identity" => { "address" => "192.0.2.20" }, "scope" => { "vrf" => "OPS" }, "attributes" => attributes }
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
        "expected" => [ object ], "managed_scopes" => [ { "vrf" => "OPS" } ] } })
      service = Baseline::Remediation.new(policy: policy)
      untouched = platform == "cisco_ios" ? "logging host 192.0.2.30 vrf OTHER" : "logging server 192.0.2.30 use-vrf OTHER"
      input = "hostname LAB\n#{before}\n#{untouched}\n"
      plan = service.call(configuration: input, platform: platform, complete: true)
      expect(plan.status).to eq(:ready)
      expect(plan.configuration_commands).to eq([ "configure terminal", removal, after, "end" ])
      # 独立叶子状态转换：仅替换已明确断言的旧声明，不解释生产操作数据。
      updated = input.sub("#{before}\n", "#{after}\n")
      expect(updated).to include("#{untouched}\n")
      second = service.call(configuration: updated, platform: platform, complete: true)
      expect(second.status).to eq(:noop)
      expect(second.audit).to be_compliant
    end

    it "adds and removes #{platform} public targets without changing correct ones" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => {
        "expected" => %w[192.0.2.20 192.0.2.40], "remediation" => { "maximum_targets" => 4 } } })
      prefix = platform == "cisco_ios" ? "logging host" : "logging server"
      service = Baseline::Remediation.new(policy: policy)
      plan = service.call(configuration: "hostname LAB\n#{prefix} 192.0.2.20\n#{prefix} 192.0.2.30\n", platform: platform, complete: true)
      expect(plan.status).to eq(:ready)
      expect(plan.configuration_commands).to eq([ "configure terminal", "#{prefix} 192.0.2.40", "no #{prefix} 192.0.2.30", "end" ])
    end
  end

  it "withholds NX-OS port rendering until the target syntax profile is verified" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => { "expected" => [ {
      "identity" => { "address" => "192.0.2.20" }, "scope" => { "vrf" => "default" }, "attributes" => { "port" => 1514 }
    } ], "managed_scopes" => [ { "vrf" => "default" } ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\nlogging server 192.0.2.20 port 514\n", platform: "cisco_nxos", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
  end

  it "keeps IOS objects in an explicitly named default VRF distinct from the global domain" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "192.0.2.40" ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\nlogging host 192.0.2.20 vrf default\n", platform: "cisco_ios", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.operations).to be_empty
  end

  it "withholds IOS object changes when parallel transports share an address and VRF" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "192.0.2.40" ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\n" \
      "logging host 192.0.2.20 transport udp port 514\nlogging host 192.0.2.20 transport tcp port 1514\n", platform: "cisco_ios", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.operations).to be_empty
  end
end

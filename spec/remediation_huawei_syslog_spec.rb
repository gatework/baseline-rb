# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Huawei syslog object remediation" do
  it "removes a wrong public target and adds the approved address with domain syntax" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => {
      "expected" => [ "logs.example.test" ], "remediation" => { "maximum_targets" => 4 } } })
    service = Baseline::Remediation.new(policy: policy)
    plan = service.call(configuration: "sysname LAB\ninfo-center loghost 192.0.2.20\n", platform: "huawei", complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "system-view", "info-center loghost domain logs.example.test", "undo info-center loghost 192.0.2.20", "return" ])
    updated = "sysname LAB\ninfo-center loghost domain logs.example.test\n"
    expect(service.call(configuration: updated, platform: "huawei", complete: true).status).to eq(:noop)
  end

  it "replaces a domain object's port using the trailing VPN form and retains facility" do
    object = { "identity" => { "address" => "logs.example.test" }, "scope" => { "vrf" => "OPS" }, "attributes" => { "port" => 1514 } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
      "expected" => [ object ], "managed_scopes" => [ { "vrf" => "OPS" } ] } })
    service = Baseline::Remediation.new(policy: policy)
    before = "info-center loghost domain logs.example.test vpn-instance OPS port 514 facility local6"
    after = "info-center loghost domain logs.example.test vpn-instance OPS port 1514 facility local6"
    plan = service.call(configuration: "sysname LAB\n#{before}\n", platform: "huawei", complete: true)
    expect(plan.configuration_commands).to eq([ "system-view", "undo info-center loghost domain logs.example.test vpn-instance OPS", after, "return" ])
    expect(service.call(configuration: "sysname LAB\n#{after}\n", platform: "huawei", complete: true).status).to eq(:noop)
  end
end

# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Hillstone logging target changes" do
  it "changes only the managed event category without removing the config category" do
    make = lambda do |address|
      { "identity" => { "address" => address, "protocol" => "udp", "port" => 514, "types" => [ "event" ] },
        "scope" => { "vrf" => "trust-vr" } }
    end
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
      "expected" => [ make.call("192.0.2.40"), { "identity" => { "address" => "192.0.2.20", "protocol" => "udp", "port" => 514,
        "types" => [ "config" ] }, "scope" => { "vrf" => "trust-vr" } } ], "managed_scopes" => [ { "vrf" => "trust-vr" } ],
      "remediation" => { "maximum_targets" => 4 } } })
    service = Baseline::Remediation.new(policy: policy)
    input = "hostname LAB\nlogging syslog 192.0.2.20 vrouter trust-vr udp 514 type event\nlogging syslog 192.0.2.20 vrouter trust-vr udp 514 type config\nEnd\n"
    plan = service.call(configuration: input, platform: "hillstone", complete: true)
    expect(plan.status).to eq(:ready)
    expect(plan.configuration_commands).to eq([ "configure", "logging syslog 192.0.2.40 vrouter trust-vr udp 514 type event",
      "no logging syslog 192.0.2.20 vrouter trust-vr udp 514 type event", "exit" ])
    after = input.sub("logging syslog 192.0.2.20 vrouter trust-vr udp 514 type event", "logging syslog 192.0.2.40 vrouter trust-vr udp 514 type event")
    expect(after).to include("logging syslog 192.0.2.20 vrouter trust-vr udp 514 type config")
    expect(service.call(configuration: after, platform: "hillstone", complete: true).status).to eq(:noop)
  end

  it "requires a complete native identity rather than guessing transport for an address list" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "192.0.2.40" ] } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\nlogging syslog 192.0.2.20 udp 514 type event\nEnd\n",
      platform: "hillstone", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
  end

  it "does not render unknown log categories as if their native syntax was verified" do
    object = { "identity" => { "address" => "192.0.2.40", "protocol" => "udp", "port" => 514, "types" => [ "invented" ] }, "scope" => { "vrf" => "default" } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => { "expected" => [ object ],
      "managed_scopes" => [ { "vrf" => "default" } ], "remediation" => { "maximum_targets" => 4 } } })
    plan = Baseline::Remediation.new(policy: policy).call(configuration: "hostname LAB\n", platform: "hillstone", complete: true)
    expect(plan.status).to eq(:blocked)
    expect(plan.configuration_commands).to be_empty
  end
end

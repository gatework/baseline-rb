# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"
require_relative "support/comware_ntp_state"

RSpec.describe "Native address identity during target transitions" do
  def ntp_policy(objects)
    Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
      "expected" => objects, "managed_scopes" => [ { "vrf" => "default" } ], "remediation" => { "maximum_targets" => 3 }
    } })
  end

  def association(address, role = "server")
    { "identity" => { "address" => address, "role" => role }, "scope" => { "vrf" => "default" } }
  end

  it "produces no NTP add/remove pair for equivalent native IPv6 endpoints" do
    sources = {
      "h3c" => "sysname LAB\nntp-service ipv6 unicast-server 2001:db8::10\n",
      "huawei" => "sysname LAB\nntp-service unicast-server ipv6 2001:db8::10\n",
      "cisco_ios" => "hostname LAB\nntp server ipv6 2001:db8::10\n",
      "cisco_nxos" => "hostname LAB\nntp server 2001:db8::10\n"
    }
    sources.each do |platform, text|
      service = Baseline::Remediation.new(policy: ntp_policy([ association("2001:0db8:0:0:0:0:0:10") ]))
      result = service.call(configuration: text, platform: platform, complete: true)
      expect(result.status).to eq(:noop)
      expect(result.operations).to be_empty
    end
  end

  it "does not count aliases as independent current capacity or independent approved targets" do
    text = "sysname LAB\nntp-service ipv6 unicast-server 2001:db8::10\nntp-service ipv6 unicast-server 2001:0db8:0:0:0:0:0:10\n"
    result = Baseline::Remediation.new(policy: ntp_policy([ association("2001:db8::11") ])).call(configuration: text, platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
    expect(result.checks.first.details[:initial_targets]).to eq(1)
    targets = [ association("2001:db8::11"), association("2001:0db8:0:0:0:0:0:11") ]
    expect { ntp_policy(targets) }.to raise_error(ArgumentError)
  end

  it "protects syslog native aliases without merging different NTP roles" do
    object = { "identity" => { "address" => "2001:0db8:0:0:0:0:0:10" }, "scope" => { "vrf" => "default" } }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.destinations" => {
      "expected" => [ object ], "managed_scopes" => [ { "vrf" => "default" } ], "remediation" => { "maximum_targets" => 2 }
    } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\ninfo-center loghost ipv6 2001:db8::10\n", platform: "h3c", complete: true)
    expect(result.status).to eq(:noop)
    mixed = ntp_policy([ association("2001:db8::10"), association("2001:0db8:0:0:0:0:0:10", "peer") ])
    result = Baseline::Remediation.new(policy: mixed).call(configuration: "sysname LAB\nntp-service ipv6 unicast-server 2001:db8::10\n", platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
  end

  it "demonstrates why an add/remove alias pair deletes the approved native endpoint" do
    state = ComwareNtpState.new("sysname LAB\nntp-service ipv6 unicast-server 2001:db8::10\n")
    commands = [ "system-view", "ntp-service ipv6 unicast-server 2001:0db8:0:0:0:0:0:10",
      "undo ntp-service ipv6 unicast-server 2001:db8::10", "return" ]
    expect(state.apply(commands).configuration).to eq("sysname LAB\n")
  end
end

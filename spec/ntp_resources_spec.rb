# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "NTP association resources" do
  {
    "h3c" => [ "sysname LAB", "ntp-service unicast-server 192.0.2.10 vpn-instance OPS version 4 authentication-keyid 7 priority source-interface LoopBack 0",
      { "version" => 4, "key_id" => 7, "prefer" => true, "source" => "LoopBack0" } ],
    "huawei" => [ "sysname LAB", "ntp-service unicast-server 192.0.2.10 vpn-instance OPS version 4 authentication-keyid 7 priority source-interface LoopBack 0",
      { "version" => 4, "key_id" => 7, "prefer" => true, "source" => "LoopBack0" } ],
    "cisco_ios" => [ "hostname LAB", "ntp server vrf OPS 192.0.2.10 version 4 key 7 prefer source Loopback0",
      { "version" => 4, "key_id" => 7, "prefer" => true, "source" => "Loopback0" } ],
    "cisco_nxos" => [ "hostname LAB", "ntp server 192.0.2.10 use-vrf OPS version 4 key 7 prefer source Loopback0",
      { "version" => 4, "key_id" => 7, "prefer" => true, "source" => "Loopback0" } ],
    "hillstone" => [ "hostname LAB", "ntp server 192.0.2.10 vrouter OPS key 7 source MGT0 prefer",
      { "key_id" => 7, "source" => "MGT0", "prefer" => true } ]
  }.each do |platform, (hostname, command, attributes)|
    it "preserves approved-target generation parameters on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 1 } })
      report = Baseline::Audit.new(policy: policy).call(configuration: "#{hostname}\n#{command}\n", platform: platform, complete: true)
      item = report.configuration.resources.find { |resource| resource.kind == "ntp.association" }
      expect(item).not_to be_nil
      expect(item.identity).to eq("address" => "192.0.2.10", "role" => "server")
      expect(item.scope).to eq("vrf" => "OPS")
      expect(item.attributes).to eq(attributes)
      expect(item).to be_complete
      expect(report.findings.first.status).to eq(:pass)
    end
  end

  %w[h3c huawei cisco_ios cisco_nxos].each do |platform|
    it "keeps peer identity separate from server identity and cancellation on #{platform}" do
      comware = %w[h3c huawei].include?(platform)
      hostname = comware ? "sysname LAB" : "hostname LAB"
      prefix, server, peer, negate = comware ? [ "ntp-service", "unicast-server", "unicast-peer", "undo" ] : [ "ntp", "server", "peer", "no" ]
      text = "#{hostname}\n#{prefix} #{server} 192.0.2.10\n#{prefix} #{peer} 192.0.2.10\n#{negate} #{prefix} #{server} 192.0.2.10\n"
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 1 } })
      report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
      resources = report.configuration.resources.select { |resource| resource.kind == "ntp.association" }
      expect(resources.size).to eq(1)
      expect(resources.first.identity).to eq("address" => "192.0.2.10", "role" => "peer")
      expect(report.configuration.fact("ntp.servers")).to eq([])
      expect(report.findings.first.status).to eq(:fail)
    end
  end

  it "preserves PAN-OS primary and secondary slots without authentication secrets" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 2 } })
    prefix = "set deviceconfig system ntp-servers"
    text = "set deviceconfig system hostname LAB\n#{prefix} primary-ntp-server ntp-server-address 192.0.2.10\n" \
      "#{prefix} primary-ntp-server authentication-type symmetric-key algorithm sha256 authentication-key PRIVATE-TOKEN\n" \
      "#{prefix} primary-ntp-server authentication-type symmetric-key key-id 7\n" \
      "#{prefix} secondary-ntp-server ntp-server-address 192.0.2.11\n" \
      "#{prefix} secondary-ntp-server authentication-type none\n"
    report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: "palo_alto", complete: true)
    resources = report.configuration.resources.select { |resource| resource.kind == "ntp.association" }
    expect(resources.map(&:identity)).to eq([ { "name" => "primary-ntp-server" }, { "name" => "secondary-ntp-server" } ])
    expect(resources.first.attributes).to include("address" => "192.0.2.10", "authenticated" => true)
    expect(resources.last.attributes).to include("address" => "192.0.2.11", "authenticated" => false)
    expect(report.to_h.to_json).not_to include("PRIVATE-TOKEN")
  end

  it "keeps an out-of-range StoneOS key reference unknown without raising" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 1 } })
    report = Baseline::Audit.new(policy: policy).call(configuration: "hostname LAB\nntp server 192.0.2.10 key 4294967296\n",
      platform: "hillstone", complete: true)
    expect(report.findings.first.status).to eq(:unknown)
    expect(report.configuration.resources).to be_empty
  end
end

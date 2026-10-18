# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline NTP declaration options" do
  def audit(platform, command)
    hostname = platform.start_with?("cisco") ? "hostname LAB" : "sysname LAB"
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 1 } })
    Baseline::Audit.new(policy: policy).call(configuration: "#{hostname}\n#{command}\n", platform: platform, complete: true)
  end

  %w[cisco_ios cisco_nxos h3c huawei].each do |platform|
    prefix = platform.start_with?("cisco") ? "ntp server" : "ntp-service unicast-server"
    it "keeps unsupported, incomplete and duplicate #{platform} NTP options unknown" do
      key = platform.start_with?("cisco") ? "key" : "authentication-keyid"
      [ "trailing-junk", "version", "version 99", "version 3 version 4", "#{key} invalid", "#{key}",
        "source-interface", "prefer junk", "minpoll 12 maxpoll 6",
        "#{platform.start_with?('cisco') ? 'source' : 'source-interface'} Loopback0 1" ].each do |tail|
        report = audit(platform, "#{prefix} 192.0.2.10 #{tail}")
        expect(report.findings.first.status).to eq(:unknown), tail
      end
    end

    it "keeps another #{platform} VRF active when one server is removed" do
      if platform.start_with?("cisco")
        command = "ntp server vrf A 192.0.2.10\nntp server vrf B 192.0.2.10\nno ntp server vrf A 192.0.2.10"
      else
        command = "ntp-service unicast-server vpn-instance A 192.0.2.10\nntp-service unicast-server vpn-instance B 192.0.2.10\nundo ntp-service unicast-server vpn-instance A 192.0.2.10"
      end
      report = audit(platform, command)
      expect(report.findings.first.status).to eq(:pass)
      expect(report.configuration.fact("ntp.servers")).to eq([ "192.0.2.10" ])
    end

    it "does not apply a malformed #{platform} NTP cancellation" do
      negate = platform.start_with?("cisco") ? "no" : "undo"
      report = audit(platform, "#{prefix} 192.0.2.10\n#{negate} #{prefix} 192.0.2.10 trailing-junk")
      expect(report.findings.first.status).to eq(:unknown)
    end
  end

  %w[cisco_ios cisco_nxos].each do |platform|
    it "accepts #{platform} NTP flags, typed values, split interfaces and DNS address families" do
      [ "ntp server vrf MGMT ipv6 time.example.test prefer version 4 key 10 source ethernet 0/1 minpoll 4 maxpoll 10 burst iburst",
        "ntp server ip time.example.test source Loopback0 normal-sync",
        "ntp server 2001:db8::10 use-vrf management" ].each do |command|
        expect(audit(platform, command).findings.first.status).to eq(:pass), command
      end
      %w[ip ipv6 vrf].each do |keyword|
        expect(audit(platform, "ntp server #{keyword}").findings.first.status).to eq(:unknown)
      end
    end
  end

  %w[h3c huawei].each do |platform|
    it "recognizes the #{platform} IPv6 NTP command family and rejects inline family keywords" do
      report = audit(platform, "ntp-service ipv6 unicast-server 2001:db8::10 version 4")
      expect(report.findings.first.status).to eq(:pass)
      expect(report.configuration.fact("ntp.servers")).to eq([ "2001:db8::10" ])
      [ "ntp-service ipv6 unicast-server", "ntp-service ipv6 unicast-server 2001:db8::10 trailing-junk",
        "ntp-service unicast-server ip time.example.test", "ntp-service unicast-server ipv6 2001:db8::10" ].each do |command|
        expect(audit(platform, command).findings.first.status).to eq(:unknown), command
      end
      removed = audit(platform, "ntp-service ipv6 unicast-server 2001:db8::10\nundo ntp-service ipv6 unicast-server 2001:db8::10")
      expect(removed.findings.first.status).to eq(:fail)
    end

    it "accepts #{platform} NTP VPN and interface options without treating keywords as servers" do
      [ "ntp-service unicast-server vpn-instance MGMT time.example.test authentication-keyid 10 priority source-interface vlan-interface 1 version 3",
        "ntp-service unicast-server 2001:db8::10 authkey 10 source-interface Vlanif1 version 4" ].each do |command|
        expect(audit(platform, command).findings.first.status).to eq(:pass), command
      end
      [ "vpn-instance", "vpn-instance MGMT", "ipv6", "ip" ].each do |prefix|
        expect(audit(platform, "ntp-service unicast-server #{prefix}").findings.first.status).to eq(:unknown)
      end
    end
  end
end

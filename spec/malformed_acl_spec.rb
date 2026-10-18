# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Malformed ACL source evidence" do
  {
    "h3c" => [ "sysname LAB\nacl number 2000\n rule 5 deny source%s\n#\nline vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n acl 2000 inbound\n", [ "", " host", " host any", " host 192.0.2.0/24", " host 192.0.2.10 0.0.0.255" ] ],
    "huawei" => [ "sysname LAB\nacl number 2000\n rule 5 deny source%s\n#\nuser-interface vty 0 4\n protocol inbound ssh\n authentication-mode aaa\n acl 2000 inbound\n", [ "", " host", " host any", " host 192.0.2.0/24", " host 192.0.2.10 0.0.0.255" ] ],
    "cisco_ios" => [ "hostname LAB\nip access-list standard MGMT\n deny%s\n!\nline vty 0 4\n transport input ssh\n login local\n access-class MGMT in\n", [ " host", " host any", " host 192.0.2.0/24", " host 192.0.2.10 0.0.0.255" ] ],
    "cisco_nxos" => [ "hostname LAB\nip access-list MGMT\n deny ip any%s\n!\nline vty\n transport input ssh\n login local\n access-class MGMT in\n", [ " host", " host any", " host 192.0.2.0/24", " host 192.0.2.10 0.0.0.255" ] ]
  }.each do |platform, (source, suffixes)|
    it "does not interpret a missing #{platform} address as an implicit deny-all" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "management.sources" => { "expected" => [ "192.0.2.0/24" ] } })
      audit = Baseline::Audit.new(policy: policy)
      suffixes.each do |suffix|
        report = audit.call(configuration: source % suffix, platform: platform, complete: true)
        expect(report.findings.first.status).to eq(:unknown), suffix.inspect
        expect(report.configuration.fact_known?("management.acl.sources")).to be(false)
        expect(report).not_to be_compliant
      end
    end
  end

  it "rejects absent addresses at the public network-conversion boundary" do
    expect { Baseline::Acl.source_network(nil) }.to raise_error(ArgumentError)
    expect { Baseline::Acl.ipv4_range(nil) }.to raise_error(ArgumentError)
  end
end

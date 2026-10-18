# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Vendor management ACL rendering" do
  def policy(endpoint, acl, extra = {})
    Baseline::Policy.new("version" => 1, "checks" => {
      "management.acl_bound" => { "expected" => true }, "management.acl_restricted" => { "expected" => true },
      "management.sources" => { "expected" => [ "192.0.2.0/24" ], "remediation" => {
        "access_targets" => [ { "endpoint" => endpoint, "acl" => acl }.merge(extra) ]
      } }
    })
  end

  {
    "huawei" => {
      endpoint: "user-interface vty 0 4", acl: "2002", enter: "system-view", leave: "return", exit: "quit",
      prefix: "sysname LAB\nstelnet server enable\n", login: "authentication-mode aaa", protocol: "protocol inbound ssh",
      original: "acl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 permit source 198.51.100.0 0.0.0.255\n rule 15 deny\n#\n",
      binding: "acl 2000 inbound", replacement: "acl 2002 inbound",
      view: "acl number 2002", permits: [ "rule 5 permit source 192.0.2.0 0.0.0.127", "rule 10 deny" ], boundary: "#"
    },
    "cisco_ios" => {
      endpoint: "line vty 0 4", acl: "VTY_NEW", enter: "configure terminal", leave: "end", exit: "exit",
      prefix: "hostname LAB\nip ssh version 2\n", login: "login local", protocol: "transport input ssh",
      original: "ip access-list standard VTY_OLD\n 5 permit 192.0.2.0 0.0.0.127\n 10 permit 198.51.100.0 0.0.0.255\n 15 deny any\n!\n",
      binding: "access-class VTY_OLD in vrf-also", replacement: "access-class VTY_NEW in vrf-also",
      view: "ip access-list standard VTY_NEW", permits: [ "5 permit 192.0.2.0 0.0.0.127", "10 deny any" ], boundary: "!"
    }
  }.each do |platform, data|
    it "creates #{platform} ACLs with native binding syntax and converges without modifying the old ACL" do
      input = data[:prefix] + data[:original] + "#{data[:endpoint]}\n #{data[:login]}\n #{data[:protocol]}\n #{data[:binding]}\n#{data[:boundary]}\n"
      service = Baseline::Remediation.new(policy: policy(data[:endpoint], data[:acl]))
      result = service.call(configuration: input, platform: platform, complete: true)
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands).to eq([ data[:enter], data[:view], *data[:permits], data[:exit], data[:endpoint], data[:replacement], data[:leave] ])
      definition = "#{data[:view]}\n#{data[:permits].map { |command| " #{command}\n" }.join}#{data[:boundary]}\n"
      after = input.sub(data[:endpoint], definition + data[:endpoint]).sub(" #{data[:binding]}\n", " #{data[:replacement]}\n")
      expect(after).to include(data[:original], data[:login])
      repeated = service.call(configuration: after, platform: platform, complete: true)
      expect(repeated.audit).to be_compliant
      expect(repeated.status).to eq(:noop)
    end
  end

  it "preserves an IOS binding without vrf-also as well" do
    input = "hostname LAB\nip access-list standard OLD\n permit any\n!\nline vty 0 4\n transport input ssh\n access-class OLD in\n!\n"
    result = Baseline::Remediation.new(policy: policy("line vty 0 4", "NEW")).call(configuration: input, platform: "cisco_ios", complete: true)
    expect(result.configuration_commands).to include("access-class NEW in")
    expect(result.configuration_commands).not_to include("access-class NEW in vrf-also")
  end

  it "supports standard numeric and safe named IOS ACL identities" do
    input = "hostname LAB\nip access-list standard OLD\n permit any\n!\nline vty 0 4\n transport input ssh\n access-class OLD in\n!\n"
    [ "VTY.NEW", "N" * 64, "14", "1300" ].each do |identity|
      result = Baseline::Remediation.new(policy: policy("line vty 0 4", identity)).call(configuration: input, platform: "cisco_ios", complete: true)
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands).to include("ip access-list standard #{identity}", "access-class #{identity} in")
    end
    %w[0 100 2002 010].each do |identity|
      result = Baseline::Remediation.new(policy: policy("line vty 0 4", identity)).call(configuration: input, platform: "cisco_ios", complete: true)
      expect(result.operations).to be_empty
    end
  end

  it "requires explicit IOS VRF scope on an initial binding" do
    input = "hostname LAB\nline vty 0 4\n transport input ssh\n!\n"
    service = Baseline::Remediation.new(policy: policy("line vty 0 4", "NEW", "sources" => [ "192.0.2.10/32" ]))
    expect(service.call(configuration: input, platform: "cisco_ios", complete: true).operations).to be_empty
    [ true, false ].each do |flag|
      approved = policy("line vty 0 4", "NEW", "sources" => [ "192.0.2.10/32" ], "vrf_also" => flag)
      plan = Baseline::Remediation.new(policy: approved).call(configuration: input, platform: "cisco_ios", complete: true)
      expect(plan.status).to eq(:ready)
      expect(plan.configuration_commands).to include("access-class NEW in#{flag ? ' vrf-also' : ''}")
    end
  end

  it "publishes the IOS initial VRF scope requirement" do
    capability = Baseline::Remediation.capabilities(platform: "ios").fetch("management.sources")
    expect(capability[:status]).to eq(:conditional)
    expect(capability[:requirements]).to include("vrf_scope_for_initial_binding")
  end

  it "rejects nonboolean VRF scopes and refuses to change an existing IOS scope" do
    expect { policy("line vty 0 4", "NEW", "vrf_also" => "yes") }.to raise_error(ArgumentError)
    input = "hostname LAB\nip access-list standard OLD\n permit any\n!\nline vty 0 4\n transport input ssh\n access-class OLD in vrf-also\n!\n"
    result = Baseline::Remediation.new(policy: policy("line vty 0 4", "NEW", "vrf_also" => false)).call(configuration: input, platform: "cisco_ios", complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:access_vrf_scope_conflict)
  end
end

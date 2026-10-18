# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Management access endpoint evidence" do
  def evidence(body)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "management.sources" => { "expected" => [ "192.0.2.0/24" ] } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{body}", platform: "h3c", complete: true).configuration
  end

  let(:definitions) do
    "acl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n rule 10 deny\n#\n" \
      "acl basic 2001\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 deny\n#\n"
  end

  it "retains both global SSH and VTY ACLs and intersects their effective permissions" do
    config = evidence(definitions + "ssh server acl 2000\nline vty 0 4\n protocol inbound ssh\n acl 2001 inbound\n#\n")
    endpoints = config.fact("management.access_endpoints")
    expect(endpoints).to eq([ { name: "line vty 0 4", transport: "ssh", protocol: "tcp", port: 22,
      acl_chain: %w[2001 2000], sources: [ "192.0.2.0/25" ], bound: true, complete: true, line: 11 } ])
    expect(config.fact("management.acl.sources")).to eq([ "192.0.2.0/25" ])
    expect(config.sources.fetch("management.acl.sources")).to include(3, 7)
    expect(endpoints).to be_frozen
    expect { endpoints.first[:acl_chain] << "OTHER" }.to raise_error(FrozenError)
  end

  it "retains endpoint differences between ranges and SSH/Telnet rather than flattening them" do
    config = evidence(definitions + "ssh server acl 2001\nline vty 0 4\n protocol inbound ssh telnet\n acl 2000 inbound\n#\nline vty 5 9\n protocol inbound ssh\n acl 2001 inbound\n#\n")
    endpoints = config.fact("management.access_endpoints")
    expect(endpoints.map { |entry| [ entry[:name], entry[:transport], entry[:sources] ] }).to eq([
      [ "line vty 0 4", "ssh", [ "192.0.2.0/25" ] ], [ "line vty 0 4", "telnet", [ "192.0.2.0/24" ] ],
      [ "line vty 5 9", "ssh", [ "192.0.2.0/25" ] ]
    ])
  end

  it "records an unbound endpoint as unrestricted rather than guessing approved sources" do
    entry = evidence("line vty 0 4\n protocol inbound ssh\n#\n").fact("management.access_endpoints").first
    expect(entry).to include(bound: false, sources: [ "0.0.0.0/0" ], complete: true, acl_chain: [])
  end

  it "keeps missing or unsupported ACLs and transports unresolved per endpoint" do
    [ " protocol inbound ssh\n acl 2999 inbound", " protocol inbound all\n acl 2000 inbound" ].each do |body|
      entry = evidence(definitions + "line vty 0 4\n#{body}\n#\n").fact("management.access_endpoints").first
      expect(entry[:complete]).to be(false)
      expect(entry[:sources]).to be_nil
    end
  end

  it "reserves ACL numbers from definitions and dangling references outside VTY" do
    input = "acl basic 2000\n rule 5 deny\n#\ninterface Vlan-interface1\n packet-filter 2998 inbound\n#\nip http acl 2999\nssh server acl-deny-log enable\nline vty 0 4\n protocol inbound ssh\n acl 2000 inbound\n#\n"
    config = evidence(input)
    expect(config.fact("acl.reserved_numeric_ids")).to contain_exactly("2000", "2998", "2999")
    expect(config.fact("acl.identifiers")).to eq([ "2000" ])
    expect(config.fact("acl.reference_uses")).to include({ id: "2998", line: 6 }, { id: "2999", line: 8 })
  end

  it "resolves protocol and port clauses against the actual service listener" do
    input = "ssh server port 2222\nacl advanced 3000\n rule 5 permit tcp source 192.0.2.0 0.0.0.255 destination-port eq 2222\n rule 10 deny\n#\nline vty 0 4\n protocol inbound ssh\n acl 3000 inbound\n#\n"
    entry = evidence(input).fact("management.access_endpoints").first
    expect(entry).to include(port: 2222, sources: [ "192.0.2.0/24" ], complete: true)
  end
end

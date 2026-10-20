# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Cisco TACACS group address and object references" do
  def report(definitions, member, platform: "cisco_ios", suffix: "")
    text = "hostname LAB\naaa new-model\n#{definitions}\naaa group server tacacs+ OPS\n #{member}\n!\n" \
      "#{suffix}aaa authentication login default group OPS local\nline vty 0 4\n login authentication default\n transport input ssh\n!\n"
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.login" => { "expected" => true } })
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
  end

  it "resolves a literal group address using the same canonical identity as its host definition" do
    result = report("tacacs-server host 2001:db8::10", "server 2001:0DB8:0:0:0:0:0:10")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.groups")).to eq("OPS" => [ "2001:db8::10" ])
  end

  it "does not resolve a missing named object through a coincident DNS host address" do
    result = report("tacacs-server host aaa1", "server name aaa1")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.findings.first.diagnostics).to include(include(code: :tacacs_group_unresolved))
  end

  it "retains named reference identity separately from the referenced canonical server addresses" do
    definition = "tacacs server AAA.Example.TEST\n address ipv6 2001:0DB8:0:0:0:0:0:10\n!"
    result = report(definition, "server name AAA.Example.TEST")
    expect(result).to be_compliant
    references = result.configuration.fact("tacacs.group_references").fetch("OPS")
    expect(references).to contain_exactly(include(kind: "named_server", name: "AAA.Example.TEST", servers: [ "2001:db8::10" ], complete: true))
    expect(report(definition, "server name aaa.example.test").findings.first.status).to eq(:unknown)
  end

  it "merges reopened groups, removes canonical member identities and honors full withdrawal" do
    definitions = "tacacs-server host 2001:db8::10\ntacacs-server host 192.0.2.30\n"       "aaa group server tacacs+ OPS\n server 2001:0DB8:0:0:0:0:0:10\n!"
    result = report(definitions, "server 192.0.2.30")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.groups")["OPS"]).to eq([ "2001:db8::10", "192.0.2.30" ])
    removed = report(definitions, "no server 2001:db8::10\n server 192.0.2.30")
    expect(removed.configuration.fact("tacacs.groups")["OPS"]).to eq([ "192.0.2.30" ])
    withdrawn = report(definitions, "server 192.0.2.30", suffix: "no aaa group server tacacs+ OPS\n")
    expect(withdrawn.configuration.fact("tacacs.groups")).to eq({})
    expect(withdrawn.findings.first.status).to eq(:unknown)
  end

  it "retains unknown member syntax as unresolved metadata without copying its secret tail" do
    result = report("tacacs-server host 192.0.2.30", "server-private 192.0.2.99 key PRIVATE-UNKNOWN")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.fact("tacacs.group_references")["OPS"]).to contain_exactly(include(kind: "unresolved", complete: false))
    expect(result.configuration.facts.to_s).not_to include("PRIVATE-UNKNOWN")
  end

  it "normalizes NX-OS DNS address references without treating them as object names" do
    text = "hostname LAB\nfeature tacacs+\ntacacs-server host Time.EXAMPLE.TEST\n"       "aaa group server tacacs+ OPS\n server time.example.test\n!\naaa authentication login default group OPS\nline vty\n!\n"
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.login" => { "expected" => true } })
    result = Baseline::Audit.new(policy: policy).call(configuration: text, platform: "cisco_nxos", complete: true)
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.group_references")["OPS"]).to contain_exactly(include(kind: "address", address: "time.example.test", complete: true))
  end

  it "does not let an unparsed unused group mask a known selected group, while retaining incomplete inventory" do
    definitions = "tacacs-server host 192.0.2.30\naaa group server tacacs+ UNUSED\n server-private 192.0.2.99 key PRIVATE-UNKNOWN\n!"
    result = report(definitions, "server 192.0.2.30")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.group_inventory_complete")).to be(false)
    expect(result.configuration.facts.to_s).not_to include("PRIVATE-UNKNOWN")
  end

  it "removes deleted named servers from references, resources and credential evidence" do
    result = report("tacacs server OLD\n address ipv4 192.0.2.10\n key 0 SYNTHETIC-OLD\n!\nno tacacs server OLD", "server name OLD")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.fact("tacacs.servers")).to eq([])
    expect(result.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }).to eq([])
    expect(result.configuration.fact("credentials.records")).to eq([])
    expect(result.configuration.fact("tacacs.group_inventory_complete")).to be(false)
  end

  it "keeps only the final address of each named address family across reentry" do
    definitions = "tacacs server AAA\n address ipv4 192.0.2.10\n key 0 SYNTHETIC-OLD\n!\n" \
      "tacacs server AAA\n address ipv4 192.0.2.20\n address ipv6 2001:db8::20\n!"
    result = report(definitions, "server name AAA")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.20", "2001:db8::20" ])
    expect(result.configuration.fact("tacacs.groups")["OPS"]).to eq([ "192.0.2.20", "2001:db8::20" ])
    expect(result.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }.map { |r| r.attributes["address"] }).to match_array([ "192.0.2.20", "2001:db8::20" ])
  end

  it "does not carry a deleted object's key into its recreated definition" do
    definitions = "tacacs server AAA\n address ipv4 192.0.2.10\n key 0 SYNTHETIC-OLD\n!\nno tacacs server AAA\n" \
      "tacacs server AAA\n address ipv4 192.0.2.20\n!"
    result = report(definitions, "server name AAA")
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.20" ])
    expect(result.configuration.fact("tacacs.keys_present")).to be(false)
    expect(result.configuration.fact("credentials.records")).to eq([])
  end

  it "honors address and key withdrawal on reopened named servers" do
    definitions = "tacacs server AAA\n address ipv4 192.0.2.10\n address ipv6 2001:db8::10\n key 0 SYNTHETIC-OLD\n!\n" \
      "tacacs server AAA\n no address ipv6 2001:0DB8::10\n no key\n!"
    result = report(definitions, "server name AAA")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.10" ])
    expect(result.configuration.fact("tacacs.keys_present")).to be(false)
    expect(result.configuration.fact("credentials.records")).to eq([])
  end

  it "does not use withdrawn global material as proof of a server key" do
    result = report("tacacs-server key 7 SYNTHETIC-GLOBAL\nno tacacs-server key\ntacacs server AAA\n address ipv4 192.0.2.10\n no key\n!", "server name AAA")
    expect(result.configuration.fact("tacacs.keys_present")).to be(false)
    expect(result.configuration.fact("credentials.records")).to eq([])
  end

  it "does not certify a malformed address withdrawal as complete reference evidence" do
    result = report("tacacs server AAA\n address ipv4 192.0.2.10\n address ipv6 2001:db8::10\n no address ipv4 192.0.2.10 unexpected\n!", "server name AAA")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.fact_known?("tacacs.group_inventory_complete")).to be(false)
  end


  it "does not interpret a key encoding marker without material as a plaintext secret" do
    result = report("tacacs server AAA\n address ipv4 192.0.2.10\n key 7\n!", "server name AAA")
    expect(result.configuration.fact_known?("tacacs.keys_present")).to be(false)
    expect(result.configuration.fact("credentials.records")).to eq([])
  end

  it "rejects missing inline legacy key material rather than treating its encoding marker as a secret" do
    result = report("tacacs-server host 192.0.2.10 key 7", "server 192.0.2.10")
    expect(result.configuration.fact_known?("tacacs.keys_present")).to be(false)
    expect(result.configuration.fact("credentials.records")).to eq([])
  end

  it "does not borrow a key from another named object with the same canonical address" do
    definitions = "tacacs server AAA\n address ipv6 2001:db8::10\n key 7 SYNTHETIC-KEY\n!\n" \
      "tacacs server BBB\n address ipv6 2001:0DB8:0:0:0:0:0:10\n!"
    result = report(definitions, "server name BBB")
    expect(result).to be_compliant
    expect(result.configuration.fact("tacacs.keys_present")).to be(false)
  end
end

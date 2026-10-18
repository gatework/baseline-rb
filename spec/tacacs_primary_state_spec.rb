# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "H3C TACACS primary server slots" do
  def report(commands)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.minimum_servers" => { "expected" => 2 } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\nhwtacacs scheme OPS\n#{commands}\n", platform: "h3c", complete: true)
  end

  it "does not count a replaced primary server as redundancy or retain its resource" do
    result = report(" primary authentication 192.0.2.30\n primary authentication 192.0.2.31")
    expect(result.findings.first.status).to eq(:fail)
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.31" ])
    expect(result.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }.map { |r| r.identity["address"] }).to eq([ "192.0.2.31" ])
  end

  it "preserves multiple secondary servers and independent primary roles" do
    result = report(" primary authentication 192.0.2.30\n primary authentication 192.0.2.31\n" \
      " secondary authentication 192.0.2.32\n secondary authentication 192.0.2.33\n primary authorization 192.0.2.30")
    expect(result.configuration.fact("tacacs.servers")).to contain_exactly("192.0.2.30", "192.0.2.31", "192.0.2.32", "192.0.2.33")
    resources = result.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }
    expect(resources.size).to eq(4)
    expect(resources.count { |r| r.identity["priority"] == "secondary" }).to eq(2)
  end

  it "applies an unqualified primary reset and permits subsequent reconfiguration" do
    body = " primary authentication 192.0.2.30\n secondary authentication 192.0.2.31\n undo primary authentication"
    removed = report(body)
    expect(removed.configuration.fact_known?("tacacs.servers")).to be(true)
    expect(removed.configuration.fact("tacacs.servers")).to eq([ "192.0.2.31" ])
    expect(removed.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }.size).to eq(1)
    restored = report(body + "\n primary authentication 192.0.2.32")
    expect(restored.configuration.fact("tacacs.servers")).to contain_exactly("192.0.2.31", "192.0.2.32")
  end

  it "does not fall back to an old primary after a malformed replacement" do
    result = report(" primary authentication 192.0.2.30\n primary authentication")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.resources.select { |r| r.kind == "tacacs.endpoint" }).to eq([])
  end

  it "does not let removal of an old address delete a later primary" do
    result = report(" primary authentication 192.0.2.30\n primary authentication 192.0.2.31\n undo primary authentication 192.0.2.30")
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.31" ])
  end
end

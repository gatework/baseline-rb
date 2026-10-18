# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "TACACS endpoint resources" do
  %w[h3c huawei cisco_ios cisco_nxos hillstone palo_alto].each do |platform|
    it "retains #{platform} endpoint objects without key material" do
      text = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))
      report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: platform, complete: true)
      resources = report.configuration.resources.select { |item| item.kind == "tacacs.endpoint" }
      expect(resources).not_to be_empty
      addresses = resources.map { |item| item.identity["address"] || item.attributes["address"] }.uniq
      expect(addresses).to match_array(%w[192.0.2.30 192.0.2.31])
      expect(resources.map(&:to_h).to_json).not_to include("PRIVATE-", "SYNTHETIC-KEY")
      expect(resources).to all(be_frozen)
    end
  end

  it "retains separate Comware authentication roles and primary/secondary targets" do
    text = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30 49\n" \
      " primary authorization 192.0.2.30 49\n secondary authentication 192.0.2.31 149 vpn-instance MGMT\n"
    report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: "h3c", complete: true)
    resources = report.configuration.resources.select { |item| item.kind == "tacacs.endpoint" }
    expect(resources.size).to eq(3)
    expect(resources.map { |item| item.identity["role"] }).to match_array(%w[authentication authorization authentication])
    secondary = resources.find { |item| item.identity["priority"] == "secondary" }
    expect(secondary.scope).to eq("group" => "OPS", "vrf" => "MGMT")
    expect(secondary.attributes).to eq("port" => 149)
  end

  it "cancels one Comware role without removing another role for the same address" do
    text = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n" \
      " primary authorization 192.0.2.30\n undo primary authentication 192.0.2.30\n"
    report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: "h3c", complete: true)
    resources = report.configuration.resources.select { |item| item.kind == "tacacs.endpoint" }
    expect(resources.size).to eq(1)
    expect(resources.first.identity["role"]).to eq("authorization")
  end

  it "marks unknown Comware endpoint options incomplete and does not copy their values" do
    text = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30 custom PRIVATE-OPTION\n"
    report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: "h3c", complete: true)
    resource = report.configuration.resources.find { |item| item.kind == "tacacs.endpoint" }
    expect(resource).not_to be_complete
    expect(resource.to_h.to_json).not_to include("PRIVATE-OPTION")
  end
end

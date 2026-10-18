# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "H3C SNMP version state" do
  def evidence(commands)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "snmp.versions" => { "expected" => [ "v3" ] } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\nsnmp-agent\n#{commands}\n", platform: "h3c", complete: true).configuration
  end

  it "retains enabled versions across additive declarations" do
    config = evidence("snmp-agent sys-info version v2c\nsnmp-agent sys-info version v3")
    expect(config.fact("snmp.versions")).to contain_exactly("v2c", "v3")
  end

  it "subtracts only explicitly disabled versions" do
    config = evidence("snmp-agent sys-info version all\nundo snmp-agent sys-info version v1 v2c")
    expect(config.fact("snmp.versions")).to eq([ "v3" ])
  end

  it "recognizes disabling all versions before enabling a subset" do
    config = evidence("snmp-agent sys-info version all\nundo snmp-agent sys-info version all\nsnmp-agent sys-info version v3")
    expect(config.fact("snmp.versions")).to eq([ "v3" ])
  end

  it "does not preserve a stale passing version after malformed declarations or resets" do
    [ "snmp-agent sys-info version", "snmp-agent sys-info version v4", "undo snmp-agent sys-info version garbage" ].each do |line|
      config = evidence("snmp-agent sys-info version v3\n#{line}")
      expect(config.fact_known?("snmp.versions")).to be(false)
    end
  end

  it "keeps uncertainty after an isolated removal followed by a partial enable" do
    config = evidence("undo snmp-agent sys-info version v1\nsnmp-agent sys-info version v3")
    expect(config.fact_known?("snmp.versions")).to be(false)
  end

  it "does not mistake repeated removal tokens for disabling all versions" do
    config = evidence("snmp-agent sys-info version all\nundo snmp-agent sys-info version v1 v1 v2c")
    expect(config.fact("snmp.versions")).to eq([ "v3" ])
  end

  it "does not infer the remaining versions from an isolated partial removal" do
    expect(evidence("undo snmp-agent sys-info version v1").fact_known?("snmp.versions")).to be(false)
  end
end

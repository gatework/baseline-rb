# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Comware and VRP SNMP service evidence" do
  def report(commands, platform: "h3c", complete: true, expected: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "snmp.enabled" => { "expected" => expected } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{commands}\n", platform: platform, complete: complete)
  end

  %w[h3c huawei].each do |platform|
    it "keeps unknown and malformed #{platform} commands unresolved for either expected state" do
      [ "snmp-agent unsupported-option", "snmp-agent community read cipher", "snmp-agent group", "snmp-agent sys-info version v4" ].each do |command|
        [ true, false ].each do |expected|
          expect(report(command, platform: platform, expected: expected).findings.first.status).to eq(:unknown)
        end
      end
    end

    it "resolves #{platform} state in command order without losing explicit enable evidence" do
      expect(report("snmp-agent\nsnmp-agent unsupported-option", platform: platform).findings.first.status).to eq(:pass)
      expect(report("undo snmp-agent\nsnmp-agent unsupported-option", platform: platform).findings.first.status).to eq(:unknown)
      expect(report("snmp-agent unsupported-option\nundo snmp-agent", platform: platform, expected: false).findings.first.status).to eq(:pass)
      expect(report("snmp-agent unsupported-option\nsnmp-agent", platform: platform).findings.first.status).to eq(:pass)
    end

    it "accepts validated implicit #{platform} enable commands and records their source" do
      [ "snmp-agent sys-info version v3", "snmp-agent community read cipher SYNTHETIC-COMMUNITY", "snmp-agent group v3 OPS privacy" ].each do |command|
        result = report("undo snmp-agent\n#{command}", platform: platform)
        expect(result.findings.first.status).to eq(:pass)
        expect(result.configuration.fact("snmp.enabled")).to be(true)
        expect(result.configuration.sources.fetch("snmp.enabled")).to eq([ 2, 3 ])
      end
    end
  end

  it "does not enable H3C SNMP through password calculation or expose its material" do
    utility = "snmp-agent calculate-password SYNTHETIC-SECRET mode sha local-engineid"
    [ utility, "undo snmp-agent\n#{utility}" ].each do |commands|
      result = report(commands, expected: false)
      expect(result.findings.first.status).to eq(:pass)
      expect(result.to_h.to_s).not_to include("SYNTHETIC-SECRET")
    end
    expect(report("snmp-agent\n#{utility}").findings.first.status).to eq(:pass)
  end

  it "does not transfer the H3C calculation exception to VRP" do
    expect(report("snmp-agent calculate-password SYNTHETIC-SECRET mode sha local-engineid", platform: "huawei").findings.first.status).to eq(:unknown)
  end

  it "requires complete input to infer the absent default" do
    expect(report("", expected: false).findings.first.status).to eq(:pass)
    expect(report("", complete: false, expected: false).findings.first.status).to eq(:unknown)
  end

  it "validates numeric ACLs and listener ports before using them as enable evidence" do
    %w[1999 4000 99999].each do |acl|
      expect(report("snmp-agent acl #{acl}").findings.first.status).to eq(:unknown)
    end
    [ "snmp-agent port 0", "snmp-agent port 65536", "snmp-agent port 161 extra" ].each do |command|
      expect(report(command).findings.first.status).to eq(:unknown)
    end
    expect(report("snmp-agent acl 2000").findings.first.status).to eq(:pass)
    expect(report("snmp-agent acl 3000").findings.first.status).to eq(:pass)
    expect(report("snmp-agent port 1161").findings.first.status).to eq(:pass)
  end

  it "distinguishes complete user security declarations from unsupported algorithms" do
    user = "snmp-agent usm-user v3 observer OPS authentication-mode %s cipher SYNTHETIC-SECRET"
    expect(report(user % "sha").findings.first.status).to eq(:pass)
    expect(report(user % "unsupported").findings.first.status).to eq(:unknown)
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Acl do
  it "owns its name without freezing the caller's string" do
    name = +"MGMT"
    value = described_class.new(name: name, line: 1, rules: [])
    expect(name).not_to be_frozen
    name.replace("OTHER")
    expect(value.name).to eq("MGMT")
    expect(value.name).to be_frozen
  end

  it "names permitted source networks separately from raw ACL rules and source locations" do
    value = acl([ [ "deny", "192.0.2.0/25" ], [ "permit", "192.0.2.0/24" ] ])
    expect(value.permitted_source_networks(protocol: "tcp")).to eq([ "192.0.2.128/25" ])
    expect(acl([]).permitted_source_networks(protocol: "tcp")).to be_nil
  end

  def acl(rules)
    described_class.new(name: "MGMT", line: 1, rules: rules.map.with_index do |(action, source, protocol), index|
      { action: action, source: source, protocol: protocol || "ip", sequence: index }
    end)
  end

  it "uses first-match order instead of collecting every permit" do
    value = acl([ [ "deny", "198.51.100.128/25" ], [ "permit", "198.51.100.0/24" ] ])
    expect(value.permitted_source_networks(protocol: "tcp")).to eq([ "198.51.100.0/25" ])
    reversed = acl([ [ "permit", "0.0.0.0/0" ], [ "deny", "0.0.0.0/0" ] ])
    expect(reversed.permitted_source_networks(protocol: "tcp")).to eq([ "0.0.0.0/0" ])
    expect(acl([ [ "deny", "0.0.0.0/0" ], [ "permit", "0.0.0.0/0" ] ]).permitted_source_networks(protocol: "tcp")).to eq([])
  end

  it "applies protocol-specific rules only to the matching service" do
    value = acl([ [ "deny", "198.51.100.128/25", "udp" ], [ "permit", "198.51.100.0/24" ] ])
    expect(value.permitted_source_networks(protocol: "tcp")).to eq([ "198.51.100.0/24" ])
    expect(value.permitted_source_networks(protocol: "udp")).to eq([ "198.51.100.0/25" ])
  end

  it "applies destination port conditions in order and requires a known matching service" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 5, action: "permit", protocol: "udp", source: "0.0.0.0/0", destination_port: 161 },
      { sequence: 10, action: "deny", protocol: "tcp", source: "198.51.100.128/25", destination_port: 22 },
      { sequence: 15, action: "permit", protocol: "tcp", source: "198.51.100.0/24", destination_port: 22 },
      { sequence: 20, action: "permit", protocol: "tcp", source: "0.0.0.0/0", destination_port: 80 }
    ])
    expect(value.permitted_source_networks(protocol: "tcp", port: 22)).to eq([ "198.51.100.0/25" ])
    expect(value.permitted_source_networks(protocol: "tcp", port: 23)).to eq([])
    expect(value.permitted_source_networks(protocol: "tcp")).to be_nil
    expect(value.permitted_source_networks(protocol: "udp", port: 162)).to eq([])
    expect(value.permitted_source_networks(protocol: "icmp")).to eq([])
  end

  it "compares CIDR coverage rather than string equality" do
    expect(described_class.networks_within?([ "198.51.100.0/24" ], %w[198.51.100.0/25 198.51.100.128/25])).to be(true)
    expect(described_class.networks_within?([ "0.0.0.0/0" ], [ "198.51.100.0/24" ])).to be(false)
    expect(described_class.source_network("198.51.100.7", "0")).to eq("198.51.100.7/32")
    expect { described_class.source_network("198.51.100.0", "0.0.1.1") }.to raise_error(ArgumentError)
  end

  it "compares network unions across gaps, overlapping approvals, and IPv4 endpoints" do
    expect(described_class.networks_within?([], [])).to be(true)
    expect(described_class.networks_within?([ "0.0.0.0/0" ], [])).to be(false)
    expect(described_class.networks_within?(%w[0.0.0.0/32 255.255.255.255/32], [ "0.0.0.0/0" ])).to be(true)
    expect(described_class.networks_within?([ "192.0.2.0/24" ], %w[192.0.2.0/26 192.0.2.128/25])).to be(false)
    expect(described_class.networks_within?([ "192.0.2.0/24" ], %w[192.0.2.128/25 192.0.2.0/25 192.0.2.0/26])).to be(true)

    random = Random.new(614)
    40.times do
      actual, approved = 2.times.map do
        8.times.map do
          network = IPAddr.new("192.0.2.#{random.rand(256)}").mask(random.rand(24..32))
          "#{network}/#{network.prefix}"
        end
      end
      actual_ips, approved_ips = [ actual, approved ].map { |list| list.map { |cidr| IPAddr.new(cidr) } }
      expected = 256.times.all? do |index|
        ip = IPAddr.new("192.0.2.#{index}")
        actual_ips.none? { |network| network.include?(ip) } || approved_ips.any? { |network| network.include?(ip) }
      end
      expect(described_class.networks_within?(actual, approved)).to eq(expected)
    end
  end

  it "reports unapproved original networks in input order without losing duplicate evidence" do
    actual = %w[203.0.113.0/24 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24]
    approved = %w[192.0.2.128/25 192.0.2.0/25]
    expect(described_class.unapproved_networks(actual, approved)).to eq(%w[203.0.113.0/24 198.51.100.0/24 203.0.113.0/24])
    expect(described_class.unapproved_networks([], [])).to eq([])
    expect(described_class.unapproved_networks([ "192.0.2.0/24" ], [ "192.0.2.0/25" ])).to eq([ "192.0.2.0/24" ])
    expect(actual.size).to eq(4)
    expect(approved.size).to eq(2)
  end

  it "does not treat empty or unsupported ACL definitions as known restrictions" do
    expect(acl([]).permitted_source_networks(protocol: "tcp")).to be_nil
    value = described_class.new(name: "MGMT", rules: [], line: 1, supported: false)
    expect(value.permitted_source_networks(protocol: "tcp")).to be_nil
  end

  it "preserves first-match precedence when adjacent ranges, tied sequences, and IPv4 endpoints overlap" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 1, action: "deny", protocol: "ip", source: "0.0.0.0/32" },
      { sequence: 2, action: "permit", protocol: "ip", source: "255.255.255.255/32" },
      { sequence: 2, action: "deny", protocol: "ip", source: "255.255.255.255/32" },
      { sequence: 3, action: "deny", protocol: "ip", source: "0.0.0.0/0" },
      { sequence: 4, action: "permit", protocol: "ip", source: "0.0.0.0/0" }
    ])
    expect(value.permitted_source_networks(protocol: "tcp", port: 22)).to eq([ "255.255.255.255/32" ])
  end

  it "does not resolve an unknown destination port from an earlier covering rule" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 1, action: "permit", protocol: "ip", source: "0.0.0.0/0" },
      { sequence: 2, action: "deny", protocol: "tcp", source: "192.0.2.0/24", destination_port: 22 }
    ])
    expect(value.permitted_source_networks(protocol: "tcp")).to be_nil
    expect(value.permitted_source_networks(protocol: "udp")).to eq([ "0.0.0.0/0" ])
  end

  it "matches independent per-address first-match decisions across overlapping policies" do
    random = Random.new(53_021)
    addresses = 256.times.map { |index| IPAddr.new("192.0.2.#{index}") }
    60.times do
      rules = 40.times.map do
        source = IPAddr.new("192.0.2.#{random.rand(256)}").mask(random.rand(24..32))
        { sequence: random.rand(20), action: %w[permit deny].sample(random: random),
          protocol: %w[ip tcp udp icmp].sample(random: random), source: "#{source}/#{source.prefix}",
          destination_port: [ nil, 22, 23, 161 ].sample(random: random) }.compact
      end
      value = described_class.new(name: "MGMT", line: 1, rules: rules)
      ordered = rules.sort_by { |rule| rule.fetch(:sequence) }.map { |rule| [ rule, IPAddr.new(rule.fetch(:source)) ] }
      [ [ "tcp", 22 ], [ "tcp", 23 ], [ "udp", 161 ] ].each do |protocol, port|
        expected = addresses.select do |address|
          matching = ordered.find do |rule, network|
            [ "ip", protocol ].include?(rule.fetch(:protocol)) &&
              (!rule[:destination_port] || rule[:destination_port] == port) && network.include?(address)
          end
          matching && matching.first.fetch(:action) == "permit"
        end
        networks = value.permitted_source_networks(protocol: protocol, port: port).map { |cidr| IPAddr.new(cidr) }
        actual = addresses.select { |address| networks.any? { |network| network.include?(address) } }
        expect(actual).to eq(expected)
      end
    end
  end
end

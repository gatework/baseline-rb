# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Acl do
  def acl(rules)
    described_class.new(name: "MGMT", line: 1, rules: rules.map.with_index do |(action, source, protocol), index|
      { action: action, source: source, protocol: protocol || "ip", sequence: index }
    end)
  end

  it "uses first-match order instead of collecting every permit" do
    value = acl([ [ "deny", "198.51.100.128/25" ], [ "permit", "198.51.100.0/24" ] ])
    expect(value.sources(protocol: "tcp")).to eq([ "198.51.100.0/25" ])
    reversed = acl([ [ "permit", "0.0.0.0/0" ], [ "deny", "0.0.0.0/0" ] ])
    expect(reversed.sources(protocol: "tcp")).to eq([ "0.0.0.0/0" ])
    expect(acl([ [ "deny", "0.0.0.0/0" ], [ "permit", "0.0.0.0/0" ] ]).sources(protocol: "tcp")).to eq([])
  end

  it "applies protocol-specific rules only to the matching service" do
    value = acl([ [ "deny", "198.51.100.128/25", "udp" ], [ "permit", "198.51.100.0/24" ] ])
    expect(value.sources(protocol: "tcp")).to eq([ "198.51.100.0/24" ])
    expect(value.sources(protocol: "udp")).to eq([ "198.51.100.0/25" ])
  end

  it "applies destination port conditions in order and requires a known matching service" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 5, action: "permit", protocol: "udp", source: "0.0.0.0/0", destination_port: 161 },
      { sequence: 10, action: "deny", protocol: "tcp", source: "198.51.100.128/25", destination_port: 22 },
      { sequence: 15, action: "permit", protocol: "tcp", source: "198.51.100.0/24", destination_port: 22 },
      { sequence: 20, action: "permit", protocol: "tcp", source: "0.0.0.0/0", destination_port: 80 }
    ])
    expect(value.sources(protocol: "tcp", port: 22)).to eq([ "198.51.100.0/25" ])
    expect(value.sources(protocol: "tcp", port: 23)).to eq([])
    expect(value.sources(protocol: "tcp")).to be_nil
    expect(value.sources(protocol: "udp", port: 162)).to eq([])
    expect(value.sources(protocol: "icmp")).to eq([])
  end

  it "compares CIDR coverage rather than string equality" do
    expect(described_class.within?([ "198.51.100.0/24" ], %w[198.51.100.0/25 198.51.100.128/25])).to be(true)
    expect(described_class.within?([ "0.0.0.0/0" ], [ "198.51.100.0/24" ])).to be(false)
    expect(described_class.source("198.51.100.7", "0")).to eq("198.51.100.7/32")
    expect { described_class.source("198.51.100.0", "0.0.1.1") }.to raise_error(ArgumentError)
  end

  it "does not treat empty or unsupported ACL definitions as known restrictions" do
    expect(acl([]).sources(protocol: "tcp")).to be_nil
    value = described_class.new(name: "MGMT", rules: [], line: 1, supported: false)
    expect(value.sources(protocol: "tcp")).to be_nil
  end

  it "preserves first-match precedence when adjacent ranges, tied sequences, and IPv4 endpoints overlap" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 1, action: "deny", protocol: "ip", source: "0.0.0.0/32" },
      { sequence: 2, action: "permit", protocol: "ip", source: "255.255.255.255/32" },
      { sequence: 2, action: "deny", protocol: "ip", source: "255.255.255.255/32" },
      { sequence: 3, action: "deny", protocol: "ip", source: "0.0.0.0/0" },
      { sequence: 4, action: "permit", protocol: "ip", source: "0.0.0.0/0" }
    ])
    expect(value.sources(protocol: "tcp", port: 22)).to eq([ "255.255.255.255/32" ])
  end

  it "does not resolve an unknown destination port from an earlier covering rule" do
    value = described_class.new(name: "MGMT", line: 1, rules: [
      { sequence: 1, action: "permit", protocol: "ip", source: "0.0.0.0/0" },
      { sequence: 2, action: "deny", protocol: "tcp", source: "192.0.2.0/24", destination_port: 22 }
    ])
    expect(value.sources(protocol: "tcp")).to be_nil
    expect(value.sources(protocol: "udp")).to eq([ "0.0.0.0/0" ])
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
        networks = value.sources(protocol: protocol, port: port).map { |cidr| IPAddr.new(cidr) }
        actual = addresses.select { |address| networks.any? { |network| network.include?(address) } }
        expect(actual).to eq(expected)
      end
    end
  end
end

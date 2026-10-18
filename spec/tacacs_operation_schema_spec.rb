# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Typed TACACS operations" do
  let(:endpoint) { { "address" => "192.0.2.30", "port" => 49, "vrf" => "default", "single_connection" => false } }
  let(:parameters) do
    { kind: "tacacs.primary", identity: { "role" => "authentication" }, scope: { "group" => "OPS" },
      before: nil, after: endpoint, action: :add, phase: :create, risk: "high" }
  end

  it "owns immutable endpoint parameters and renders only the typed view" do
    operation = Baseline::ConfigurationOperation.new(**parameters)
    endpoint["port"] = 149
    expect(operation.after["port"]).to eq(49)
    expect(operation.after).to be_frozen
    steps = Baseline::H3c::CommandRenderer.new.render(operation)
    expect(steps.map(&:command)).to eq([ "primary authentication 192.0.2.30 49" ])
    expect(steps.first.view).to eq([ "hwtacacs scheme OPS" ])
  end

  it "rejects secret fields, raw commands and invalid shape before export" do
    [ { "key" => "PRIVATE" }, { "command" => "quit" }, { "port" => 0 }, { "single_connection" => "false" } ].each do |extra|
      expect { Baseline::ConfigurationOperation.new(**parameters.merge(after: endpoint.merge(extra))) }.to raise_error(ArgumentError)
    end
    expect { Baseline::ConfigurationOperation.new(**parameters.merge(scope: { "group" => "OPS\nquit" })) }.to raise_error(ArgumentError)
    expect { Baseline::ConfigurationOperation.new(**parameters.merge(phase: :remove)) }.to raise_error(ArgumentError)
  end

  it "refuses unvalidated routing and multicast addresses at the vendor renderer" do
    [ { "vrf" => "MGMT" }, { "address" => "224.0.0.1" }, { "address" => "ff02::1" } ].each do |extra|
      operation = Baseline::ConfigurationOperation.new(**parameters.merge(after: endpoint.merge(extra)))
      error = extra.key?("vrf") ? Baseline::CommandRenderer::UnsupportedOperation : ArgumentError
      expect { Baseline::H3c::CommandRenderer.new.render(operation) }.to raise_error(error)
    end
  end
end

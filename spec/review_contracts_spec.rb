# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline review contracts" do
  it "rejects normalized identity collisions in either insertion order" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => true } })
    audit = Baseline::Audit.new(policy: policy)
    [ { host: "LEAF", "host" => "OTHER" }, { "host" => "OTHER", host: "LEAF" } ].each do |context|
      expect { audit.call(configuration: "sysname LAB\nssh server enable\n", platform: :h3c, complete: true, context: context) }.to raise_error(ArgumentError)
    end
  end

  {
    h3c: "sysname LAB\nntp-service source Loopback0\ninfo-center loghost source Loopback0\nntp-service authentication enable\n",
    huawei: "sysname LAB\nntp-service source-interface Loopback0\ninfo-center loghost source Loopback0\nntp-service authentication enable\n",
    cisco_ios: "hostname LAB\nntp source Loopback0\nlogging source-interface Loopback0\nntp authenticate\n",
    cisco_nxos: "hostname LAB\nntp source-interface Loopback0\nlogging source-interface Loopback0\nntp authenticate\n",
    hillstone: "hostname LAB\nntp server 192.0.2.1 source Loopback0\nlogging syslog 192.0.2.2 source-interface Loopback0 udp 514\n",
    palo_alto: "set deviceconfig system hostname LAB\nset deviceconfig system route service ntp source interface Loopback0\nset deviceconfig system route service syslog source interface Loopback0\n"
  }.each do |platform, text|
    it "retains scalar source captures and report lines for #{platform}" do
      checks = %w[ntp.source syslog.source].to_h { |name| [ name, { "expected" => "Loopback1" } ] }
      policy = Baseline::Policy.new("version" => 1, "checks" => checks)
      report = Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
      expect(report.findings.map(&:status)).to eq([ :fail, :fail ])
      expect(report.findings.map(&:lines)).to eq([ [ 2 ], [ 3 ] ])
      parser = Baseline::Audit::PARSERS.fetch(platform.to_s).new
      parser.parse(text, complete: true)
      expect(parser.cursor.captures_for([ "facts", "ntp.source" ]).map(&:line_range)).to eq([ 2..2 ])
      expect(parser.cursor.captures_for([ "facts", "syslog.source" ]).map(&:line_range)).to eq([ 3..3 ])
    end
  end
end

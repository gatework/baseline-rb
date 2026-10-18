# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Document do
  it "retains source blocks while isolating banner bodies, metadata, and explicit boundaries" do
    text = "Building configuration...\r\nhostname LEAF\n! generated\r\ninterface Ethernet1/1\r\n description edge\n# end section\r\nbanner motd ^C\r\nhostname FORGED\n! not a boundary\n^C\nntp server 192.0.2.10\nend\n"
    document = described_class.new(text)

    expect(document).to be_a(CtxParser::Document)
    expect(document.roots.map(&:text)).to eq([ "hostname LEAF", "interface Ethernet1/1", "ntp server 192.0.2.10" ])
    expect(document.roots).to all(be_a(CtxParser::Block))
    expect(document.roots[1].content).to eq("interface Ethernet1/1\r\n description edge\n")
    expect(document.cursor.content).to eq(text)
    expect(document.cursor.state(7)).to eq(:ignored)
    expect(document.issues).to be_empty
  end

  it "preserves incomplete-output diagnostics and allows a one-line header delimiter" do
    document = described_class.new("header login information %hello%\nsysname AC\n-- More --\nbanner motd ^C\nunfinished\n")

    expect(document.roots.map(&:text)).to eq([ "sysname AC" ])
    expect(document.cursor.lines.map(&:text)).to include("-- More --")
    expect(document.issues).to eq([ { code: :incomplete_configuration, line: 3 }, { code: :incomplete_banner } ])
    expect(document.cursor.state(4)).to eq(:ignored)
  end
end

RSpec.describe "Baseline parse sessions" do
  Baseline::Audit::PARSERS.each do |platform, parser_class|
    it "isolates #{platform} facts, credentials, and sources across successive parses" do
      parser = parser_class.new
      first = parser.parse(File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__)), complete: true)
      first_document = parser.document
      original = CtxParser::Immutable.copy(first.to_h)
      hostname = case platform
      when "palo_alto" then "set deviceconfig system hostname"
      when "h3c", "huawei" then "sysname"
      else "hostname"
      end

      expect(parser.parse("\xff".b, complete: true).status).to eq(:failed)
      expect(parser.cursor).to be_nil
      second = parser.parse("#{hostname} SECOND\n", complete: true)
      expect(second.records.first.fetch("facts")).to include("hostname" => "SECOND", "ntp.servers" => [],
        "acls" => [], "ssh.vty" => [], "snmp.users" => [], "credentials.records" => [])
      expect(parser.document).not_to equal(first_document)
      expect(parser.cursor.captures.map(&:data)).to eq([ "SECOND" ])
      expect(first.to_h).to eq(original)
    end
  end

  it "captures Comware log hosts after excluding the source-interface command" do
    parser = Baseline::H3c::Parser.new
    text = "sysname LAB\ninfo-center loghost 192.0.2.10\ninfo-center loghost source LoopBack0\n"
    result = parser.parse(text, complete: true)

    expect(result.records.first.fetch("facts").fetch("syslog.servers")).to eq([ "192.0.2.10" ])
    expect(parser.cursor.captures_for([ "facts", "syslog.servers" ]).map(&:data)).to all(eq([ "192.0.2.10" ]))
    incomplete = parser.parse("sysname LAB\ninfo-center loghost source LoopBack0\n")
    expect(incomplete.records.first.fetch("facts")).not_to have_key("syslog.servers")
    expect(parser.cursor.captures_for([ "facts", "syslog.servers" ])).to be_empty
  end
end

RSpec.describe Baseline::CiscoNxos::Parser do
  it "shares one frozen reduced fact across its source commands without mixing later parse versions" do
    parser = described_class.new
    source = "hostname LEAF\nntp server 192.0.2.1\nntp server 192.0.2.2\n"
    result = parser.parse(source, complete: true)
    captures = parser.cursor.captures_for([ "facts", "ntp.servers" ])
    expect(captures.map(&:data)).to all(eq([ "192.0.2.1", "192.0.2.2" ]))
    expect(captures.last.data).to equal(captures.first.data)
    expect(captures.first.data).not_to equal(result.records.first.fetch("facts").fetch("ntp.servers"))
    expect(captures.map(&:line_range)).to eq([ 2..2, 3..3 ])
    expect(captures.map(&:content)).to eq([ "ntp server 192.0.2.1\n", "ntp server 192.0.2.2\n" ])

    parser.parse("hostname LEAF\nntp server 192.0.2.3\n", complete: true)
    expect(parser.cursor.captures_for([ "facts", "ntp.servers" ]).first.data).to eq([ "192.0.2.3" ])
    expect(captures.map(&:data)).to all(eq([ "192.0.2.1", "192.0.2.2" ]))
  end

  it "retains baseline facts and explicit sources while exposing stateful source provenance separately" do
    parser = described_class.new
    text = "hostname LEAF\r\nntp server 192.0.2.10\r\nip ssh custom-option\nfeature ssh\ninterface Ethernet1/1\r\n unknown child\nend\n"
    result = parser.parse(text, complete: true)

    expect(result).to be_complete
    expect(result.to_h.keys).to contain_exactly(:status, :records, :issues)
    expect(result.records.first.fetch("sources")).to eq("ssh.enabled" => [ 3, 4 ], "ntp.servers" => [ 2 ], "ntp.associations" => [ 2 ])
    expect(parser.document.cursor).to equal(parser.cursor)
    expect(parser.document.roots).to equal(parser.blocks)
    expect(parser.cursor.content).to eq(text)
    expect(parser.cursor.captures_for([ "facts", "hostname" ]).first.content).to eq("hostname LEAF\r\n")
    expect(parser.cursor.captures_for([ "facts", "ntp.servers" ]).first.data).to eq([ "192.0.2.10" ])
    expect(parser.cursor.captures_for([ "facts", "ssh.enabled" ]).map(&:line_range)).to eq([ 4..4 ])
    expect(parser.cursor.state(2)).to eq(:pending)
    expect(parser.cursor.unparsed_content).to include("ip ssh custom-option", "unknown child")
  end

  it "tracks supported ACL rules independently from unsupported syntax within the same block" do
    parser = described_class.new
    parser.parse("hostname LEAF\nip access-list MGMT\n 10 permit ip 192.0.2.0 0.0.0.255 any\n 20 deny tcp any any range 22 23\nend\n", complete: true)

    expect(parser.cursor.state(2)).to eq(:parsed)
    expect(parser.cursor.state(3)).to eq(:unsupported)
    expect(parser.blocks[1].content).to include("10 permit", "20 deny")
    expect(parser.blocks[1]).not_to be_complete
  end

  it "captures only reduced credential data and clears the source session before a later invalid input" do
    parser = described_class.new
    result = parser.parse("hostname LEAF\nusername admin secret 9 PRIVATE-SECRET\nend\n", complete: true)
    original_document = parser.document
    capture = parser.cursor.captures_for([ "facts", "credentials.records", 0 ]).first

    expect(capture.content).to include("PRIVATE-SECRET")
    expect(capture.data.to_s).not_to include("PRIVATE-SECRET")
    [ result, parser, parser.document, parser.cursor, capture ].each do |object|
      expect(object.to_json).not_to include("PRIVATE-SECRET")
      expect(object.inspect).not_to include("PRIVATE-SECRET")
    end
    invalid = parser.parse("\xff".b, complete: true)
    expect(invalid.status).to eq(:failed)
    expect(parser.document).to be_nil
    expect(parser.cursor).to be_nil
    expect(original_document.cursor.content).to include("PRIVATE-SECRET")
  end
end

RSpec.describe "Baseline hostname declaration evidence" do
  { "h3c" => "sysname", "huawei" => "sysname", "cisco_ios" => "hostname", "cisco_nxos" => "hostname",
    "hillstone" => "hostname", "palo_alto" => "set deviceconfig system hostname" }.each do |platform, command|
    it "does not reuse an earlier #{platform} identity after a malformed replacement" do
      [ command, "#{command} NEW extra" ].each do |last|
        result = Baseline::Audit::PARSERS.fetch(platform).parse("#{command} OLD\n#{last}\n", complete: true)
        configuration = Baseline::Evidence.new(platform: platform, sha256: "synthetic", result: result)
        expect(configuration.fact_known?("hostname")).to be(false)
        expect(configuration.fact("hostname")).to be_nil
        expect(configuration).not_to be_complete
      end
    end
  end
end

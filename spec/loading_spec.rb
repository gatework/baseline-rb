# frozen_string_literal: true

require_relative "spec_helper"
require "open3"
require "rbconfig"
require "json"
require "bundler"

RSpec.describe "Standalone baseline assessment" do
  {
    "h3c" => [ "H3c", "sysname LAB\n" ],
    "huawei" => [ "Huawei", "sysname LAB\n" ],
    "cisco_ios" => [ "CiscoIos", "hostname LAB\n" ],
    "cisco_nxos" => [ "CiscoNxos", "hostname LAB\n" ],
    "hillstone" => [ "Hillstone", "hostname LAB\n" ],
    "palo_alto" => [ "PaloAlto", "set deviceconfig system hostname LAB\n" ]
  }.each do |platform, (namespace, source)|
    it "loads and parses #{platform} independently of the aggregate entry point" do
      script = <<~RUBY
        require "baseline/#{platform}/parser"
        abort "Aggregate entry loaded" if defined?(Baseline::Audit)
        result = Baseline::#{namespace}::Parser.parse(#{source.inspect}, complete: true)
        abort "Missing parsed hostname" unless result.complete? && result.records.first.fetch("facts").fetch("hostname") == "LAB"
      RUBY
      _, stderr, status = Open3.capture3(RbConfig.ruby, "-rbundler/setup", "-I", File.expand_path("../lib", __dir__), "-e", script)
      expect(status).to be_success, stderr
    end
  end

  it "evaluates text without Rails, Netstack, a connector or a database" do
    script = <<~RUBY
      require "baseline"
      abort "Unexpected dependency" if defined?(Rails) || defined?(ActiveRecord) || defined?(Net::Connector::Result) || $LOADED_FEATURES.any? { |path| path.include?("/netstack") && !path.end_with?("/version.rb") }
      policy = Baseline::Policy.new("version" => 1, "checks" => {"ssh.enabled" => {"expected" => true}})
      audit = Baseline::Audit.new(policy: policy)
      inputs = { "h3c" => "sysname LAB\\nssh server enable\\n",
        "hillstone" => "hostname LAB\\ninterface ethernet0/0\\n  manage ssh\\nexit\\n",
        "palo_alto" => "set deviceconfig system hostname LAB\\nset deviceconfig system service disable-ssh no\\n" }
      reports = inputs.to_h do |platform, configuration|
        [platform, audit.call(configuration: configuration, platform: platform, complete: true).summary]
      end
      puts JSON.generate(reports)
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-rbundler/setup", "-I", File.expand_path("../lib", __dir__), "-e", script)

    expect(status).to be_success, stderr
    expect(JSON.parse(stdout).keys).to contain_exactly("h3c", "hillstone", "palo_alto")
    expect(JSON.parse(stdout).values).to all(include("status" => "pass", "compliant" => true))
  end
end

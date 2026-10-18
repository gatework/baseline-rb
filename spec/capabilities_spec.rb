# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline vendor capability contract" do
  Baseline::Audit::PARSERS.each_key do |platform|
    it "evaluates the same server, SSH and SNMP capabilities on #{platform}" do
      checks = { "ntp.servers" => { "expected" => %w[192.0.2.10 192.0.2.11] }, "syslog.minimum_servers" => { "expected" => 1 },
        "tacacs.minimum_servers" => { "expected" => 2 }, "ssh.enabled" => { "expected" => true }, "snmp.enabled" => { "expected" => true } }
      audit = Baseline::Audit.new(policy: Baseline::Policy.new("version" => 1, "checks" => checks))
      source = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))
      report = audit.call(configuration: source, platform: platform, complete: true)
      expect(report.findings.map(&:status)).to eq(Array.new(checks.size, :pass))
      expect(report).to be_compliant
      expect(Baseline::Audit.capabilities(platform: platform).slice(*checks.keys).values.map { |value| value[:status] }).to all(eq(:supported))
      partial = audit.call(configuration: source, platform: platform, complete: false)
      expect(partial.findings.map(&:status)).to all(eq(:unknown))
      expect(partial).not_to be_compliant
    end

    it "exposes an immutable entry for every public rule on #{platform}" do
      capabilities = Baseline::Audit.capabilities(platform: platform)
      expect(capabilities.keys).to eq(Baseline::Rule::DEFINITIONS.keys)
      expect(capabilities.values.map { |value| value[:status] }.uniq - %i[supported partial unsupported]).to be_empty
      expect { capabilities.fetch("ntp.servers")[:status] = :unsupported }.to raise_error(FrozenError)
    end
  end

  it "does not advertise a newly added rule as implemented without an explicit capability declaration" do
    definition = Baseline::Rule::Definition.new(title: "Future check", fact: "future.enabled", operator: :equals, value_type: :boolean)
    stub_const("Baseline::Rule::DEFINITIONS", Baseline::Rule::DEFINITIONS.merge("future.enabled" => definition))
    Baseline::Audit::PARSERS.each_key do |platform|
      expect(Baseline::Audit.capabilities(platform: platform).fetch("future.enabled")).to include(
        status: :unsupported, reason: :capability_unmodeled)
    end
  end

  it "uses the same aliases for capability lookup and runtime platform selection" do
    Baseline::Audit::ALIASES.each do |alias_name, canonical|
      expect(Baseline::Audit.capabilities(platform: alias_name)).to eq(Baseline::Audit.capabilities(platform: canonical))
    end
    expect(Baseline::Audit.normalize_platform(" PAN-OS ")).to eq("palo_alto")
    expect { Baseline::Audit.capabilities(platform: nil) }.to raise_error(ArgumentError)
    expect(Baseline::Audit.capabilities(platform: "future").values).to all(include(status: :unsupported, reason: :unsupported_platform))
  end

  %w[hillstone palo_alto].each do |platform|
    it "keeps unmodeled #{platform} capabilities unknown rather than silently excluding checks" do
      checks = { "ssh.vty_aaa" => { "expected" => true }, "tacacs.accounting" => { "expected" => true } }
      audit = Baseline::Audit.new(policy: Baseline::Policy.new("version" => 1, "checks" => checks))
      source = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))
      report = audit.call(configuration: source, platform: platform, complete: true)
      expect(report.findings.map(&:status)).to eq([ :unknown, :unknown ])
      expect(report.findings.map(&:reason)).to eq([ :unsupported_capability, :unsupported_capability ])
      expect(report.coverage).to eq(0.0)
      expect(report).not_to be_compliant
      expect(report.to_text).to include("尚未建模")
      expect(Baseline::Audit.capabilities(platform: platform).fetch("services.disabled")[:status]).to eq(:partial)
    end
  end
end

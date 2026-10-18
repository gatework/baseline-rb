# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Comware and VRP management AAA bindings" do
  def fixture(platform) = File.read(File.expand_path("fixtures/baseline/#{platform}.cfg", __dir__))

  def evidence(source, platform: "h3c")
    Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: source, platform: platform, complete: true).configuration
  end

  it "retains selected domain methods, reference roles, fallback and VTY evidence without secrets" do
    config = evidence(fixture("h3c"))
    bindings = config.fact("aaa.bindings")
    expect(bindings.map { |row| row[:role] }).to eq(%w[authentication authorization accounting])
    login = bindings.first
    expect(login).to include(domain: "OPS", complete: true, uses_tacacs: true, local_fallback: true, allows_none: false)
    expect(login[:methods]).to eq([ { kind: "tacacs", group: "OPS" }, { kind: "local" } ])
    expect(login[:references]).to contain_exactly(include(group: "OPS", role: "authentication", resolved: true, servers: %w[192.0.2.30 192.0.2.31]))
    expect(login[:vtys]).to contain_exactly(include(name: "line vty 0 63", authentication: "scheme"))
    expect(bindings).to all(be_frozen)
    expect(bindings.to_s).not_to include("PRIVATE-", "password")
    expect(config.sources.fetch("tacacs.login")).to include(26, 29, 35, 39, 44)
  end

  it "does not certify a removed or malformed default-domain selector using an older selection" do
    [ "undo domain default enable", "domain default enable" ].each do |command|
      config = evidence(fixture("h3c") + "#{command}\n")
      expect(config.fact_known?("tacacs.login")).to be(false)
    end
  end

  it "marks an explicitly selected missing domain unresolved rather than proving TACACS disabled" do
    config = evidence(fixture("h3c").sub("domain default enable OPS", "domain default enable MISSING"))
    expect(config.fact_known?("tacacs.login")).to be(false)
    expect(config.fact("aaa.bindings").first).to include(domain: "MISSING", complete: false, uses_tacacs: nil)
  end

  it "supports domain-name syntax, reopened domains and case-insensitive scheme references" do
    text = fixture("h3c").sub("domain OPS\n", "domain name OPS\n").sub("authentication login hwtacacs-scheme OPS local", "authentication login hwtacacs-scheme ops local")
    config = evidence(text)
    expect(config.fact("tacacs.login")).to be(true)
    replaced = evidence(text + "domain name OPS\n authentication login local\n#\n")
    expect(replaced.fact("tacacs.login")).to be(false)
    expect(replaced.fact("aaa.bindings").first[:methods]).to eq([ { kind: "local" } ])
  end

  it "uses the domain default after a login-specific method reset" do
    text = fixture("h3c").sub(" authentication login hwtacacs-scheme OPS local", " authentication default hwtacacs-scheme OPS local\n authentication login local\n undo authentication login")
    config = evidence(text)
    expect(config.fact("tacacs.login")).to be(true)
    expect(config.fact("aaa.bindings").first).to include(local_fallback: true, inherited: true)
  end

  it "keeps bypass and fallback distinct and rejects unparsed method tails without copying values" do
    config = evidence(fixture("h3c").sub("authentication login hwtacacs-scheme OPS local", "authentication login hwtacacs-scheme OPS local none"))
    expect(config.fact("aaa.bindings").first).to include(local_fallback: true, allows_none: true)
    malformed = evidence(fixture("h3c").sub("authentication login hwtacacs-scheme OPS local", "authentication login hwtacacs-scheme OPS PRIVATE-UNKNOWN-TAIL"))
    expect(malformed.fact_known?("tacacs.login")).to be(false)
    expect(malformed.fact("aaa.bindings").to_s).not_to include("PRIVATE-UNKNOWN-TAIL")
  end

  it "resolves Huawei template and scheme method references into separate bindings" do
    config = evidence(fixture("huawei"), platform: "huawei")
    binding = config.fact("aaa.bindings").first
    expect(binding).to include(domain: "OPS", scheme: "TAC", uses_tacacs: true, local_fallback: true, complete: true)
    expect(binding[:references]).to contain_exactly(include(group: "OPS", role: "authentication", resolved: true))
  end

  it "does not accept Huawei unknown methods or a withdrawn mode by its old first token" do
    [ "authentication-mode hwtacacs PRIVATE-UNKNOWN-TAIL", "authentication-mode hwtacacs local\n  undo authentication-mode" ].each do |mode|
      config = evidence(fixture("huawei").sub("authentication-mode hwtacacs local", mode), platform: "huawei")
      expect(config.fact("tacacs.login")).not_to be(true)
      expect(config.fact("aaa.bindings").to_s).not_to include("PRIVATE-UNKNOWN-TAIL")
    end
  end

  it "does not treat a referenced missing Huawei template or scheme as unused TACACS" do
    [ [ "hwtacacs-server OPS", "hwtacacs-server MISSING" ], [ "authentication-scheme TAC\n  authorization-scheme", "authentication-scheme MISSING\n  authorization-scheme" ] ].each do |from, to|
      config = evidence(fixture("huawei").sub(from, to), platform: "huawei")
      expect(config.fact_known?("tacacs.login")).to be(false)
    end
  end

  it "rejects Huawei contradictory local variants and multi-method accounting declarations" do
    text = fixture("huawei").sub("authentication-mode hwtacacs local", "authentication-mode hwtacacs local local-case")
    expect(evidence(text, platform: "huawei").fact_known?("tacacs.login")).to be(false)
    text = fixture("huawei").sub("accounting-mode hwtacacs", "accounting-mode hwtacacs radius")
    expect(evidence(text, platform: "huawei").fact_known?("tacacs.accounting")).to be(false)
  end

  it "resolves an explicitly configured Huawei default admin domain after selector reset" do
    text = fixture("huawei") + "aaa\n domain default_admin\n  authentication-scheme TAC\n  authorization-scheme TAC\n  accounting-scheme TAC\n  hwtacacs-server OPS\n#\nundo domain admin\n"
    config = evidence(text, platform: "huawei")
    expect(config.fact("aaa.bindings").first).to include(domain: "default_admin", uses_tacacs: true)
  end

  it "keeps bindings unresolved when referenced endpoint syntax is incomplete" do
    text = fixture("h3c").sub("primary authentication 192.0.2.30", "primary authentication 192.0.2.30 unsupported PRIVATE-ENDPOINT-TAIL")
    binding = evidence(text).fact("aaa.bindings").first
    expect(binding).to include(complete: false, uses_tacacs: nil)
    expect(binding[:references].first).to include(resolved: false)
    expect(binding.to_s).not_to include("PRIVATE-ENDPOINT-TAIL")
  end

  it "uses documented default selectors only when the built-in domain is explicitly modelled in complete input" do
    text = fixture("h3c").sub("domain OPS\n", "domain system\n").sub("domain default enable OPS\n", "")
    expect(evidence(text).fact("aaa.bindings").first).to include(domain: "system", uses_tacacs: true)
    text = fixture("huawei").sub("domain OPS admin\n", "").sub(" domain OPS\n", " domain default_admin\n")
    expect(evidence(text, platform: "huawei").fact("aaa.bindings").first).to include(domain: "default_admin", uses_tacacs: true)
  end
end

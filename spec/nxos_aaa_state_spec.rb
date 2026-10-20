# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "NX-OS global management AAA semantics" do
  let(:source) do
    "hostname LAB\nfeature tacacs+\ntacacs-server host 192.0.2.30 key 7 SYNTHETIC-ONLY\n" \
      "aaa group server tacacs+ OPS\n server 192.0.2.30\n!\naaa group server tacacs+ BACKUP\n server 192.0.2.30\n!\n" \
      "aaa authentication login default group OPS\naaa authorization commands default group OPS local\n" \
      "aaa authorization config-commands default group OPS local\naaa accounting default group OPS\nline vty\n!\n"
  end

  def report(text = source, id: "tacacs.login", complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => true } })
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: :cisco_nxos, complete: complete)
  end

  it "keeps default-login fallback controls separate from ordered authentication groups" do
    result = report(source + "no aaa authentication login default fallback error local\n")
    expect(result).to be_compliant
    login = result.configuration.fact("aaa.nxos").fetch("authentication").fetch("default")
    expect(login).to include("methods" => [ { "kind" => "tacacs", "group" => "OPS" } ], "fallback_on_error" => false, "complete" => true)
    expect(result.to_h.to_s).not_to include("SYNTHETIC-ONLY")
  end

  it "resolves all ordered native group-list members rather than treating the second group as an unknown method" do
    result = report(source.sub("login default group OPS", "login default group OPS BACKUP"))
    expect(result).to be_compliant
    expect(result.configuration.fact("aaa.nxos")["authentication"]["default"]["methods"]).to eq([
      { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "tacacs", "group" => "BACKUP" }
    ])
  end

  it "does not certify account authentication when native default login bypasses it" do
    [ "none", "group OPS none" ].each do |methods|
      result = report(source.sub("login default group OPS", "login default #{methods}"), id: "ssh.vty_aaa")
      expect(result.findings.first.status).to eq(:fail)
      expect(result.findings.first.actual).to be(false)
    end
  end

  it "checks config-command authorization as well as exec commands" do
    result = report(source.sub("authorization config-commands default group OPS local", "authorization config-commands default local"), id: "tacacs.authorization")
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.actual).to be(false)
  end

  it "derives native remote transport from explicit feature state instead of requiring IOS transport commands" do
    result = report("hostname LAB\nno feature telnet\nline vty\n!\n", id: "ssh.vty_ssh_only")
    expect(result).to be_compliant
    expect(result.configuration.fact("ssh.enabled")).to be(true)
    expect(report("hostname LAB\nfeature telnet\nline vty\n!\n", id: "ssh.vty_ssh_only").findings.first.status).to eq(:fail)
    expect(report("hostname LAB\nline vty\n!\n", id: "ssh.vty_ssh_only").findings.first.status).to eq(:unknown)
  end

  it "models the documented complete-input local login default without inventing a VTY range" do
    result = report("hostname LAB\n", id: "ssh.vty_aaa")
    expect(result).to be_compliant
    expect(result.configuration.fact("ssh.vty")).to eq([])
    expect(result.configuration.fact("aaa.nxos")["authentication"]["default"]).to include("declared" => false, "methods" => [ { "kind" => "local" } ])
    partial = report("hostname LAB\n", id: "ssh.vty_aaa", complete: false)
    expect(partial).not_to be_compliant
    expect(partial.counts.fetch(:pass, 0)).to eq(0)
  end

  it "rejects IOS login controls and unsupported native tails without copying unknown values" do
    [ source.sub("line vty\n", "line vty\n login local\n"),
      source.sub("login default group OPS", "login default group OPS local"),
      source.sub("login default group OPS", "login default group OPS PRIVATE-UNKNOWN-TAIL") ].each do |text|
      result = report(text)
      expect(result.findings.first.status).to eq(:unknown)
      expect(result.configuration.facts.to_s).not_to include("PRIVATE-UNKNOWN-TAIL")
    end
  end

  it "reduces default method withdrawal and console declarations independently" do
    text = source + "aaa authentication login console none\nno aaa authentication login default group OPS\naaa authentication login default fallback error local\n"
    result = report(text)
    expect(result.findings.first.status).to eq(:fail)
    graph = result.configuration.fact("aaa.nxos")["authentication"]
    expect(graph["default"]).to include("methods" => [ { "kind" => "local" } ], "fallback_on_error" => true)
    expect(graph["console"]["methods"]).to eq([ { "kind" => "none" } ])
  end

  it "does not certify remote TACACS use while the native feature is disabled" do
    %w[tacacs.login tacacs.authorization tacacs.accounting].each do |id|
      expect(report(source + "no feature tacacs+\n", id: id).findings.first.status).to eq(:fail)
    end
  end

  it "checks the missing config-command role instead of considering one declared authorization role sufficient" do
    text = source.lines.reject { |line| line.start_with?("aaa authorization config-commands") }.join
    expect(report(text, id: "tacacs.authorization").findings.first.status).to eq(:fail)
  end

  it "retains native no-database authorization fallback as typed evidence" do
    text = source.sub("authorization commands default group OPS local", "authorization commands default group OPS none")
    node = report(text).configuration.fact("aaa.nxos")["authorization"]["commands"]
    expect(node).to include("complete" => true, "methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "none" } ])
  end

  it "marks malformed fallback evidence incomplete without exporting its tail" do
    text = source + "aaa authentication login default fallback PRIVATE-UNKNOWN-TAIL\n"
    result = report(text)
    node = result.configuration.fact("aaa.nxos")["authentication"]["default"]
    expect(node).to include("fallback_on_error" => nil, "complete" => false)
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.to_h.to_s).not_to include("PRIVATE-UNKNOWN-TAIL")
  end

  it "does not expose a complete graph when foreign VTY login syntax is present" do
    result = report(source.sub("line vty\n", "line vty\n login local\n"))
    expect(result.configuration.fact("aaa.nxos")["scope_complete"]).to be(false)
  end

  it "does not reuse a feature state after an incomplete declaration" do
    %w[ssh telnet tacacs+].each do |name|
      text = source + "feature #{name} PRIVATE-UNKNOWN-TAIL\n"
      id = name == "tacacs+" ? "tacacs.login" : name == "ssh" ? "ssh.enabled" : "ssh.vty_ssh_only"
      expect(report(text, id: id).findings.first.status).to eq(:unknown)
    end
  end

  it "uses final native feature declarations after withdrawals and malformed replacements" do
    text = "hostname LAB\nno feature telnet\nfeature telnet\nno feature telnet\n"
    expect(report(text, id: "ssh.vty_ssh_only")).to be_compliant
    expect(report(text + "feature telnet\n", id: "ssh.vty_ssh_only").findings.first.status).to eq(:fail)
    expect(report(text + "no feature telnet invalid\n", id: "ssh.vty_ssh_only").findings.first.status).to eq(:unknown)
  end

  it "reduces only default native lists and restores a valid replacement after a malformed one" do
    [ "no aaa authentication login default", "aaa authentication login default" ].each do |replacement|
      text = source + replacement + "\n"
      expect(report(text).findings.first.status).to eq(replacement.start_with?("no ") ? :fail : :unknown)
      restored = text + "aaa authentication login default group OPS\n"
      expect(report(restored)).to be_compliant
    end
    expect(report(source + "aaa authentication login OPERATORS group OPS\n").findings.first.status).to eq(:unknown)
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Approved Comware VTY account authentication" do
  let(:source) do
    "sysname LAB\nssh server enable\ndomain ADMIN\n authentication login local\n#\ndomain default enable ADMIN\n" \
      "line vty 0 4\n authentication-mode password\n protocol inbound all\n acl 2001 inbound\n#\n" \
      "line vty 5 9\n authentication-mode scheme\n protocol inbound ssh\n#\n"
  end
  let(:approval) do
    { "management_domain" => "ADMIN", "methods" => [ { "kind" => "local" } ], "syntax_profile" => "comware7",
      "vty_ranges" => [ "line vty 0 4", "line vty 5 9" ], "local_fallback_access_verified" => true, "management_consumers_verified" => true }
  end

  def service(options = approval, expected: true, extra: {})
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => {
      "ssh.vty_aaa" => { "expected" => expected, "remediation" => options }
    }.merge(extra)))
  end

  def plan(text = source, options: approval, expected: true, complete: true, extra: {})
    service(options, expected: expected, extra: extra).call(configuration: text, platform: :h3c, complete: complete)
  end

  # 独立状态模型只归约原生范围级设置，原始 class 保留，由后续真实审计核验联动效果。
  def apply(text, commands)
    lines, view = text.lines, nil
    commands.each do |command|
      next if command == "system-view"
      if %w[quit return].include?(command)
        view = nil
      elsif /\Aline vty \d+(?: \d+)?\z/.match?(command)
        view = command
      elsif (match = /\A(authentication-mode|protocol inbound) (scheme|all|ssh|telnet)\z/.match(command))
        first = lines.index("#{view}\n")
        raise "Unknown native VTY" unless first
        last = ((first + 1)...lines.size).find { |i| !lines[i].start_with?(" ") } || lines.size
        indexes = ((first + 1)...last).select { |i| lines[i].start_with?(" #{match[1]} ") }
        indexes.reverse_each { |i| lines.delete_at(i) }
        lines.insert(first + 1, " #{command}\n")
      else
        raise "Unexpected native command"
      end
    end
    lines.join
  end

  it "changes only approved unsafe ranges and preserves protocols, ACLs, domains and safe ranges" do
    result = plan
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.configuration_commands).to eq([ "system-view", "line vty 0 4", "authentication-mode scheme", "protocol inbound all", "return" ])
    operation = result.operations.fetch(0)
    expect(operation.kind).to eq("aaa.vty")
    expect(operation.after).to eq("authentication" => "scheme", "protocols" => [ "all" ])
    changed = apply(source, result.configuration_commands)
    expect(changed).to include(" acl 2001 inbound\n", "domain ADMIN\n authentication login local\n", "line vty 5 9\n authentication-mode scheme\n protocol inbound ssh\n")
    expect(plan(changed).status).to eq(:noop)
    expect(result.review[:rollback]).to include(status: :manual_required, configuration_commands: [])
    expect { Baseline::H3c::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "retains inherited SSH-only transport by explicitly configuring the pair after the mode change" do
    text = source.sub("line vty 0 4\n authentication-mode password\n protocol inbound all", "line class vty\n authentication-mode password\n protocol inbound ssh\n#\nline vty 0 4\n authentication-mode password")
    result = plan(text, options: approval.merge("temporary_vty_protocol_rebind_approved" => true))
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.checks.first.details[:temporary_protocol_rebind]).to be(true)
    expect(result.configuration_commands).to include("authentication-mode scheme", "protocol inbound ssh")
    changed = apply(text, result.configuration_commands)
    expect(changed).to include("line class vty\n authentication-mode password\n protocol inbound ssh\n")
    expect(plan(changed).status).to eq(:noop)
    expect(plan(changed).audit.configuration.fact("ssh.vty_ssh_only")).to be(true)
  end

  it "projects VTY mode and requested SSH-only transport together rather than leaving one metric blocked" do
    extra = { "ssh.vty_ssh_only" => { "expected" => true } }
    result = plan(extra: extra)
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.operations.size).to eq(1)
    expect(result.configuration_commands).to include("authentication-mode scheme", "protocol inbound ssh")
    expect(result.checks.map(&:operation_ids).uniq.size).to eq(1)
    expect(plan(apply(source, result.configuration_commands), extra: extra).status).to eq(:noop)
  end

  it "attributes a TACACS login correction caused solely by VTY mode to the same verified operations" do
    text = "hwtacacs scheme OPS\n primary authentication 192.0.2.30\n key authentication cipher SYNTHETIC-ONLY\n#\n" +
      source.sub("authentication login local", "authentication login hwtacacs-scheme OPS local")
    options = approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ], "tacacs_peer_compatibility_verified" => true)
    extra = { "tacacs.login" => { "expected" => true } }
    result = plan(text, options: options, extra: extra)
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.operations.map(&:kind)).to eq([ "aaa.vty" ])
    expect(result.checks.map(&:operation_ids).uniq.size).to eq(1)
    expect(result.to_h.to_s).not_to include("SYNTHETIC-ONLY")
    expect(plan(apply(text, result.configuration_commands), options: options, extra: extra).status).to eq(:noop)
    conflict = plan(text, options: options, extra: { "tacacs.login" => { "expected" => false } })
    expect(conflict.operations).to be_empty
    expect(conflict.checks.first.reason).to eq(:policy_conflict)
  end

  it "does not infer domain, method, range or recovery approval from observed values" do
    %w[management_domain methods vty_ranges local_fallback_access_verified management_consumers_verified].each do |key|
      result = plan(options: approval.except(key))
      expect(result.status).to eq(:blocked)
      expect(result.operations).to be_empty
    end
    expect(plan(complete: false).operations).to be_empty
    expect(plan(expected: false).operations).to be_empty
  end

  it "blocks incomplete, overlapping or mismatched range inventories and unknown effective protocols" do
    [ [ source, approval.merge("vty_ranges" => [ "line vty 0 4" ]) ],
      [ source.sub("line vty 5 9", "line vty 3 9"), approval ],
      [ source.sub(" protocol inbound all\n", ""), approval ],
      [ source, approval.merge("management_domain" => "MISSING") ],
      [ source.sub("authentication login local", "authentication login none"), approval ] ].each do |text, options|
      result = plan(text, options: options)
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
    end
  end

  it "does not narrow transports to SSH without enable evidence or with a disable policy" do
    extra = { "ssh.vty_ssh_only" => { "expected" => true } }
    expect(plan(source.sub("ssh server enable\n", ""), extra: extra).operations).to be_empty
    result = plan(extra: extra.merge("ssh.enabled" => { "expected" => false }))
    expect(result.operations).to be_empty
  end

  it "blocks a temporary protocol fallback caused by class inheritance unless explicitly approved" do
    text = source.sub("line vty 0 4\n authentication-mode password\n protocol inbound all", "line class vty\n authentication-mode password\n protocol inbound ssh\n#\nline vty 0 4\n authentication-mode password")
    result = plan(text)
    expect(result.status).to eq(:blocked)
    expect(result.configuration_commands).to be_empty
    expect(result.checks.first.requirements).to include("temporary_vty_protocol_rebind_approved")
  end

  it "withholds every coupled check if the renderer rejects the verified transaction" do
    policy = Baseline::Policy.new("version" => 1, "checks" => {
      "ssh.vty_aaa" => { "expected" => true, "remediation" => approval }, "ssh.vty_ssh_only" => { "expected" => true }
    })
    audit = Baseline::Audit.new(policy: policy).call(configuration: source, platform: :h3c, complete: true)
    result = Baseline::VtyAuthenticationRemediation.new(policy: policy, renderer: Baseline::CommandRenderer.new).call(audit)
    expect(result.operations).to be_empty
    expect(result.steps).to be_empty
    expect(result.checks.keys.sort).to eq(%w[ssh.vty_aaa ssh.vty_ssh_only])
    expect(result.checks.values.map { |check| check[:status] }).to eq([ :blocked, :blocked ])
  end

  it "keeps unapproved endpoint metrics blocked without suppressing an independently verified VTY correction" do
    result = plan(extra: { "tacacs.servers" => { "expected" => nil }, "tacacs.endpoints" => { "expected" => nil } })
    expect(result.status).to eq(:partial)
    expect(result.checks.first.status).to eq(:planned)
    expect(result.operations.size).to eq(1)
    expect(result.checks.drop(1).map(&:status)).to eq([ :blocked, :blocked ])
  end

  it "rejects invalid approved scope syntax before any planner output" do
    [ [ "line vty 4 1" ], [ "line vty 0 4", "line vty 3 8" ], [ "line vty 0 4", "line vty 0 4" ],
      [ "line vty 0 4\nquit" ], [ "line vty 65536" ] ].each do |ranges|
      expect { service(approval.merge("vty_ranges" => ranges)) }.to raise_error(ArgumentError)
    end
  end
end

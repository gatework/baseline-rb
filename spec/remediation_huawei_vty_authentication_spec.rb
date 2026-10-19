# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Approved Huawei VTY account authentication" do
  let(:source) do
    "sysname LAB\nstelnet server enable\ndomain ADMIN admin\n#\nhwtacacs-server template OPS\n" \
      " hwtacacs-server authentication 192.0.2.30\n hwtacacs-server authorization 192.0.2.31\n hwtacacs-server shared-key cipher SYNTHETIC-ONLY\n#\n" \
      "aaa\n authentication-scheme MGMT\n  authentication-mode hwtacacs local\n authorization-scheme AUTHZ\n  authorization-mode local\n" \
      " accounting-scheme ACCT\n  accounting-mode none\n domain ADMIN\n  authentication-scheme MGMT\n  authorization-scheme AUTHZ\n  accounting-scheme ACCT\n  hwtacacs-server OPS\n" \
      " domain OTHER\n  authentication-scheme MGMT\n  authorization-scheme AUTHZ\n  accounting-scheme ACCT\n  hwtacacs-server OPS\n#\n" \
      "user-interface vty 0 4\n authentication-mode password\n protocol inbound all\n acl 2001 inbound\n#\n" \
      "user-interface vty 5 9\n authentication-mode aaa\n protocol inbound ssh\n#\n"
  end
  let(:approval) do
    { "management_domain" => "ADMIN", "syntax_profile" => "vrp_s_series", "methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ],
      "vty_ranges" => [ "user-interface vty 0 4", "user-interface vty 5 9" ], "local_fallback_access_verified" => true,
      "management_consumers_verified" => true, "tacacs_peer_compatibility_verified" => true }
  end

  def plan(text = source, options: approval, extra: {}, complete: true, platform: :huawei)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_aaa" => { "expected" => true, "remediation" => options } }.merge(extra))
    Baseline::Remediation.new(policy: policy).call(configuration: text, platform: platform, complete: complete)
  end

  # 测试只解释明确的 Huawei UI 命令；AAA 层级、模板与其他根节点均按原字节保留。
  def apply(text, commands)
    lines, view = text.lines, nil
    commands.each do |command|
      next if command == "system-view"
      if %w[quit return].include?(command)
        view = nil
      elsif /\Auser-interface vty \d+(?: \d+)?\z/.match?(command)
        view = command
      elsif (match = /\A(authentication-mode|protocol inbound) (aaa|all|ssh|telnet)\z/.match(command))
        first = lines.index("#{view}\n")
        raise "Unknown native UI" unless first
        last = ((first + 1)...lines.size).find { |index| !lines[index].start_with?(" ") } || lines.size
        indexes = ((first + 1)...last).select { |index| lines[index].start_with?(" #{match[1]} ") }
        indexes.reverse_each { |index| lines.delete_at(index) }
        lines.insert(first + 1, " #{command}\n")
      else
        raise "Unsupported Huawei command"
      end
    end
    lines.join
  end

  it "emits Huawei AAA mode only for changed approved UIs and preserves shared AAA configuration" do
    result = plan
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.configuration_commands).to eq([ "system-view", "user-interface vty 0 4", "authentication-mode aaa", "protocol inbound all", "return" ])
    expect(result.operations.fetch(0).scope).to eq("syntax_profile" => "vrp_s_series")
    changed = apply(source, result.configuration_commands)
    expect(changed.split("user-interface").first).to eq(source.split("user-interface").first)
    expect(changed).to include(" acl 2001 inbound\n", "user-interface vty 5 9\n authentication-mode aaa\n protocol inbound ssh\n")
    expect(plan(changed).status).to eq(:noop)
    expect(result.to_h.to_s).not_to include("SYNTHETIC-ONLY")
    expect(result.review[:rollback]).to include(status: :manual_required, configuration_commands: [])
    expect(result.review[:persistence][:commands]).to be_empty
  end

  it "projects SSH-only and TACACS login to the same typed UI operation" do
    extra = { "ssh.vty_ssh_only" => { "expected" => true }, "tacacs.login" => { "expected" => true } }
    result = plan(extra: extra)
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.configuration_commands).to include("authentication-mode aaa", "protocol inbound ssh")
    expect(result.operations.size).to eq(1)
    expect(result.checks.map(&:operation_ids).uniq.size).to eq(1)
    expect(plan(apply(source, result.configuration_commands), extra: extra).status).to eq(:noop)
  end

  it "retains local-case semantics and requires their explicit approval instead of equating them with local" do
    text = source.sub("authentication-mode hwtacacs local", "authentication-mode hwtacacs local-case")
    refused = plan(text)
    expect(refused.status).to eq(:blocked)
    expect(refused.operations).to be_empty
    options = approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local", "case_sensitive" => true } ])
    accepted = plan(text, options: options)
    expect(accepted.status).to eq(:ready), accepted.checks.map(&:to_h).inspect
    changed = apply(text, accepted.configuration_commands)
    expect(changed).to include("  authentication-mode hwtacacs local-case\n")
    expect(plan(changed, options: options).status).to eq(:noop)
  end

  it "supports a verified existing local chain without requiring a remote group or key" do
    text = source.sub("authentication-mode hwtacacs local", "authentication-mode local").sub(" hwtacacs-server shared-key cipher SYNTHETIC-ONLY\n", "")
    result = plan(text, options: approval.merge("methods" => [ { "kind" => "local" } ]).except("tacacs_peer_compatibility_verified"))
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.configuration_commands).to include("authentication-mode aaa")
  end

  it "blocks missing shared material, wrong role endpoints, wrong template identity or selected domain" do
    [ source.sub(" hwtacacs-server shared-key cipher SYNTHETIC-ONLY\n", ""),
      source.sub(" hwtacacs-server authentication 192.0.2.30\n", ""),
      source.sub("  hwtacacs-server OPS\n", "  hwtacacs-server MISSING\n"),
      source.sub("domain ADMIN admin", "domain MISSING admin") ].each do |text|
      result = plan(text)
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
    end
  end

  it "requires complete scope, current method identity and peer/recovery/consumer verification" do
    [ approval.merge("vty_ranges" => [ "user-interface vty 0 4" ]),
      approval.merge("methods" => [ { "kind" => "local" } ]),
      *%w[local_fallback_access_verified management_consumers_verified tacacs_peer_compatibility_verified].map { |key| approval.merge(key => false) } ].each do |options|
      expect(plan(options: options).operations).to be_empty
    end
    expect(plan(complete: false).operations).to be_empty
    expect(plan(extra: { "tacacs.login" => { "expected" => false } }).operations).to be_empty
    expect(plan(extra: { "tacacs.servers" => { "expected" => [ "192.0.2.99" ] } }).operations).to be_empty
  end

  it "does not require the Comware class protocol transition approval for an independent Huawei UI setting" do
    text = source.sub("protocol inbound all", "protocol inbound telnet")
    result = plan(text)
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.checks.first.details[:temporary_protocol_rebind]).to be(false)
    expect(result.configuration_commands).to include("protocol inbound telnet")
  end

  it "does not activate unresolved authorization or accounting paths when changing UI mode" do
    [ source.sub("  authorization-scheme AUTHZ\n", "  authorization-scheme MISSING\n"),
      source.sub("  accounting-scheme ACCT\n", "  accounting-scheme MISSING\n") ].each do |text|
      result = plan(text)
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
      expect(result.checks.first.requirements).to include("resolved_management_login_roles")
    end
  end

  it "requires AAA role and local recovery runtime verification even if only the SSH metric is managed" do
    result = plan
    expect(result.review[:validation][:runtime_requirements]).to include("aaa_roles_and_local_fallback")
    expect(result.review[:validation][:status]).to eq(:not_executed)
  end

  it "reports Huawei-native prerequisites without imposing a Comware class rebind approval" do
    capability = Baseline::Remediation.capabilities(platform: :huawei).fetch("ssh.vty_aaa")
    expect(capability[:status]).to eq(:conditional)
    expect(capability[:requirements]).to include("resolved_management_login_roles", "exact_existing_methods_including_local_case", "existing_shared_tacacs_key_for_remote_roles")
    expect(capability[:requirements]).not_to include("temporary_vty_protocol_rebind_approved_for_inherited_protocol_changes")
  end

  it "verifies remote accounting material and peer prerequisites even with local authentication" do
    text = source.sub("authentication-mode hwtacacs local", "authentication-mode local")
      .sub("accounting-mode none", "accounting-mode hwtacacs")
      .sub(" hwtacacs-server authorization 192.0.2.31", " hwtacacs-server authorization 192.0.2.31\n hwtacacs-server accounting 192.0.2.32")
    options = approval.merge("methods" => [ { "kind" => "local" } ])
    expect(plan(text, options: options).status).to eq(:ready)
    refused = plan(text, options: options.except("tacacs_peer_compatibility_verified"))
    expect(refused.operations).to be_empty
    expect(refused.checks.first.requirements).to include("tacacs_peer_compatibility_verified")
    expect(plan(text.sub(" hwtacacs-server shared-key cipher SYNTHETIC-ONLY\n", ""), options: options).operations).to be_empty
  end

  it "binds proofs to the actual profile and rejects another range or renderer" do
    operation = plan.operations.fetch(0)
    changed = Baseline::ConfigurationOperation.new(**operation.to_h.except(:id).merge(identity: { "vty" => "user-interface vty 10 15" }))
    expect { Baseline::Huawei::CommandRenderer.new.render(changed, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { Baseline::H3c::CommandRenderer.new.render(operation, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { Baseline::Huawei::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end
end

# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"

RSpec.describe "Approved Comware management method chains" do
  let(:source) do
    "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n primary authorization 192.0.2.31\n" \
      " primary accounting 192.0.2.32\n key authentication cipher SYNTHETIC-AUTH\n key authorization cipher SYNTHETIC-AUTHZ\n key accounting cipher SYNTHETIC-ACCT\n#\n" \
      "domain ADMIN\n authentication default local\n authorization login local\n accounting login local\n authentication lan-access radius-scheme LAN\n#\n" \
      "domain OTHER\n authentication login local\n#\ndomain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n"
  end
  let(:approval) do
    { "management_domain" => "ADMIN", "methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ],
      "syntax_profile" => "comware7", "local_fallback_access_verified" => true, "management_consumers_verified" => true,
      "tacacs_peer_compatibility_verified" => true }
  end

  def plan(text = source, id: "tacacs.login", expected: true, options: approval, complete: true, extra: {})
    policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => expected, "remediation" => options } }.merge(extra))
    Baseline::Remediation.new(policy: policy).call(configuration: text, platform: :h3c, complete: complete)
  end

  # 独立原生命令模型：只替换指定现有域的 login 行，拒绝越域或删除其他配置。
  def apply(text, commands)
    lines, domain = text.lines, nil
    commands.each do |command|
      next if command == "system-view"
      if %w[quit return].include?(command)
        domain = nil
      elsif (match = /\Adomain (\S+)\z/.match(command))
        domain = match[1]
      elsif (match = /\A(authentication|authorization|accounting) login (.+)\z/.match(command))
        first = lines.index("domain #{domain}\n")
        raise "Unknown domain" unless first
        finish = ((first + 1)...lines.size).find { |i| !lines[i].start_with?(" ") } || lines.size
        indexes = ((first + 1)...finish).select { |i| lines[i].match?(/\A #{match[1]} login\b/) }
        indexes.reverse_each { |i| lines.delete_at(i) }
        lines.insert(first + 1, " #{command}\n")
      else
        raise "Unsupported native command"
      end
    end
    lines.join
  end

  { "tacacs.login" => "authentication", "tacacs.authorization" => "authorization", "tacacs.accounting" => "accounting" }.each do |id, role|
    it "changes only the approved #{role} login chain and converges without exposing material" do
      result = plan(id: id)
      expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
      expect(result.configuration_commands).to eq([ "system-view", "domain ADMIN", "#{role} login hwtacacs-scheme OPS local", "return" ])
      operation = result.operations.fetch(0)
      expect(operation.kind).to eq("aaa.login_chain")
      expect(operation.after).to eq("methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ])
      changed = apply(source, result.configuration_commands)
      expect(changed).to include(" authentication lan-access radius-scheme LAN\n", "domain OTHER\n authentication login local\n")
      expect(plan(changed, id: id).status).to eq(:noop)
      expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-ACCT")
      expect(result.review[:rollback]).to include(status: :manual_required, configuration_commands: [])
      expect { Baseline::H3c::CommandRenderer.new.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    end
  end

  it "uses an explicitly approved local alternative when removing a primary remote chain" do
    text = source.sub("authentication default local", "authentication login hwtacacs-scheme OPS local")
    result = plan(text, expected: false, options: approval.merge("methods" => [ { "kind" => "local" } ]))
    expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
    expect(result.configuration_commands).to include("authentication login local")
    expect(plan(apply(text, result.configuration_commands), expected: false, options: approval.merge("methods" => [ { "kind" => "local" } ])).status).to eq(:noop)
  end

  it "blocks without complete input, exact selected domain and recovery/consumer/peer approvals" do
    cases = [ [ source, approval, false ], [ source, approval.merge("management_domain" => "OTHER"), true ],
      *%w[local_fallback_access_verified management_consumers_verified tacacs_peer_compatibility_verified].map { |key| [ source, approval.merge(key => false), true ] } ]
    cases.each do |text, options, complete|
      result = plan(text, options: options, complete: complete)
      expect(result.status).to eq(:blocked)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
  end

  it "blocks missing role material, unresolved targets, unknown old methods and non-scheme VTYs" do
    [ source.sub("key authentication cipher SYNTHETIC-AUTH", ""), source.sub("primary authentication 192.0.2.30", ""),
      source.sub("authentication default local", "authentication login unexpected"), source.sub("authentication-mode scheme", "authentication-mode password") ].each do |text|
      result = plan(text)
      expect(result.status).to eq(:blocked)
      expect(result.operations).to be_empty
    end
  end

  it "keeps endpoint changes and contradictory explicit binding approvals from being silently composed" do
    endpoint = { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" },
      "scope" => { "group" => "OPS", "vrf" => "default" }, "bindings" => [] }
    [ { "tacacs.servers" => { "expected" => [ "192.0.2.99" ] } },
      { "tacacs.endpoints" => { "expected" => [ endpoint ] } } ].each do |extra|
      result = plan(extra: extra)
      expect(result.checks.find { |check| check.id == "tacacs.login" }.status).to eq(:blocked)
      expect(result.operations).to be_empty
    end
  end

  it "requires exact-operation approval rather than borrowing a proof for another role or group" do
    operation = plan.operations.fetch(0)
    changed = Baseline::ConfigurationOperation.new(**operation.to_h.except(:id).merge(identity: { "role" => "authorization" }))
    renderer = Baseline::H3c::CommandRenderer.new
    expect { renderer.render(changed, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { Baseline::Huawei::CommandRenderer.new.render(operation, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "preserves each ordered role when the three changes are reviewed together" do
    policy = Baseline::Policy.new("version" => 1, "checks" => %w[tacacs.login tacacs.authorization tacacs.accounting].to_h do |id|
      [ id, { "expected" => true, "remediation" => approval } ]
    end)
    service = Baseline::Remediation.new(policy: policy)
    result = service.call(configuration: source, platform: :h3c, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(3)
    expect(result.configuration_commands.count("domain ADMIN")).to eq(1)
    expect(service.call(configuration: apply(source, result.configuration_commands), platform: :h3c, complete: true).status).to eq(:noop)
  end

  it "does not invent endpoint changes from missing approval values when correcting a role chain" do
    result = plan(extra: { "tacacs.servers" => { "expected" => nil } })
    expect(result.status).to eq(:partial)
    expect(result.checks.first.status).to eq(:planned)
    expect(result.operations.size).to eq(1)
    expect(result.checks.last.status).to eq(:blocked)
  end

  it "rejects injected identities, unknown fields, repeated methods and chains without local recovery" do
    [ approval.merge("management_domain" => "ADMIN\nquit"), approval.merge("extra" => true),
      approval.merge("methods" => [ { "kind" => "none" } ]), approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" } ]),
      approval.merge("methods" => [ { "kind" => "local" }, { "kind" => "local" } ]) ].each do |options|
      expect { plan(options: options) }.to raise_error(ArgumentError)
    end
  end
end

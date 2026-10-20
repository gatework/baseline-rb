# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Approved native NX-OS management AAA corrections" do
  let(:source) do
    "hostname LAB\nfeature tacacs+\nno feature telnet\n" \
      "tacacs-server host 192.0.2.30 key 7 SYNTHETIC-KEY\n" \
      "aaa group server tacacs+ OPS\n server 192.0.2.30\n use-vrf management\n!\n" \
      "aaa authentication login default local\nno aaa authentication login default fallback error local\n" \
      "aaa authentication login console local\nno aaa authentication login console fallback error local\n" \
      "aaa authorization commands default local\naaa authorization config-commands default local\n" \
      "aaa accounting default local\nline vty\n access-class MGMT in\n!\ninterface Ethernet1/1\n description KEEP\n!\n"
  end

  def approval(id = "tacacs.login", local: false)
    methods = [ { "kind" => "tacacs", "group" => "OPS" } ]
    methods << { "kind" => "local" } if id == "tacacs.authorization"
    result = { "syntax_profile" => "nxos", "methods" => local ? [ { "kind" => "local" } ] : methods,
      "local_fallback_access_verified" => true, "management_consumers_verified" => true, "tacacs_peer_compatibility_verified" => true }
    result["local_fallback_on_error"] = true if !local && %w[tacacs.login ssh.vty_aaa].include?(id)
    result
  end

  def plan(text = source, id: "tacacs.login", expected: true, options: approval(id), complete: true, extra: {})
    policy = Baseline::Policy.new("version" => 1, "checks" => { id => { "expected" => expected, "remediation" => options } }.merge(extra))
    Baseline::Remediation.new(policy: policy).call(configuration: text, platform: :cisco_nxos, complete: complete)
  end

  # 独立全局命令模型：后备为独立状态，只替换相同 native 控制项，其他文本逐字保留。
  def apply(text, commands)
    lines = text.lines
    commands.each do |command|
      next if [ "configure terminal", "end" ].include?(command)
      prefix = case command
      when /\Aaaa authentication login default fallback error local\z/ then /\A(?:no )?aaa authentication login default fallback(?:\s|\z)/
      when /\Aaaa authentication login default (?:group \S+(?: \S+)*|local)\z/ then /\A(?:no )?aaa authentication login default (?!fallback(?:\s|\z))/
      when /\Aaaa authorization (commands|config-commands) default (?:group \S+(?: \S+)* local|local)\z/
        /\A(?:no )?aaa authorization #{Regexp.escape(Regexp.last_match(1))} default(?:\s|\z)/
      when /\Aaaa accounting default (?:group \S+(?: \S+)*|local)\z/ then /\A(?:no )?aaa accounting default(?:\s|\z)/
      else raise "Unsupported native command"
      end
      lines.reject! { |line| prefix.match?(line) }
      lines << "#{command}\n"
    end
    lines.join
  end

  {
    "tacacs.login" => [ "aaa authentication login default fallback error local", "aaa authentication login default group OPS" ],
    "tacacs.authorization" => [ "aaa authorization commands default group OPS local", "aaa authorization config-commands default group OPS local" ],
    "tacacs.accounting" => [ "aaa accounting default group OPS" ]
  }.each do |id, commands|
    it "corrects #{id} with native syntax and converges while preserving console and shared objects" do
      result = plan(id: id)
      expect(result.status).to eq(:ready), result.checks.map(&:to_h).inspect
      expect(result.configuration_commands).to eq([ "configure terminal", *commands, "end" ])
      after = apply(source, result.configuration_commands)
      expect(after).to include("aaa authentication login console local\nno aaa authentication login console fallback error local\n",
        "aaa group server tacacs+ OPS\n server 192.0.2.30\n use-vrf management\n!\n",
        "line vty\n access-class MGMT in\n!\ninterface Ethernet1/1\n description KEEP\n!\n")
      expect(plan(after, id: id).status).to eq(:noop)
      expect(result.to_h.to_s).not_to include("SYNTHETIC-KEY")
      expect(result.review[:validation][:runtime_requirements]).to include("aaa_roles_and_local_fallback")
      expect(result.review[:rollback][:configuration_commands]).to be_empty
    end
  end

  it "supports explicit local alternatives for each native role without changing independent fallback" do
    %w[tacacs.login tacacs.authorization tacacs.accounting].each do |id|
      remote = apply(source, plan(id: id).configuration_commands)
      result = plan(remote, id: id, expected: false, options: approval(id, local: true))
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands.grep(/fallback/)).to be_empty
      expect(plan(apply(remote, result.configuration_commands), id: id, expected: false, options: approval(id, local: true)).status).to eq(:noop)
    end
  end

  it "repairs native no-authentication using an approved local chain without inventing numeric VTY ranges" do
    text = source.sub("login default local", "login default none")
    result = plan(text, id: "ssh.vty_aaa", options: approval("ssh.vty_aaa", local: true))
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure terminal", "aaa authentication login default local", "end" ])
    expect(plan(apply(text, result.configuration_commands), id: "ssh.vty_aaa", options: approval("ssh.vty_aaa", local: true)).status).to eq(:noop)
  end

  it "preserves explicitly approved ordered groups in native authentication syntax" do
    text = source + "aaa group server tacacs+ BACKUP\n server 192.0.2.30\n!\n"
    options = approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "tacacs", "group" => "BACKUP" } ])
    result = plan(text, options: options)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("aaa authentication login default group OPS BACKUP")
    expect(plan(apply(text, result.configuration_commands), options: options).status).to eq(:noop)
  end

  it "requires explicit profile, consumer, recovery, peer and native fallback approval" do
    expect { plan(options: approval.except("syntax_profile")) }.to raise_error(ArgumentError)
    [ {}, *%w[local_fallback_access_verified management_consumers_verified tacacs_peer_compatibility_verified local_fallback_on_error].map { |key| approval.except(key) } ].each do |options|
      result = plan(options: options)
      expect(result.status).to eq(:blocked)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
  end

  it "blocks unknown old chains, missing keys/groups, disabled features and partial configuration" do
    [ source.sub(" key 7 SYNTHETIC-KEY", ""), source.sub("feature tacacs+", "no feature tacacs+"),
      source.sub("login default local", "login default unsupported"), source.sub(" server 192.0.2.30", " server 192.0.2.99") ].each do |text|
      result = plan(text)
      expect(result.status).to eq(:blocked)
      expect(result.operations).to be_empty
    end
    expect(plan(complete: false).operations).to be_empty
  end

  it "keeps endpoint lifecycle changes separate from activating new role references" do
    result = plan(extra: { "tacacs.servers" => { "expected" => [ "192.0.2.99" ] } })
    expect(result.checks.first.status).to eq(:blocked)
    expect(result.operations).to be_empty
  end

  it "rejects conflicting authentication targets across SSH and TACACS checks" do
    text = source.sub("login default local", "login default none")
    other = { "ssh.vty_aaa" => { "expected" => true, "remediation" => approval("ssh.vty_aaa", local: true) } }
    result = plan(text, extra: other)
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
  end

  it "binds rendering to exact operation approval and the NX-OS renderer" do
    operation = plan.operations.fetch(0)
    renderer = Baseline::CiscoNxos::CommandRenderer.new
    expect { renderer.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    changed = Baseline::ConfigurationOperation.new(**operation.to_h.except(:id).merge(after: operation.after.merge("methods" => [ { "kind" => "tacacs", "group" => "OTHER" } ])))
    expect { renderer.render(changed, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { Baseline::CiscoIos::CommandRenderer.new.render(operation, verified_aaa_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
  end

  it "rejects injected, unbounded, duplicate, bypass and role-incompatible approval methods" do
    bad = [ approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS\nend" } ]),
      approval.merge("methods" => [ { "kind" => "none" } ]), approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" } ] * 2),
      approval.merge("methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ]),
      approval.merge("management_domain" => "ADMIN") ]
    bad.each { |options| expect { plan(options: options) }.to raise_error(ArgumentError) }
    expect { plan(id: "tacacs.authorization", options: approval("tacacs.login")) }.to raise_error(ArgumentError)
  end

  it "does not rewrite an already matching authorization action while repairing the other action" do
    text = source.sub("aaa authorization commands default local", "aaa authorization commands default group OPS local")
    result = plan(text, id: "tacacs.authorization")
    expect(result.operations.size).to eq(1)
    expect(result.configuration_commands).to eq([ "configure terminal", "aaa authorization config-commands default group OPS local", "end" ])
  end

  it "withholds both authorization operations when rendering one action fails" do
    allow_any_instance_of(Baseline::CiscoNxos::CommandRenderer).to receive(:render).and_wrap_original do |original, operation, **options|
      raise Baseline::CommandRenderer::UnsupportedOperation if operation.identity["function"] == "config-commands"
      original.call(operation, **options)
    end
    result = plan(id: "tacacs.authorization")
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
    expect(result.configuration_commands).to be_empty
  end

  it "deduplicates compatible SSH and TACACS login changes while retaining all three role corrections" do
    text = source.sub("login default local", "login default none")
    ids = %w[tacacs.login tacacs.authorization tacacs.accounting ssh.vty_aaa]
    policy = Baseline::Policy.new("version" => 1, "checks" => ids.to_h { |id| [ id, { "expected" => true, "remediation" => approval(id) } ] })
    service = Baseline::Remediation.new(policy: policy)
    result = service.call(configuration: text, platform: :cisco_nxos, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(4)
    expect(result.configuration_commands.count("aaa authentication login default group OPS")).to eq(1)
    after = apply(text, result.configuration_commands)
    expect(service.call(configuration: after, platform: :cisco_nxos, complete: true).status).to eq(:noop)
  end

  it "permits an approved local recovery transition without borrowing unavailable remote material" do
    text = apply(source, plan.configuration_commands).sub(" key 7 SYNTHETIC-KEY", "")
    options = approval(local: true).merge("tacacs_peer_compatibility_verified" => false)
    result = plan(text, expected: false, options: options)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "configure terminal", "aaa authentication login default local", "end" ])
  end

  it "rejects malformed method objects with argument errors instead of leaking Ruby method errors" do
    [ nil, [ nil ], [ "local" ], [ { "kind" => "tacacs", "group" => "x" * 128 } ], [ { "kind" => "local", "secret" => "PRIVATE" } ] ].each do |methods|
      expect { plan(options: approval.merge("methods" => methods)) }.to raise_error(ArgumentError)
    end
  end

  it "does not silently accept NX-OS fallback controls in another native profile" do
    %w[tacacs.login ssh.vty_aaa].each do |id|
      options = approval(id).merge("syntax_profile" => "comware7", "management_domain" => "ADMIN",
        "methods" => [ { "kind" => "tacacs", "group" => "OPS" }, { "kind" => "local" } ])
      expect { plan(id: id, options: options) }.to raise_error(ArgumentError)
    end
  end

  it "does not bypass explicit denied approval on the same authentication chain through another check" do
    text = source.sub("login default local", "login default none")
    %w[management_consumers_verified local_fallback_access_verified tacacs_peer_compatibility_verified local_fallback_on_error].each do |key|
      other = { "ssh.vty_aaa" => { "expected" => true, "remediation" => approval("ssh.vty_aaa").merge(key => false) } }
      result = plan(text, extra: other)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
  end
end

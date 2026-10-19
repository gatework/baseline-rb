# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"
require_relative "support/snmp_group_state"

RSpec.describe "Guarded SNMP read-only group migrations" do
  let(:source) do
    "sysname LAB\nsnmp-agent\n" \
      "snmp-agent group v3 OLD privacy read-view READ write-view WRITE notify-view NOTIFY acl 2000\n" \
      "snmp-agent usm-user v3 observer group OLD\n" \
      "snmp-agent usm-user v3 observer authentication-mode sha cipher SYNTHETIC-AUTH\n" \
      "snmp-agent usm-user v3 observer privacy-mode aes128 cipher SYNTHETIC-PRIV\n"
  end

  def engine(users: [ "observer" ], group_verified: true, user_verified: true, profile: "vrp_v600", checks: {}, slots: 4)
    Baseline::Remediation.new(policy: Baseline::Policy.new("version" => 1, "checks" => {
      "snmp.write_enabled" => { "expected" => false, "remediation" => {
        "syntax_profile" => profile, "snmp_group_migration_verified" => group_verified,
        "snmp_user_group_transition_verified" => user_verified,
        "available_group_slots" => slots,
        "group_migrations" => [ { "from_group" => "OLD", "to_group" => "READONLY", "users" => users } ]
      }.compact }
    }.merge(checks)))
  end

  it "creates an equivalent read-only group, moves users, then retires the writable group without material commands" do
    result = engine.call(configuration: source, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view",
      "snmp-agent group v3 READONLY privacy read-view READ notify-view NOTIFY acl 2000",
      "snmp-agent usm-user v3 observer group READONLY", "undo snmp-agent group v3 OLD privacy", "return" ])
    expect(result.operations.map(&:phase)).to eq([ :create, :update, :remove ])
    expect(result.to_h.to_s).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV", "authentication-mode", "privacy-mode")
    after = SnmpGroupState.new(source).apply(result.configuration_commands).configuration
    expect(after).to include("snmp-agent usm-user v3 observer authentication-mode sha cipher SYNTHETIC-AUTH",
      "snmp-agent usm-user v3 observer privacy-mode aes128 cipher SYNTHETIC-PRIV")
    expect(engine.call(configuration: after, platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "does not treat a local username inventory as complete remote-engine or context evidence" do
    [ "snmp-agent remote-engineid 8000000001 usm-user v3 remote group OLD\n",
      "snmp-agent context PRIVATE\n", "interface Vlanif1\n snmp-agent usm-user v3 hidden group OLD\n#\n",
      "snmp-agent usm-user v3 observer group OLD unsupported-option VALUE\n",
      "snmp-agent usm-user v3 observer group OLD acl 2000 acl 2001\n" ].each do |extra|
      result = engine.call(configuration: source + extra, platform: :huawei, complete: true)
      expect(result.operations).to be_empty
      expect(result.checks.first.requirements).to include("resolved_snmp_permission_inventory")
    end
  end

  it "requires every configured consumer and external verification of the native nonsecret user transition" do
    [ engine(users: []), engine(group_verified: false), engine(user_verified: false) ].each do |service|
      result = service.call(configuration: source, platform: :huawei, complete: true)
      expect(result.configuration_commands).to be_empty
      expect(result.operations).to be_empty
      expect(result.checks.first.status).to eq(:blocked)
    end
  end

  it "blocks reuse of a destination group or an unrelated writable community instead of emitting a partial metric" do
    [ "snmp-agent group v3 READONLY privacy\n", "snmp-agent community write cipher SYNTHETIC-COMMUNITY\n" ].each do |extra|
      result = engine.call(configuration: source + extra, platform: :huawei, complete: true)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
  end

  it "does not assume a Comware inline user definition preserves its authentication material on a group-only update" do
    text = source.sub("observer group OLD\n", "observer OLD authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV\n")
    text = text.lines.reject { |line| /\Asnmp-agent usm-user v3 observer (?:authentication|privacy)-mode /.match?(line) }.join
    result = engine(profile: "comware7").call(configuration: text, platform: :h3c, complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.first.requirements).to include("snmp_user_material_provisioning")
  end

  it "keeps service, version, authPriv and approved source indicators passing through a permission migration" do
    checks = { "snmp.enabled" => { "expected" => true }, "snmp.versions" => { "expected" => [ "v3" ] },
      "snmp.auth_priv" => { "expected" => true }, "snmp.acl_bound" => { "expected" => true },
      "snmp.acl_restricted" => { "expected" => true }, "snmp.sources" => { "expected" => [ "192.0.2.0/24" ] } }
    text = source.sub("observer group OLD", "observer group OLD acl 2000") + "snmp-agent sys-info version v3\n" \
      "acl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n#\n"
    service = engine(checks: checks)
    result = service.call(configuration: text, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(3)
    after = SnmpGroupState.new(text).apply(result.configuration_commands).configuration
    final = service.call(configuration: after, platform: :huawei, complete: true)
    expect(final.status).to eq(:noop)
    expect(final.audit.findings.map(&:status)).to all(eq(:pass))
    expect(after).to include("observer group READONLY acl 2000", "rule 5 permit source 192.0.2.0 0.0.0.255")
  end

  it "preserves every security definition and leaves user materials intact before deleting any old variant" do
    text = source + "snmp-agent group v3 OLD authentication read-view READ notify-view NOTIFY acl 2000\n"
    result = engine.call(configuration: text, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.operations.map(&:phase)).to eq([ :create, :create, :update, :remove, :remove ])
    after = SnmpGroupState.new(text).apply(result.configuration_commands).configuration
    expect(after).to include("group v3 READONLY authentication read-view READ notify-view NOTIFY acl 2000")
    expect(engine.call(configuration: after, platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "preserves an unrelated read-only group and configuration outside the approved shared group" do
    retained = "snmp-agent group v3 UNMANAGED privacy read-view PRIVATE notify-view EVENTS acl 2001\n"
    text = source + retained + "stelnet server enable\n"
    result = engine.call(configuration: text, platform: :huawei, complete: true)
    expect(result.status).to eq(:ready)
    after = SnmpGroupState.new(text).apply(result.configuration_commands).configuration
    expect(after).to include(retained, "stelnet server enable\n")
    expect(result.operations.map { |operation| operation.identity["name"] }).not_to include("UNMANAGED")
    expect(engine.call(configuration: after, platform: :huawei, complete: true).status).to eq(:noop)
  end

  it "can retire a confirmed unused Comware writable group without rewriting any user" do
    text = source.lines.reject { |line| line.start_with?("snmp-agent usm-user ") }.join
    service = engine(users: [], profile: "comware7", user_verified: false)
    result = service.call(configuration: text, platform: :h3c, complete: true)
    expect(result.status).to eq(:ready)
    expect(result.operations.map(&:kind)).to eq([ "snmp.group", "snmp.group" ])
    after = SnmpGroupState.new(text).apply(result.configuration_commands).configuration
    expect(service.call(configuration: after, platform: :h3c, complete: true).status).to eq(:noop)
  end

  it "blocks partial input, ambiguous definitions, incomplete writable scope and unsupported rendering atomically" do
    [ source + "snmp-agent group v3 OTHER privacy write-view WRITE\n",
      source + "snmp-agent group v3 OLD privacy read-view READ\n",
      source.sub("acl 2000", "acl-ipv6 2000"), source.sub("acl 2000", "acl 9999") ].each do |text|
      result = engine.call(configuration: text, platform: :huawei, complete: true)
      expect(result.operations).to be_empty
      expect(result.configuration_commands).to be_empty
    end
    expect(engine.call(configuration: source, platform: :huawei, complete: false).operations).to be_empty
    expect(engine(checks: { "snmp.enabled" => { "expected" => false } }).call(configuration: source, platform: :huawei, complete: true).operations).to be_empty
  end

  it "requires complete operation proof at the renderer and rejects unsafe or duplicate approvals" do
    operation = engine.call(configuration: source, platform: :huawei, complete: true).operations.first
    renderer = Baseline::Huawei::CommandRenderer.new
    expect { renderer.render(operation) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation, "snmp_permission_preconditions_unverified")
    changed = Baseline::ConfigurationOperation.new(**operation.to_h.except(:id).merge(identity: operation.identity.merge("name" => "DIFFERENT")))
    expect { renderer.render(changed, verified_snmp_permission_operation_ids: [ operation.id ]) }.to raise_error(Baseline::CommandRenderer::UnsupportedOperation)
    expect { engine(users: [ "observer\nquit" ]) }.to raise_error(ArgumentError)
    expect { engine(users: %w[observer observer]) }.to raise_error(ArgumentError)
    expect { engine(user_verified: "yes") }.to raise_error(ArgumentError)
  end

  it "requires externally confirmed free group-definition slots before creating any destination" do
    text = source + "snmp-agent group v3 OLD authentication read-view READ\n"
    result = engine(slots: 1).call(configuration: text, platform: :huawei, complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.first.reason).to eq(:capacity_exceeded)
    expect(engine(slots: 0).call(configuration: source, platform: :huawei, complete: true).operations).to be_empty
    missing = engine(slots: nil).call(configuration: source, platform: :huawei, complete: true)
    expect(missing.operations).to be_empty
    expect(missing.checks.first.requirements).to include("available_snmp_group_slots")
    expect { engine(slots: -1) }.to raise_error(ArgumentError)
  end
end

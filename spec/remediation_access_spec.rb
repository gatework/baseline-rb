# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Management ACL remediation" do
  def policy(targets, limits = [ "192.0.2.0/24" ])
    Baseline::Policy.new("version" => 1, "checks" => {
      "management.acl_bound" => { "expected" => true }, "management.acl_restricted" => { "expected" => true },
      "management.sources" => { "expected" => limits, "remediation" => { "access_targets" => targets } }
    })
  end

  def configuration(body = "")
    binding = body.empty? ? "" : " acl 2000 inbound\n"
    "sysname LAB\nssh server enable\n#{body}line vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#{binding}#\n"
  end

  def plan(input, targets, limits = [ "192.0.2.0/24" ], complete: true)
    Baseline::Remediation.new(policy: policy(targets, limits)).call(configuration: input, platform: "h3c", complete: complete)
  end

  let(:old_acl) { "acl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 permit source 198.51.100.0 0.0.0.255\n rule 15 deny\n#\n" }

  it "creates a dedicated ACL from the intersection, then rebinds VTY without editing the shared ACL" do
    input = configuration(old_acl + "snmp-agent\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY acl 2000\n")
    result = plan(input, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "acl basic 2002", "rule 5 permit source 192.0.2.0 0.0.0.127", "rule 10 deny", "quit", "line vty 0 4", "acl 2002", "return" ])
    expect(result.operations.map(&:phase)).to eq(%i[create update])
    expect(result.operations.map(&:risk)).to all(eq("high"))
    expect(result.to_text).to include("操作最高风险: high")
    expect(result.checks.map(&:status)).to eq(%i[not_needed not_needed planned])
    expect(result.to_h.to_json).not_to include("SYNTHETIC-COMMUNITY")
    after = input.sub("line vty", "acl basic 2002\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 deny\n#\nline vty").sub(" acl 2000 inbound", " acl 2002")
    expect(after).to include(old_acl, "SYNTHETIC-COMMUNITY acl 2000")
    second = plan(after, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
    expect(second.audit).to be_compliant
    expect(second.status).to eq(:noop)
  end

  it "requires explicit initial targets within the approved upper bound for an unbound range" do
    target = { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [ "192.0.2.10/32" ] }
    expect(plan(configuration, [ target ]).configuration_commands).to include("rule 5 permit source 192.0.2.10 0.0.0.0")
    expect(plan(configuration, [ target.reject { |key| key == 'sources' } ]).operations).to be_empty
    expect(plan(configuration, [ target.merge("sources" => [ "198.51.100.0/24" ]) ]).operations).to be_empty
  end

  it "does not widen existing access even for explicit targets inside the approved upper bound" do
    result = plan(configuration(old_acl), [ { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [ "192.0.2.0/24" ] } ])
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:access_target_expands_existing)
  end

  it "blocks identifiers that already exist or have dangling references in other business configuration" do
    [ old_acl + "acl basic 2002\n rule 5 deny\n#\n", old_acl + "interface Vlan-interface1\n packet-filter 2002 inbound\n#\n",
      old_acl + "interface Vlan-interface1\n packet-filter 02002 inbound\n#\n" ].each do |body|
      result = plan(configuration(body), [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
      expect(result.operations).to be_empty
      expect(result.checks.last.reason).to eq(:acl_identity_in_use)
    end
  end

  it "rejects fresh IDs occurring outside the currently recognized ACL command families" do
    input = configuration(old_acl) + "vendor-extension target 02002\n"
    result = plan(input, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:acl_identity_in_use)
  end

  it "uses the same immutable input snapshot for audit and collision checks" do
    input = configuration(old_acl) + "vendor-extension target 2002\n"
    allow_any_instance_of(Baseline::Audit).to receive(:call).and_wrap_original do |original, **arguments|
      report = original.call(**arguments)
      input.replace(configuration(old_acl))
      report
    end
    result = plan(input, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
    expect(result.operations).to be_empty
    expect(input).not_to be_frozen
  end

  it "does not turn an empty intersection into a silent deny-all" do
    result = plan(configuration(old_acl), [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ], [ "203.0.113.0/24" ])
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:access_intersection_empty)
  end

  it "withholds the entire ACL metric for overlapping ranges or unresolved transports" do
    [ configuration(old_acl).sub("protocol inbound ssh", "protocol inbound all"), configuration(old_acl) + "line vty 3 8\n protocol inbound ssh\n#\n" ].each do |input|
      expect(plan(input, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ]).operations).to be_empty
    end
  end

  it "does not create ACLs for partial input or policy endpoints absent from the configuration" do
    target = { "endpoint" => "line vty 0 4", "acl" => "2002" }
    expect(plan(configuration(old_acl), [ target ], complete: false).operations).to be_empty
    expect(plan(configuration(old_acl), [ target.merge("endpoint" => "line vty 100 104") ]).operations).to be_empty
  end

  it "plans all changed ranges atomically while retaining a compliant range" do
    input = configuration(old_acl) + "line vty 5 9\n authentication-mode scheme\n protocol inbound ssh\n#\n" \
      "acl basic 2003\n rule 5 permit source 192.0.2.64 0.0.0.63\n rule 10 deny\n#\nline vty 10 15\n authentication-mode scheme\n protocol inbound ssh\n acl 2003\n#\n"
    targets = [ { "endpoint" => "line vty 0 4", "acl" => "2002" },
      { "endpoint" => "line vty 5 9", "acl" => "2004", "sources" => [ "192.0.2.10/32" ] } ]
    result = plan(input, targets)
    expect(result.status).to eq(:ready)
    expect(result.operations.size).to eq(4)
    expect(result.steps.map(&:phase)).to eq(%i[create create create create update update])
    expect(result.configuration_commands).not_to include("line vty 10 15")
    expect(result.configuration_commands.index("acl basic 2004")).to be < result.configuration_commands.index("line vty 0 4")
  end

  it "requires explicit empty targets before generating a deny-all ACL" do
    result = plan(configuration, [ { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [] } ], [])
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "acl basic 2002", "rule 5 deny", "quit", "line vty 0 4", "acl 2002", "return" ])
  end

  it "does not let a passing negative ACL requirement be violated by a source correction" do
    approved = policy([ { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [ "192.0.2.10/32" ] } ])
    altered = Baseline::Policy.new("version" => 1, "checks" => {
      "management.acl_bound" => { "expected" => false },
      "management.sources" => { "expected" => [ "192.0.2.0/24" ], "remediation" => approved.rules.last.remediation }
    })
    result = Baseline::Remediation.new(policy: altered).call(configuration: configuration, platform: "h3c", complete: true)
    expect(result.checks.first.status).to eq(:not_needed)
    expect(result.checks.last.reason).to eq(:policy_conflict)
    expect(result.operations).to be_empty
  end

  it "supports multiple transports only when the desired basic ACL preserves each protocol's permissions" do
    input = configuration(old_acl).sub("protocol inbound ssh", "protocol inbound ssh telnet")
    result = plan(input, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ])
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("acl 2002")
    advanced = "acl advanced 3000\n rule 5 permit tcp source 192.0.2.0 0.0.0.127 destination-port eq 22\n rule 10 permit tcp source 198.51.100.0 0.0.0.255 destination-port eq 23\n rule 15 deny\n#\n"
    differing = configuration(advanced).sub("acl 2000 inbound", "acl 3000 inbound").sub("protocol inbound ssh", "protocol inbound ssh telnet")
    blocked = plan(differing, [ { "endpoint" => "line vty 0 4", "acl" => "2002" } ], [ "192.0.2.0/24", "198.51.100.0/25" ])
    expect(blocked.operations).to be_empty
    expect(blocked.checks.last.reason).to eq(:access_protocol_dependency)
  end

  it "does not expose generic ACL deletion or arbitrary binding lifecycle operations" do
    expect do
      Baseline::ConfigurationOperation.new(kind: "access.acl", identity: { "name" => "2000" }, before: { "sources" => [ "192.0.2.0/24" ] }, after: nil, action: :remove, phase: :remove)
    end.to raise_error(ArgumentError)
    expect do
      Baseline::ConfigurationOperation.new(kind: "access.binding", identity: { "name" => "line vty 0 4" }, before: {}, after: { "acl" => "2002\nquit" }, action: :replace)
    end.to raise_error(ArgumentError)
  end

  it "publishes fresh ACL and initial target requirements for the conditional H3C capability" do
    capability = Baseline::Remediation.capabilities(platform: "h3c").fetch("management.sources")
    expect(capability[:status]).to eq(:conditional)
    expect(capability[:requirements]).to include("fresh_acl_identity", "approved_access_limits", "access_targets_for_initial_binding")
    expect(Baseline::Remediation.capabilities(platform: "cisco_nxos").fetch("management.sources")[:status]).to eq(:unsupported)
  end

  it "rejects unsafe or ambiguous ACL target approval parameters" do
    base = { "endpoint" => "line vty 0 4", "acl" => "2002", "sources" => [ "192.0.2.0/24" ] }
    [ base.merge("acl" => "2002\nquit"), base.merge("endpoint" => "line vty 0 4\nquit"), base.merge("sources" => [ "::/0" ]),
      base.merge("source" => "192.0.2.1"), base.merge("sources" => "192.0.2.1") ].each do |target|
      expect { policy([ target ]) }.to raise_error(ArgumentError)
    end
    expect { policy([ base, base ]) }.to raise_error(ArgumentError)
  end
end

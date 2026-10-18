# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "H3C SNMP global ACL remediation" do
  def policy(target = { "endpoint" => "snmp.global", "acl" => "2005" }, supported: true, limits: [ "192.0.2.0/24" ], extra: {})
    Baseline::Policy.new("version" => 1, "checks" => {
      "snmp.acl_bound" => { "expected" => true }, "snmp.acl_restricted" => { "expected" => true },
      "snmp.sources" => { "expected" => limits, "remediation" => { "access_targets" => [ target ], "global_acl_supported" => supported } }
    }.merge(extra))
  end

  def configuration(global = "")
    "sysname LAB\nsnmp-agent\n#{global}" \
      "acl basic 2000\n rule 5 permit source 192.0.2.0 0.0.0.127\n rule 10 permit source 198.51.100.0 0.0.0.255\n rule 15 deny\n#\n" \
      "acl basic 2001\n rule 5 permit source 192.0.2.0 0.0.0.63\n rule 10 permit source 198.51.100.0 0.0.0.255\n rule 15 deny\n#\n" \
      "snmp-agent group v3 OPS privacy acl 2001\nsnmp-agent usm-user v3 observer OPS authentication-mode sha cipher SYNTHETIC-AUTH privacy-mode aes128 cipher SYNTHETIC-PRIV acl 2000\n" \
      "snmp-agent community read cipher SYNTHETIC-COMMUNITY acl 2000\n"
  end

  it "adds a global filter without rewriting principals or widening their different existing permissions" do
    input = configuration
    service = Baseline::Remediation.new(policy: policy)
    result = service.call(configuration: input, platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "acl basic 2005", "rule 5 permit source 192.0.2.0 0.0.0.255", "rule 10 deny", "quit", "snmp-agent acl 2005", "return" ])
    expect(result.operations.map(&:phase)).to eq(%i[create update])
    after = input + "acl basic 2005\n rule 5 permit source 192.0.2.0 0.0.0.255\n rule 10 deny\n#\nsnmp-agent acl 2005\n"
    repeated = service.call(configuration: after, platform: "h3c", complete: true)
    expect(repeated.audit.configuration.fact("snmp.access_endpoints").map { |entry| entry[:sources] }).to eq([ [ "192.0.2.0/25" ], [ "192.0.2.0/26" ] ])
    expect(repeated.audit).to be_compliant
    expect(repeated.status).to eq(:noop)
    expect(result.to_h.to_json).not_to include("SYNTHETIC-AUTH", "SYNTHETIC-PRIV", "SYNTHETIC-COMMUNITY")
  end

  it "preserves a stricter existing global filter while changing its shared reference" do
    service = Baseline::Remediation.new(policy: policy(supported: false))
    result = service.call(configuration: configuration("snmp-agent acl 2000\n"), platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("rule 5 permit source 192.0.2.0 0.0.0.127", "snmp-agent acl 2005")
    expect(result.configuration_commands.grep(/undo/)).to be_empty
  end

  it "requires explicit targets for otherwise unbound principals and checks approved limits" do
    input = "sysname LAB\nsnmp-agent\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY\n"
    missing = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
    expect(missing.operations).to be_empty
    expect(missing.checks.last.reason).to eq(:approved_access_targets_required)
    target = { "endpoint" => "snmp.global", "acl" => "2005", "sources" => [ "192.0.2.10/32" ] }
    result = Baseline::Remediation.new(policy: policy(target)).call(configuration: input, platform: "h3c", complete: true)
    expect(result.status).to eq(:ready)
    outside = policy(target.merge("sources" => [ "198.51.100.0/24" ]))
    expect(Baseline::Remediation.new(policy: outside).call(configuration: input, platform: "h3c", complete: true).operations).to be_empty
  end

  it "does not assume a global ACL command exists on an unverified firmware profile" do
    result = Baseline::Remediation.new(policy: policy(supported: false)).call(configuration: configuration, platform: "h3c", complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:snmp_global_acl_support_required)
    expect(result.checks.last.requirements).to include("global_acl_supported")
  end

  it "rejects widening, occupied identities, empty intersections, partial input and disabled-service conflicts" do
    target = { "endpoint" => "snmp.global", "acl" => "2005" }
    [ [ configuration("snmp-agent acl 2001\n"), policy(target.merge("sources" => [ "192.0.2.0/24" ])) ],
      [ configuration + "unknown reference 2005\n", policy ],
      [ configuration, policy(limits: [ "203.0.113.0/24" ]) ],
      [ configuration, policy(extra: { "snmp.enabled" => { "expected" => false } }) ] ].each do |input, approved|
      expect(Baseline::Remediation.new(policy: approved).call(configuration: input, platform: "h3c", complete: true).operations).to be_empty
    end
    expect(Baseline::Remediation.new(policy: policy).call(configuration: configuration, platform: "h3c", complete: false).operations).to be_empty
  end

  it "blocks simultaneous management and SNMP plans that allocate the same fresh ACL" do
    target = { "endpoint" => "line vty 0 4", "acl" => "2005", "sources" => [ "192.0.2.10/32" ] }
    approved = policy(extra: {
      "management.acl_bound" => { "expected" => true },
      "management.sources" => { "expected" => [ "192.0.2.10/32" ], "remediation" => { "access_targets" => [ target ] } }
    })
    input = configuration + "line vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n"
    result = Baseline::Remediation.new(policy: approved).call(configuration: input, platform: "h3c", complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.select { |item| item.status == :blocked }.map(&:reason)).to all(eq(:policy_conflict))
  end

  it "publishes actual global ACL prerequisites without implying support on other vendors" do
    capability = Baseline::Remediation.capabilities(platform: "h3c").fetch("snmp.sources")
    expect(capability[:status]).to eq(:conditional)
    expect(capability[:requirements]).to include("global_acl_support_evidence", "explicit_targets_for_unbound_principals")
    expect(capability[:prerequisites]).to include("snmp.enabled" => true)
    expect(Baseline::Remediation.capabilities(platform: "huawei").fetch("snmp.sources")[:status]).to eq(:unsupported)
  end

  it "names the missing approved source limit instead of copying current device addresses" do
    approved = Baseline::Policy.new("version" => 1, "checks" => { "snmp.acl_restricted" => { "expected" => true } })
    input = "sysname LAB\nsnmp-agent\nsnmp-agent community read cipher SYNTHETIC-COMMUNITY\n"
    result = Baseline::Remediation.new(policy: approved).call(configuration: input, platform: "h3c", complete: true)
    expect(result.operations).to be_empty
    expect(result.checks.first.reason).to eq(:approved_access_limits_required)
    expect(result.checks.first.requirements).to include("snmp.sources")
  end

  it "validates the support flag and forbids VTY targets on SNMP ACL rules" do
    expect { policy(supported: "yes") }.to raise_error(ArgumentError)
    expect { policy({ "endpoint" => "line vty 0 4", "acl" => "2005" }) }.to raise_error(ArgumentError)
  end
end

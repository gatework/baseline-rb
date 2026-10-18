# frozen_string_literal: true

require_relative "spec_helper"
require "baseline/remediation"
require_relative "support/h3c_tacacs_state"

RSpec.describe "H3C TACACS target remediation" do
  def source(primary = "192.0.2.30", secondary = [ "192.0.2.31" ])
    "sysname LAB\nhwtacacs scheme OPS\n primary authentication #{primary} 49\n" +
      secondary.map { |address| " secondary authentication #{address} 49\n" }.join +
      " key authentication cipher SYNTHETIC-AUTH\n key authorization cipher SYNTHETIC-AUTHZ\n key accounting cipher SYNTHETIC-ACCT\n#\n" \
      "domain ADMIN\n authentication login hwtacacs-scheme OPS local\n#\ndomain default enable ADMIN\nlocal-user operator class manage\n password cipher SYNTHETIC-LOCAL\n service-type ssh\n#\nline vty 0 4\n authentication-mode scheme\n protocol inbound ssh\n#\n"
  end

  def target(address, priority = "primary", attributes: {})
    { "identity" => { "address" => address, "role" => "authentication", "priority" => priority },
      "scope" => { "group" => "OPS", "vrf" => "default" }, "attributes" => attributes }
  end

  def policy(targets, options: {}, checks: {})
    approval = { "syntax_profile" => "comware7", "local_fallback_access_verified" => true, "tacacs_key_compatibility_verified" => true }.merge(options)
    Baseline::Policy.new("version" => 1, "checks" => checks.merge("tacacs.endpoints" => {
      "expected" => targets, "managed_scopes" => [ { "group" => "OPS", "vrf" => "default" } ], "remediation" => approval
    }))
  end

  def plan(text, targets, options: {}, checks: {}, complete: true)
    Baseline::Remediation.new(policy: policy(targets, options: options, checks: checks)).call(configuration: text, platform: "h3c", complete: complete)
  end

  it "replaces a primary slot without deleting the new target and converges on independent configuration" do
    targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ]
    result = plan(source, targets)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "hwtacacs scheme OPS", "primary authentication 192.0.2.32 49", "return" ])
    expect(result.operations).to contain_exactly(have_attributes(kind: "tacacs.primary", action: :replace, risk: "high"))
    expect(result.configuration_commands.join).not_to include("SYNTHETIC-", "key authentication")
    after = source("192.0.2.32")
    expect(plan(after, targets).status).to eq(:noop)
    expect(Baseline::Audit.new(policy: policy(targets)).call(configuration: after, platform: "h3c", complete: true)).to be_compliant
  end

  it "adds a new secondary before removing an old secondary and preserves unrelated statements" do
    targets = [ target("192.0.2.30"), target("192.0.2.33", "secondary") ]
    result = plan(source, targets, options: { "maximum_targets" => 3 })
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to eq([ "system-view", "hwtacacs scheme OPS", "secondary authentication 192.0.2.33 49", "undo secondary authentication 192.0.2.31 49", "return" ])
    expect(plan(source("192.0.2.30", [ "192.0.2.33" ]), targets).status).to eq(:noop)
  end

  it "can remove a secondary first to respect confirmed capacity while keeping a primary path" do
    targets = [ target("192.0.2.30"), target("192.0.2.33", "secondary") ]
    result = plan(source, targets, options: { "maximum_targets" => 2 })
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands.index("undo secondary authentication 192.0.2.31 49")).to be < result.configuration_commands.index("secondary authentication 192.0.2.33 49")
    expect(result.checks.first.details[:early_removals]).to eq(1)
  end

  it "retains a role endpoint for every current domain reference and refuses binding rewrites" do
    result = plan(source, [])
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:tacacs_reference_would_break)
    wanted = target("192.0.2.32")
    wanted["bindings"] = []
    result = plan(source, [ wanted, target("192.0.2.31", "secondary") ])
    expect(result.checks.first.reason).to eq(:tacacs_binding_change_required)
    expect(result.operations).to be_empty
  end

  it "does not create a target from count-only or address-only policy" do
    definition = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.minimum_servers" => { "expected" => 3 } })
    result = Baseline::Remediation.new(policy: definition).call(configuration: source, platform: "h3c", complete: true)
    expect(result.checks.first.requirements).to include("approved_tacacs_endpoints")
    expect(result.operations).to be_empty
  end

  it "honors legacy server and minimum-count constraints in the same projection" do
    targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ]
    result = plan(source, targets, checks: { "tacacs.servers" => { "expected" => %w[192.0.2.30 192.0.2.31] } })
    expect(result.status).to eq(:blocked)
    expect(result.operations).to be_empty
    expect(result.checks.last.reason).to eq(:policy_conflict)
  end

  it "requires verified fallback and matching server-side material, and cannot use unknown scheme keys" do
    targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ]
    %w[local_fallback_access_verified tacacs_key_compatibility_verified].each do |key|
      result = plan(source, targets, options: { key => false })
      expect(result.status).to eq(:blocked)
      expect(result.checks.first.requirements).to include(key)
    end
    result = plan(source.sub(" key authentication cipher SYNTHETIC-AUTH\n", ""), targets)
    expect(result.checks.first.reason).to eq(:tacacs_key_dependency)
    expect(result.operations).to be_empty
  end

  it "does not generate operations from partial capture or unknown source options" do
    targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ]
    expect(plan(source, targets, complete: false).operations).to be_empty
    malformed = source.sub("primary authentication 192.0.2.30 49", "primary authentication 192.0.2.30 49 key cipher PRIVATE-INLINE")
    result = plan(malformed, targets)
    expect(result.operations).to be_empty
    expect(result.to_h.to_s).not_to include("PRIVATE-INLINE")
  end

  it "blocks group routing contexts that are not yet represented by endpoint scope" do
    targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ]
    routed = source.sub("hwtacacs scheme OPS\n", "hwtacacs scheme OPS\n vpn-instance MGMT\n")
    expect(plan(routed, targets).checks.first.reason).to eq(:tacacs_context_unresolved)
  end

  it "preserves declared single-connection and supports a literal IPv6 primary target" do
    text = source.sub("primary authentication 192.0.2.30 49", "primary authentication 192.0.2.30 49 single-connection")
    result = plan(text, [ target("192.0.2.32"), target("192.0.2.31", "secondary") ])
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("primary authentication 192.0.2.32 49 single-connection")
    targets = [ target("2001:db8::32"), target("192.0.2.31", "secondary") ]
    result = plan(source("ipv6 2001:db8::30"), targets)
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("primary authentication ipv6 2001:db8::32 49")
    expect(plan(source("ipv6 2001:db8::32"), targets).status).to eq(:noop)
  end

  it "requires an existing alternate endpoint when a flag reset needs remove then re-create" do
    text = source.sub("primary authentication 192.0.2.30 49", "primary authentication 192.0.2.30 49 single-connection")
    targets = [ target("192.0.2.30", attributes: { "single_connection" => false }), target("192.0.2.31", "secondary") ]
    result = plan(text, targets)
    expect(result.configuration_commands).to include("undo primary authentication", "primary authentication 192.0.2.30 49")
    expect(plan(source, targets).status).to eq(:noop)
    sole = source("192.0.2.30", []).sub("primary authentication 192.0.2.30 49", "primary authentication 192.0.2.30 49 single-connection")
    expect(plan(sole, targets.first(1)).checks.first.reason).to eq(:tacacs_transition_would_disconnect)
  end

  it "blocks secondary address aliases that name the same native endpoint" do
    text = source("192.0.2.30", [ "ipv6 2001:db8::31" ])
    result = plan(text, [ target("192.0.2.30"), target("2001:0db8:0:0:0:0:0:31", "secondary") ])
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:tacacs_context_unresolved)
    expect(result.operations).to be_empty
  end

  it "advertises the actual target prerequisites separately from binding writes" do
    capability = Baseline::Remediation.capabilities(platform: "h3c").fetch("tacacs.endpoints")
    expect(capability).to include(status: :conditional)
    expect(capability[:requirements]).to include("approved_tacacs_endpoints", "managed_scopes", "syntax_profile",
      "local_fallback_access_verified", "tacacs_key_compatibility_verified", "existing_scheme_role_key", "preserved_domain_references")
    expect(Baseline::Remediation.capabilities(platform: "huawei").fetch("tacacs.endpoints")[:status]).to eq(:unsupported)
  end


  it "does not reuse an occupied native endpoint under the other priority during a transition" do
    result = plan(source, [ target("192.0.2.31"), target("192.0.2.30", "secondary") ])
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:tacacs_context_unresolved)
    expect(result.operations).to be_empty
  end


  it "does not temporarily exceed the native sixteen-secondary limit" do
    addresses = (1..16).map { |number| "198.51.100.#{number}" }
    targets = [ target("192.0.2.30"), *addresses.drop(1).map { |address| target(address, "secondary") }, target("198.51.100.17", "secondary") ]
    result = plan(source("192.0.2.30", addresses), targets, options: { "maximum_targets" => 18 })
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:capacity_exceeded)
    expect(result.operations).to be_empty
    ordered = plan(source("192.0.2.30", addresses), targets, options: { "maximum_targets" => 18, "order" => "remove_before_add" })
    expect(ordered.status).to eq(:ready)
  end


  it "converges through an independent native state model without changing other statements" do
    variants = [
      [ source, [ target("192.0.2.32"), target("192.0.2.31", "secondary") ], {} ],
      [ source, [ target("192.0.2.30"), target("192.0.2.33", "secondary") ], { "maximum_targets" => 3 } ],
      [ source, [ target("192.0.2.30"), target("192.0.2.33", "secondary") ], { "maximum_targets" => 2 } ],
      [ source("ipv6 2001:db8::30"), [ target("2001:db8::32"), target("192.0.2.31", "secondary") ], {} ],
      [ source.sub("192.0.2.30 49", "192.0.2.30 49 single-connection"),
        [ target("192.0.2.30", attributes: { "single_connection" => false }), target("192.0.2.31", "secondary") ], {} ]
    ]
    variants.each do |before, targets, options|
      result = plan(before, targets, options: options)
      expect(result.status).to eq(:ready)
      after = H3cTacacsState.new(before).apply(result.configuration_commands).configuration
      unrelated = ->(text) { text.lines.reject { |line| /\A (?:primary|secondary) /.match?(line) } }
      expect(unrelated.call(after)).to eq(unrelated.call(before))
      expect(Baseline::Audit.new(policy: policy(targets)).call(configuration: after, platform: "h3c", complete: true)).to be_compliant
      expect(plan(after, targets, options: options).status).to eq(:noop)
    end
  end

  it "repairs a missing referenced role using existing scheme material and explicit capacity" do
    text = source.lines.reject { |line| /\A (?:primary|secondary) authentication /.match?(line) }.join
    targets = [ target("192.0.2.32") ]
    result = plan(text, targets, options: { "maximum_targets" => 1 })
    expect(result.status).to eq(:ready)
    expect(result.configuration_commands).to include("primary authentication 192.0.2.32 49")
    after = H3cTacacsState.new(text).apply(result.configuration_commands).configuration
    expect(plan(after, targets).status).to eq(:noop)
  end

  it "retains an unrelated scheme and renders each supported role in its own slot" do
    %w[authentication authorization accounting].each do |role|
      text = source.gsub("primary authentication", "primary #{role}").gsub("secondary authentication", "secondary #{role}")
        .sub("domain ADMIN", "hwtacacs scheme OTHER\n primary authentication 198.51.100.40 49\n#\ndomain ADMIN")
        .sub("authentication login", "#{role} login")
      targets = [ target("192.0.2.32"), target("192.0.2.31", "secondary") ].map do |object|
        object.merge("identity" => object["identity"].merge("role" => role))
      end
      result = plan(text, targets)
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands).to include("primary #{role} 192.0.2.32 49")
      after = H3cTacacsState.new(text).apply(result.configuration_commands).configuration
      expect(after).to include("hwtacacs scheme OTHER\n primary authentication 198.51.100.40 49\n#")
      expect(plan(after, targets).status).to eq(:noop)
    end
  end

  it "does not treat duplicate observed native addresses as two fallback paths or capacity slots" do
    text = source("192.0.2.30", [ "ipv6 2001:db8::31", "ipv6 2001:0db8:0:0:0:0:0:31" ])
      .lines.reject { |line| line.start_with?(" primary authentication") }.join
    result = plan(text, [ target("192.0.2.32", "secondary") ])
    expect(result.checks.first.reason).to eq(:native_resource_identity_unresolved)
    expect(result.operations).to be_empty
  end
end

# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Typed TACACS domain bindings" do
  def endpoint(bindings: :omitted)
    object = { "identity" => { "address" => "192.0.2.30", "role" => "authentication", "priority" => "primary" }, "scope" => { "group" => "OPS" } }
    object["bindings"] = bindings unless bindings == :omitted
    object
  end

  def binding(domain = "ADMIN", position: "primary", selected: :omitted)
    value = { "kind" => "aaa.domain", "domain" => domain, "role" => "authentication", "position" => position }
    value["selected"] = selected unless selected == :omitted
    value
  end

  def source(method = "hwtacacs-scheme OPS local")
    "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\ndomain ADMIN\n authentication login #{method}\n#\n" \
      "domain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n#\n"
  end

  def audit(text, object = endpoint(bindings: [ binding ]), platform: "h3c", complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.endpoints" => { "expected" => [ object ] } })
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: complete)
  end

  it "keeps omitted binding requirements explicitly at object-definition scope" do
    result = audit(source("local"), endpoint)
    expect(result).to be_compliant
    expect(result.findings.first.details[:verification_scope]).to eq(:objects_only)
    expect(result.to_text).to include("仅对象定义，未核验使用链")
    expect(result.to_text).not_to include("差异:")
  end

  it "checks approved domain reference, role, position and optional selected status" do
    result = audit(source, endpoint(bindings: [ binding("admin", selected: true) ]))
    expect(result).to be_compliant
    expect(result.findings.first.details[:verification_scope]).to eq(:objects_and_requested_bindings)
    resource = result.configuration.resources.find { |r| r.kind == "tacacs.endpoint" }
    expect(resource.bindings).to contain_exactly(binding("admin", selected: true))
    expect(resource.bindings).to be_frozen
  end

  it "fails an unreferenced definition and separates fallback from primary use" do
    result = audit(source("local"))
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details.fetch(:binding_differences).first[:missing]).to eq([ binding("admin") ])
    result = audit(source("local hwtacacs-scheme OPS"))
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details.fetch(:binding_differences).first[:unexpected]).to contain_exactly(binding("admin", position: "fallback", selected: true))
  end

  it "retains shared references from unselected domains and detects extra uses" do
    text = source + "domain OTHER\n authentication login hwtacacs-scheme OPS local\n#\n"
    result = audit(text)
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details.fetch(:binding_differences).first[:unexpected]).to contain_exactly(binding("other", selected: false))
    all = [ binding, binding("OTHER", selected: false) ]
    expect(audit(text, endpoint(bindings: all))).to be_compliant
  end

  it "checks selected status without deleting a known unselected domain reference" do
    text = source + "domain OTHER\n authentication login local\n#\ndomain default enable OTHER\n"
    result = audit(text, endpoint(bindings: [ binding(selected: true) ]))
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details.fetch(:binding_differences).first[:changed]).not_to be_empty
    expect(audit(text, endpoint(bindings: [ binding ]))).to be_compliant
  end

  it "requires known inventory for an explicit unbound assertion and never certifies unknown references" do
    text = source("local") + "domain OTHER\n authentication login hwtacacs-scheme OPS UNKNOWN-PRIVATE-TAIL\n#\n"
    result = audit(text, endpoint(bindings: []))
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.findings.first.reason).to eq(:resource_binding_unresolved)
    expect(result.to_h.to_s).not_to include("UNKNOWN-PRIVATE-TAIL")
    expect(audit(source, endpoint(bindings: [ binding ]), complete: false).findings.first.status).to eq(:unknown)
    partial = audit(source, endpoint(bindings: [ binding ]), complete: false).configuration
    expect(partial.fact("aaa.domain_bindings_complete").values).to all(be(false))
    expect(partial.resources.find { |resource| resource.kind == "tacacs.endpoint" }.bindings).to be_nil
  end

  it "resolves Huawei domain bindings through its separate named scheme and template" do
    text = "sysname LAB\nhwtacacs-server template OPS\n hwtacacs-server authentication 192.0.2.30\n#\ndomain ADMIN admin\n" \
      "aaa\n authentication-scheme TAC\n  authentication-mode hwtacacs local\n domain ADMIN\n  authentication-scheme TAC\n  hwtacacs-server OPS\n#\nuser-interface vty 0 4\n authentication-mode aaa\n"
    expect(audit(text, endpoint(bindings: [ binding(selected: true) ]), platform: "huawei")).to be_compliant
  end

  it "rejects unknown fields, missing identity, duplicate logical bindings and command injection" do
    invalid = [ binding.merge("secret" => "PRIVATE"), binding.reject { |key, _| key == "role" }, binding.merge("position" => "any"),
      binding.merge("domain" => "ADMIN\nsave"), binding.merge("selected" => "yes"), binding.merge("kind" => "raw.command") ]
    invalid.each do |value|
      expect { audit(source, endpoint(bindings: [ value ])) }.to raise_error(ArgumentError)
    end
    expect { audit(source, endpoint(bindings: [ binding("ADMIN"), binding("admin", selected: true) ])) }.to raise_error(ArgumentError)
  end

  it "owns binding values without freezing or retaining caller strings" do
    name = +"ADMIN"
    values = [ binding(name) ]
    resource = Baseline::ConfigurationResource.new(kind: "tacacs.endpoint", identity: { "address" => "192.0.2.30" }, bindings: values)
    name.replace("OTHER")
    values.clear
    expect(name).not_to be_frozen
    expect(resource.bindings).to contain_exactly(binding("admin"))
  end

  it "clears withdrawn unselected references without changing the selected-domain result" do
    text = source + "domain OTHER\n authentication login hwtacacs-scheme OPS local\n#\nundo domain OTHER\n"
    expect(audit(text)).to be_compliant
    malformed = source + "domain OTHER\n authentication login hwtacacs-scheme OPS PRIVATE-TAIL\n#\n"
    result = audit(malformed)
    expect(result.configuration.fact("tacacs.login")).to be(true)
    expect(result.findings.first.status).to eq(:unknown)
    anonymous = source("local") + "domain\n authentication login hwtacacs-scheme OPS local\n#\n"
    expect(audit(anonymous, endpoint(bindings: [])).findings.first.status).to eq(:unknown)
  end

  it "preserves a conclusive attribute mismatch alongside unknown binding evidence" do
    object = endpoint(bindings: [])
    object["attributes"] = { "port" => 149 }
    text = source.sub("primary authentication 192.0.2.30", "primary authentication 192.0.2.30 49") + "domain OTHER\n authentication login UNKNOWN-TAIL\n#\n"
    result = audit(text, object)
    expect(result.findings.first.status).to eq(:fail)
    expect(result.findings.first.details.fetch(:changed)).not_to be_empty
    expect(result.findings.first.details.fetch(:unresolved)).not_to be_empty
  end

  it "keeps unmodelled vendor bindings unknown even when the endpoint definition is known" do
    text = "hostname LAB\ntacacs-server host 192.0.2.30\n"
    report = Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: text, platform: "cisco_ios", complete: true)
    resource = report.configuration.resources.find { |item| item.kind == "tacacs.endpoint" }
    object = { "identity" => resource.identity, "scope" => resource.scope, "bindings" => [] }
    result = audit(text, object, platform: "cisco_ios")
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.findings.first.reason).to eq(:resource_binding_unresolved)
  end

  it "exposes reference support separately from object parsing support" do
    h3c = Baseline::Audit.capabilities(platform: "h3c").fetch("tacacs.endpoints")
    expect(h3c[:bindings]).to include(status: :conditional, kinds: [ "aaa.domain" ])
    ios = Baseline::Audit.capabilities(platform: "cisco_ios").fetch("tacacs.endpoints")
    expect(ios[:status]).to eq(:supported)
    expect(ios[:bindings]).to include(status: :unsupported, kinds: [])
  end
end

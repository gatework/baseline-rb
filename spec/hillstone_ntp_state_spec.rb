# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "StoneOS NTP configuration evidence" do
  def evidence(text, complete: true)
    Baseline::Audit.new(policy: Baseline::Policy.default).call(configuration: "hostname LAB\n#{text}", platform: :hillstone, complete: complete).configuration
  end

  it "reduces an address across vrouter changes, withdrawal and recreation as one native endpoint" do
    text = "ntp server TIME.EXAMPLE vrouter OLD source MGT0 prefer\n" \
      "ntp server time.example vrouter NEW source MGT1\n"
    result = evidence(text)
    expect(result.fact("ntp.associations")).to eq([ { "identity" => { "address" => "time.example", "role" => "server" },
      "scope" => { "vrf" => "NEW" }, "attributes" => { "source" => "MGT1", "prefer" => false } } ])
    expect(result.fact("ntp.source")).to eq("MGT1")
    expect(evidence(text + "no ntp server Time.Example\n").fact("ntp.servers")).to eq([])
    recreated = evidence(text + "no ntp server TIME.EXAMPLE\nntp server time.example\n")
    expect(recreated.fact("ntp.associations").first).to include("scope" => { "vrf" => "default" }, "attributes" => { "prefer" => false })
    expect(recreated.fact("ntp.source")).to be_nil
  end

  it "invalidates malformed final endpoint and switch updates without stale fallback" do
    text = "ntp server 192.0.2.10 source MGT0\nntp server 192.0.2.10 source\n"
    expect(evidence(text).fact_known?("ntp.associations")).to be(false)
    expect(evidence(text + "no ntp server 192.0.2.10\n").fact("ntp.servers")).to eq([])
    expect(evidence("ntp authentication\nntp authentication PRIVATE-TAIL\n").fact_known?("ntp.authentication")).to be(false)
    restored = evidence("ntp authentication PRIVATE-TAIL\nno ntp authentication\n")
    expect(restored.fact("ntp.authentication")).to be(false)
    expect(restored.facts.to_s).not_to include("PRIVATE-TAIL")
  end

  it "uses documented disabled defaults only for complete input and validates native key ranges" do
    expect(evidence("ntp server 192.0.2.10\n").fact("ntp.authentication")).to be(false)
    expect(evidence("ntp server 192.0.2.10\n", complete: false).fact_known?("ntp.authentication")).to be(false)
    expect(evidence("ntp server 192.0.2.10 key 65536\n").fact_known?("ntp.associations")).to be(false)
  end

  it "retains final nonsecret material and distinguishes implicit key use from explicit trust declarations" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7\n"
    result = evidence(text)
    expect(result.fact_known?("ntp.key_slots")).to be(true)
    expect(result.fact("ntp.key_slots")).to contain_exactly(include(key_id: 7, present: true, complete: true, algorithm: "md5", trust_required: false))
    expect(result.fact("ntp.authentication_bindings").first).to include(configured_ready: true, trust_required: false, key_trusted: nil)
    expect(result.fact("credentials.records")).to include(include(kind: "ntp", purpose: "authentication", storage: "plaintext"))
    expect(result.facts.to_s).not_to include("SYNTHETIC-KEY")
    removed = evidence(text + "no ntp authentication-key 7\n")
    expect(removed.fact("ntp.key_slots").first).to include(present: false)
    expect(removed.fact("credentials.records")).to eq([])
    expect(removed.fact("ntp.authentication_bindings").first).to include(configured_ready: false, reason: :ntp_key_missing)
  end

  it "does not certify incomplete, stale, unsupported or interface-local material" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7\n"
    result = evidence(text + "ntp authentication-key 7 md5\n")
    expect(result.fact_known?("ntp.key_slots")).to be(false)
    expect(result.fact("credentials.records")).to include(include(kind: "ntp", storage: "unknown", present: nil))
    expect(result.fact("ntp.authentication_bindings").first[:configured_ready]).to be_nil
    expect(evidence(text, complete: false).fact_known?("ntp.key_slots")).to be(false)
    nested = "interface ethernet0/0\n ntp authentication-key 7 md5 SYNTHETIC-KEY\nexit\nntp server 192.0.2.10 key 7\n"
    expect(evidence(nested).fact("ntp.key_slots").first[:present]).to be(false)
  end

  it "does not prove an empty association inventory when a peer family is unmodelled" do
    result = evidence("ntp peer 192.0.2.10 PRIVATE-TAIL\n")
    expect(result.fact_known?("ntp.associations")).to be(false)
    expect(result.facts.to_s).not_to include("PRIVATE-TAIL")
  end

  it "keeps per-association readiness unknown when the material inventory cannot identify an update" do
    text = "ntp authentication-key 7 md5 SYNTHETIC-KEY\nntp authentication\nntp server 192.0.2.10 key 7\n" \
      "ntp authentication-key UNKNOWN md5 PRIVATE-TAIL\n"
    result = evidence(text)
    expect(result.fact_known?("ntp.key_slots")).to be(false)
    expect(result.fact("ntp.authentication_bindings").first).to include(configured_ready: nil, reason: :ntp_key_inventory_unresolved)
    expect(result.facts.to_s).not_to include("PRIVATE-TAIL", "SYNTHETIC-KEY")
  end
end

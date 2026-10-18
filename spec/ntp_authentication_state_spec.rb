# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "NTP authentication material and trust evidence" do
  def evidence(body, platform: "h3c", complete: true)
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.authentication" => { "expected" => true } })
    Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{body}\n", platform: platform, complete: complete).configuration
  end

  def key(id = 7, format = "cipher", value = "SYNTHETIC-KEY")
    "ntp-service authentication-keyid #{id} authentication-mode md5 #{format} #{value}\n"
  end

  def configured
    "ntp-service authentication enable\n#{key}ntp-service reliable authentication-keyid 7\nntp-service unicast-server 192.0.2.10 authentication-keyid 7\n"
  end

  it "separates the global switch, final material, trusted declarations and association readiness" do
    result = evidence(configured)
    expect(result.fact("ntp.authentication")).to be(true)
    expect(result.fact("ntp.key_slots")).to contain_exactly(include(key_id: 7, algorithm: "md5", format: "cipher", present: true, complete: true, trusted: true))
    expect(result.fact("ntp.authentication_bindings")).to contain_exactly(include(key_id: 7, configured_ready: true, reason: nil))
    record = result.fact("credentials.records").find { |item| item[:kind] == "ntp" }
    expect(record).to include(owner: "ntp-key:7", purpose: "authentication", storage: "protected")
    expect(result.facts.to_s).not_to include("SYNTHETIC-KEY")
  end

  it "does not prove readiness from an enabled switch, unknown key, or untrusted material" do
    no_key = evidence(configured.lines.reject { |line| line.start_with?("ntp-service authentication-keyid") }.join)
    expect(no_key.fact("ntp.authentication_bindings").first).to include(configured_ready: false, reason: :ntp_key_missing)
    untrusted = evidence(configured.sub("ntp-service reliable authentication-keyid 7\n", ""))
    expect(untrusted.fact("ntp.authentication_bindings").first).to include(configured_ready: false, reason: :ntp_key_untrusted)
    no_reference = evidence(configured.sub("192.0.2.10 authentication-keyid 7", "192.0.2.10"))
    expect(no_reference.fact("ntp.authentication_bindings").first).to include(configured_ready: false, reason: :ntp_key_reference_missing)
  end

  it "reduces material replacements and withdrawals before recording credential evidence" do
    result = evidence(configured + key(7, "simple", "OLD-PLAINTEXT") + key(7))
    expect(result.fact("credentials.records")).to contain_exactly(include(owner: "ntp-key:7", storage: "protected"))
    removed = evidence(configured + "undo ntp-service authentication-keyid 7\n" + key(7))
    expect(removed.fact("ntp.key_slots").first).to include(present: true, trusted: false)
    expect(removed.fact("ntp.authentication_bindings").first[:configured_ready]).to be(false)
    expect(evidence(configured + "undo ntp-service authentication-keyid 7\n").fact("credentials.records")).to eq([])
  end

  it "invalidates malformed final updates without retaining stale material or exporting the tail" do
    result = evidence(configured + "ntp-service authentication-keyid 7 authentication-mode md5 cipher\n")
    expect(result.fact("ntp.key_slots").first).to include(present: nil, complete: false)
    expect(result.fact("ntp.authentication_bindings").first).to include(configured_ready: nil, reason: :ntp_key_unresolved)
    expect(result.fact("credentials.records")).to contain_exactly(include(owner: "ntp-key:7", storage: "unknown", present: nil))
    unknown = evidence(configured + "ntp-service authentication-keyid 7 authentication-mode FUTURE cipher PRIVATE-UNKNOWN\n")
    expect(unknown.facts.to_s).not_to include("PRIVATE-UNKNOWN")
  end

  it "keeps missing evidence unknown in partial input and does not use interface-local material" do
    result = evidence("ntp-service authentication enable\nntp-service unicast-server 192.0.2.10 authentication-keyid 7", complete: false)
    expect(result.fact_known?("ntp.key_slots")).to be(false)
    expect(result.fact("ntp.authentication_bindings").first[:configured_ready]).to be_nil
    nested = "interface Vlan-interface1\n #{key}#\nntp-service unicast-server 192.0.2.10 authentication-keyid 7\n"
    expect(evidence(nested).fact("ntp.key_slots").first[:present]).to be(false)
  end

  it "uses Huawei key syntax independently from the Comware algorithm and secret-format set" do
    text = "ntp-service authentication enable\nntp-service authentication-keyid 7 authentication-mode hmac-sha256 cipher SYNTHETIC-KEY\n" \
      "ntp-service reliable authentication-keyid 7\nntp-service unicast-server 192.0.2.10 authentication-keyid 7\n"
    expect(evidence(text, platform: "huawei").fact("ntp.authentication_bindings").first[:configured_ready]).to be(true)
    expect(evidence(text).fact("ntp.authentication_bindings").first[:configured_ready]).to be_nil
  end

  it "invalidates a malformed final trust declaration and recovers only with an explicit later state" do
    malformed = configured + "ntp-service reliable authentication-keyid 7 unsupported-option VALUE\n"
    expect(evidence(malformed).fact("ntp.key_slots").first[:trusted]).to be_nil
    restored = evidence(malformed + "ntp-service reliable authentication-keyid 7\n")
    expect(restored.fact_known?("ntp.key_slots")).to be(true)
    expect(restored.fact("ntp.authentication_bindings").first[:configured_ready]).to be(true)
  end

  it "does not certify a stale switch after an unsupported final authentication declaration" do
    result = evidence(configured + "ntp-service authentication enable unsupported-option VALUE\n")
    expect(result.fact_known?("ntp.authentication")).to be(false)
    expect(result.fact("ntp.authentication_bindings").first[:configured_ready]).to be_nil
    restored = evidence(configured + "ntp-service authentication enable unsupported-option VALUE\nntp-service authentication enable\n")
    expect(restored.fact_known?("ntp.authentication")).to be(true)
    expect(restored.fact("ntp.authentication_bindings").first[:configured_ready]).to be(true)
  end

  it "retains an independently proven unsafe credential alongside unknown final NTP material" do
    body = configured + "ntp-service authentication-keyid 7 authentication-mode md5 cipher\n" +
      "local-user operator class manage\n password simple SYNTHETIC-PLAINTEXT\n#\n"
    policy = Baseline::Policy.new("version" => 1, "checks" => { "credentials.storage" => { "expected" => true } })
    report = Baseline::Audit.new(policy: policy).call(configuration: "sysname LAB\n#{body}", platform: "h3c", complete: true)
    expect(report.findings.first.status).to eq(:fail)
    expect(report.configuration.fact("credentials.records")).to include(include(kind: "ntp", owner: "ntp-key:7", storage: "unknown", present: nil))
  end

  it "distinguishes explicit trust withdrawal from a disabled global switch" do
    withdrawn = evidence(configured + "undo ntp-service reliable authentication-keyid 7\n")
    expect(withdrawn.fact("ntp.authentication_bindings").first).to include(configured_ready: false, reason: :ntp_key_untrusted)
    disabled = evidence(configured + "undo ntp-service authentication enable\n")
    expect(disabled.fact("ntp.authentication_bindings").first).to include(key_trusted: true, configured_ready: false, reason: :ntp_authentication_disabled)
  end

  it "keeps VRP deletion trust unknown and classifies its bare material as plaintext" do
    text = configured + "undo ntp-service authentication-keyid 7\n" +
      "ntp-service authentication-keyid 7 authentication-mode hmac-sha256 SYNTHETIC-PLAINTEXT\n"
    result = evidence(text, platform: "huawei")
    expect(result.fact("ntp.key_slots").first).to include(present: true, trusted: nil, format: "plain")
    expect(result.fact("ntp.authentication_bindings").first[:configured_ready]).to be_nil
    expect(result.fact("credentials.records")).to contain_exactly(include(kind: "ntp", storage: "plaintext"))
    restored = evidence(text + "ntp-service reliable authentication-keyid 7\n", platform: "huawei")
    expect(restored.fact("ntp.authentication_bindings").first[:configured_ready]).to be(true)
  end
end

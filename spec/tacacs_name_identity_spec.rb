# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Vendor-specific TACACS name identity" do
  def audit(text, platform, checks)
    policy = Baseline::Policy.new("version" => 1, "checks" => checks.transform_values { |expected| { "expected" => expected } })
    Baseline::Audit.new(policy: policy).call(configuration: text, platform: platform, complete: true)
  end

  it "merges case variants of the same H3C scheme before counting primary servers" do
    text = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.30\n#\nhwtacacs scheme ops\n primary authentication 192.0.2.31\n"
    result = audit(text, "h3c", "tacacs.minimum_servers" => 2)
    expect(result.findings.first.status).to eq(:fail)
    expect(result.configuration.fact("tacacs.servers")).to eq([ "192.0.2.31" ])
    removed = audit(text + "#\nundo hwtacacs scheme OpS\n", "h3c", "tacacs.minimum_servers" => 2)
    expect(removed.configuration.resources.select { |resource| resource.kind == "tacacs.endpoint" }).to be_empty
  end

  it "does not resolve a differently cased Huawei template reference" do
    text = "sysname LAB\nhwtacacs-server template OPS\n hwtacacs-server authentication 192.0.2.30\n#\ndomain ADMIN admin\n" \
      "aaa\n authentication-scheme TAC\n  authentication-mode hwtacacs local\n domain ADMIN\n  authentication-scheme TAC\n  hwtacacs-server ops\n#\nuser-interface vty 0 4\n authentication-mode aaa\n"
    result = audit(text, "huawei", "tacacs.login" => true)
    expect(result.findings.first.status).to eq(:unknown)
    expect(result.configuration.fact("aaa.domain_bindings_complete")["authentication"]).to be(false)
  end

  it "retains separate Huawei templates differing only in case and binds only the exact target" do
    text = "sysname LAB\nhwtacacs-server template OPS\n hwtacacs-server authentication 192.0.2.30\n#\n" \
      "hwtacacs-server template ops\n hwtacacs-server authentication 192.0.2.31\n#\ndomain ADMIN admin\naaa\n authentication-scheme TAC\n  authentication-mode hwtacacs local\n domain ADMIN\n  authentication-scheme TAC\n  hwtacacs-server ops\n#\nuser-interface vty 0 4\n authentication-mode aaa\n"
    result = audit(text, "huawei", "tacacs.login" => true)
    expect(result.findings.first.status).to eq(:pass)
    endpoints = result.configuration.resources.select { |resource| resource.kind == "tacacs.endpoint" }
    expect(endpoints.find { |resource| resource.scope["group"] == "OPS" }.bindings).to eq([])
    expect(endpoints.find { |resource| resource.scope["group"] == "ops" }.bindings.size).to eq(1)
  end

  it "keeps Huawei named authorization schemes separate from case-insensitive domains" do
    text = File.read(File.expand_path("fixtures/baseline/huawei.cfg", __dir__))
    mismatch = text.sub("  authorization-scheme TAC", "  authorization-scheme tac")
    expect(audit(mismatch, "huawei", "tacacs.authorization" => true).findings.first.status).to eq(:unknown)
    separate = mismatch.sub(" domain OPS\n", " authorization-scheme tac\n  authorization-mode local\n domain OPS\n")
    expect(audit(separate, "huawei", "tacacs.authorization" => true).findings.first.status).to eq(:fail)
  end
end

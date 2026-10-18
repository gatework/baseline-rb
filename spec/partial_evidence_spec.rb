# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe Baseline::Evaluator, "partial configuration evidence" do
  def audit(checks, body:, complete: false, context: {}, platform: "h3c")
    policy = Baseline::Policy.new("version" => 1, "checks" => checks)
    Baseline::Audit.new(policy: policy).call(configuration: body, platform: platform, complete: complete, context: context)
  end

  def finding(report, id) = report.findings.find { |row| row.id == id }

  it "retains an observed forbidden service with both explicit partial input and a real pagination marker" do
    checks = { "services.disabled" => { "expected" => %w[http telnet] } }
    body = "sysname LAB\nip http enable\n"
    [ audit(checks, body: body), audit(checks, body: body + "--More--\n", complete: true) ].each do |report|
      row = finding(report, "services.disabled")
      expect(row.to_h).to include(status: :fail, reason: :unnecessary_service_enabled, details: { enabled: [ "http" ] })
      expect(row.actual.fetch("http")).to be(true)
      expect(report.status).to eq(:fail)
      expect(report).not_to be_complete
      expect(report).not_to be_compliant
      expect(row.diagnostics.map { |issue| issue[:code] }).to include(satisfy { |code| %i[input_not_confirmed_complete incomplete_configuration].include?(code) })
    end
  end

  it "retains unsupported allowed-set elements but never passes a partial allowed set" do
    checks = { "snmp.versions" => { "expected" => [ "v3" ] } }
    violated = audit(checks, body: "sysname LAB\nsnmp-agent sys-info version v1 v3\n")
    allowed = audit(checks, body: "sysname LAB\nsnmp-agent sys-info version v3\n")
    expect(violated.findings.first.to_h).to include(status: :fail, details: { unexpected: [ "v1" ] })
    expect(allowed.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
  end

  it "reports observed extra servers without inventing missing servers from partial evidence" do
    checks = { "ntp.servers" => { "expected" => %w[192.0.2.10 192.0.2.11] } }
    report = audit(checks, body: "sysname LAB\nntp-service unicast-server 203.0.113.10\n--More--\n", complete: true)
    expect(report.findings.first.to_h).to include(status: :fail, actual: [ "203.0.113.10" ],
      expected: %w[192.0.2.10 192.0.2.11], lines: [ 2 ], details: { unexpected: [ "203.0.113.10" ] })
  end

  it "requires complete input before missing servers or insufficient server counts become faults" do
    checks = { "ntp.servers" => { "expected" => %w[192.0.2.10 192.0.2.11] }, "ntp.minimum_servers" => { "expected" => 2 } }
    body = "sysname LAB\nntp-service unicast-server 192.0.2.10\n"
    partial = audit(checks, body: body)
    full = audit(checks, body: body, complete: true)
    expect(partial.findings.map(&:status)).to eq(%i[unknown unknown])
    expect(partial.findings.map(&:details)).to eq([ {}, {} ])
    expect(full.findings.map(&:status)).to eq(%i[fail fail])
    expect(full.findings.first.details).to eq(missing: [ "192.0.2.11" ], unexpected: [])
  end

  it "does not pass matching sets, sufficient counts, or explicitly disabled services from partial input" do
    checks = { "ntp.servers" => { "expected" => [ "192.0.2.10" ] }, "ntp.minimum_servers" => { "expected" => 1 },
      "services.disabled" => { "expected" => [ "http" ] } }
    body = "sysname LAB\nntp-service unicast-server 192.0.2.10\nundo ip http enable\n"
    expect(audit(checks, body: body).findings.map(&:status)).to eq(%i[unknown unknown unknown])
    expect(audit(checks, body: body, complete: true).findings.map(&:status)).to eq(%i[pass pass pass])
  end

  it "retains an approved-network violation only when the ACL-derived fact is known" do
    body = File.read(File.expand_path("fixtures/baseline/h3c.cfg", __dir__))
    checks = { "management.sources" => { "expected" => [ "198.51.100.128/25" ] } }
    partial = audit(checks, body: body + "--More--\n", complete: true)
    expect(partial.findings.first.to_h).to include(status: :fail, details: { outside_approved: [ "198.51.100.0/25" ] })
    ambiguous = audit(checks, body: body.sub("rule 10 permit source", "rule 10 unsupported source"))
    expect(ambiguous.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
    expect(ambiguous.findings.first.diagnostics).to include(hash_including(code: :acl_unresolved))
  end

  it "does not call incomplete ordered ACL exposure a conclusive violation" do
    body = <<~CLI
      hostname LAB
      ip access-list standard MGMT
       10 permit 198.51.100.0 0.0.0.255
       20 permit 192.0.2.0 0.0.0.255
      line vty 0 4
       transport input ssh
       login local
       access-class MGMT in
      snmp-server community SYNTHETIC RO MGMT
      end
    CLI
    checks = %w[management.sources snmp.sources].to_h { |name| [ name, { "expected" => [ "192.0.2.0/24" ] } ] }
    observed = audit(checks, body: body, platform: "cisco_ios")
    expect(observed.findings.map(&:status)).to eq(%i[unknown unknown])
    expect(observed.findings.map(&:details)).to eq([ {}, {} ])
    full = body.sub(" 10 permit", " 5 deny 198.51.100.0 0.0.0.255\n 10 permit")
    expect(audit(checks, body: full, platform: "cisco_ios", complete: true)).to be_compliant
  end

  it "keeps safe partial network sources unknown" do
    body = File.read(File.expand_path("fixtures/baseline/h3c.cfg", __dir__))
    report = audit({ "management.sources" => { "expected" => [ "198.51.100.0/24" ] } }, body: body)
    expect(report.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
  end

  it "retains known weak passwords and unsafe storage without serializing secret values" do
    checks = { "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } },
      "credentials.storage" => { "expected" => true, "applies_to" => { "facts" => { "credentials.present" => true } } } }
    report = audit(checks, body: "sysname LAB\nlocal-user observer class manage\n password simple Unsafe123\n--More--\n", complete: true)
    expect(report.findings.map(&:status)).to eq(%i[fail fail])
    expect(report.findings.first.reason).to eq(:weak_password)
    expect(report.to_h.to_json).not_to include("Unsafe123")
  end

  it "keeps strong visible passwords and protected storage unknown in partial input" do
    checks = { "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } }
    report = audit(checks, body: "sysname LAB\nlocal-user observer class manage\n password simple Synthetic-Strong-123!\n")
    expect(report.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
    protected = audit({ "credentials.storage" => { "expected" => true } },
      body: "sysname LAB\nlocal-user observer class manage\n password hash FIXTURE-HASH\n")
    expect(protected.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
  end

  it "retains known SNMP write grants under the default policy but cannot prove their absence" do
    definition = Baseline::Policy.default
    report = Baseline::Audit.new(policy: definition).call(platform: "h3c", complete: true,
      configuration: "sysname LAB\nsnmp-agent\nsnmp-agent community write cipher FIXTURE-COMMUNITY\n--More--\n")
    expect(finding(report, "snmp.write_enabled").to_h).to include(status: :fail, actual: true, expected: false)
    readonly = audit({ "snmp.write_enabled" => { "expected" => false } },
      body: "sysname LAB\nsnmp-agent community read cipher FIXTURE-COMMUNITY\n")
    expect(readonly.findings.first.to_h).to include(status: :unknown, reason: :input_incomplete)
  end

  it "does not generalize partial violations to scalar equality or all-user aggregate facts" do
    checks = { "ssh.enabled" => { "expected" => true }, "ntp.source" => { "expected" => "LoopBack0" },
      "snmp.auth_priv" => { "expected" => true } }
    report = audit(checks, body: "sysname LAB\nundo ssh server enable\nntp-service source LoopBack1\nsnmp-agent usm-user v3 observer READONLY\n")
    expect(report.findings.map(&:status)).to eq(%i[unknown unknown unknown])
    expect(report.findings.map(&:details)).to eq([ {}, {}, {} ])
  end

  it "excludes a known context mismatch before inspecting partial or unsupported evidence" do
    checks = { "services.disabled" => { "expected" => [ "http" ],
      "applies_to" => { "site" => "HQ", "vendor" => "cisco_ios", "facts" => { "snmp.enabled" => true } } } }
    [ "h3c", "unsupported" ].each do |platform|
      report = audit(checks, body: "sysname LAB\nip http enable\n--More--\n", complete: true, platform: platform)
      expect(report.findings.first.to_h).to include(status: :not_applicable, reason: :scope_mismatch)
      expect(report).not_to be_compliant
    end
  end

  it "does not apply a rule without required context even when a violation is visible" do
    checks = { "services.disabled" => { "expected" => [ "http" ], "applies_to" => { "site" => "HQ" } } }
    report = audit(checks, body: "sysname LAB\nip http enable\n")
    expect(report.findings.first.to_h).to include(status: :unknown, reason: :scope_unknown)
  end

  it "does not infer a fact-based scope from a partial absence or all-member aggregate" do
    { "snmp.write_enabled" => false, "ssh.vty_ssh_only" => true }.each do |fact, value|
      checks = { "services.disabled" => { "expected" => [ "http" ], "applies_to" => { "facts" => { fact => value } } } }
      report = audit(checks, body: "sysname LAB\nip http enable\nline vty 0 4\n protocol inbound ssh\n")
      expect(report.configuration.fact(fact)).to eq(value)
      expect(report.findings.first.to_h).to include(status: :unknown, reason: :scope_unknown)
    end
  end

  it "retains policy selection and input diagnostics when partial evidence proves a violation" do
    checks = { "ntp.servers" => { "expected" => { "by_site" => { "HQ" => [ "192.0.2.10" ] } } } }
    report = audit(checks, body: "sysname LAB\nntp-service unicast-server 203.0.113.10\n", context: { site: "HQ" })
    expect(report.findings.first.to_h).to include(status: :fail, policy_path: %w[by_site HQ], lines: [ 2 ])
    expect(report.findings.first.diagnostics).to include(hash_including(code: :input_not_confirmed_complete))
    missing_policy = audit(checks, body: "sysname LAB\nntp-service unicast-server 203.0.113.10\n", context: { site: "BRANCH" })
    expect(missing_policy.findings.first.to_h).to include(status: :unknown, reason: :policy_missing)
  end

  it "keeps scoped parser uncertainty local while retaining a separate violation" do
    checks = { "services.disabled" => { "expected" => [ "http" ] }, "snmp.write_enabled" => { "expected" => false } }
    report = audit(checks, platform: "cisco_ios",
      body: "hostname LAB\nip http server\nsnmp-server group OPS v3 priv unsupported-option VALUE\n--More--\n", complete: true)
    service = finding(report, "services.disabled")
    expect(service.status).to eq(:fail)
    expect(service.diagnostics.map { |issue| issue[:code] }).not_to include(:snmp_permission_unresolved)
    permission = finding(report, "snmp.write_enabled")
    expect(permission.status).to eq(:unknown)
    expect(permission.diagnostics).to include(hash_including(code: :snmp_permission_unresolved))
  end

  it "excludes an unterminated password token from partial facts without losing earlier complete violations" do
    checks = { "services.disabled" => { "expected" => [ "http" ] },
      "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } }
    body = "sysname LAB\nip http enable\nlocal-user observer class manage\n password simple admin"
    report = audit(checks, body: body)
    expect(finding(report, "services.disabled").status).to eq(:fail)
    password = finding(report, "credentials.strength")
    expect(password.status).to eq(:unknown)
    expect(password.diagnostics).to include(code: :incomplete_final_line, line: 4)
    expect(report.configuration.sha256).to eq(Digest::SHA256.hexdigest(body))
    expect(report.configuration.fact("credentials.records")).to be_nil
  end

  it "does not treat a truncated address following pagination as an observed unexpected server" do
    checks = { "services.disabled" => { "expected" => [ "http" ] }, "ntp.servers" => { "expected" => [ "203.0.113.10" ] } }
    body = "sysname LAB\nip http enable\n--More--\nntp-service unicast-server 203.0.113.1"
    report = audit(checks, body: body, complete: true)
    expect(finding(report, "services.disabled").status).to eq(:fail)
    expect(finding(report, "ntp.servers").status).to eq(:unknown)
    expect(finding(report, "ntp.servers").diagnostics).to include(hash_including(code: :incomplete_configuration),
      { code: :incomplete_final_line, line: 4 })
  end

  it "preserves complete inputs without final newlines and partial inputs with any supported line ending" do
    checks = { "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } }
    body = "sysname LAB\nlocal-user observer class manage\n password simple admin"
    expect(audit(checks, body: body, complete: true).findings.first.status).to eq(:fail)
    [ "\n", "\r\n", "\r" ].each do |ending|
      expect(audit(checks, body: body + ending).findings.first.status).to eq(:fail)
    end
  end

  it "keeps the original cursor, line numbers and capture source while excluding the incomplete final block" do
    body = "sysname LAB\nntp-service unicast-server 192.0.2.10\nlocal-user observer class manage\n password simple admin"
    parser = Baseline::H3c::Parser.new
    result = parser.parse(body, complete: false)
    expect(result.status).to eq(:partial)
    expect(parser.cursor.content).to eq(body)
    expect(parser.cursor.checksum).to eq(Digest::SHA256.hexdigest(body))
    expect(parser.cursor.state(3)).to eq(:unsupported)
    expect(parser.cursor.captures_for([ "facts", "ntp.servers" ]).size).to eq(1)
    expect(result.records.first.fetch("sources").fetch("ntp.servers")).to eq([ 2 ])
    expect(parser.blocks.last.children).to be_empty
    expect(parser.document.roots.last.children.last.line).to eq(4)
  end

  it "retains the incomplete-line diagnostic when no complete statement remains" do
    result = Baseline::H3c::Parser.parse("sysname LA", complete: false)
    expect(result.status).to eq(:failed)
    expect(result.issues).to include({ code: :incomplete_final_line, line: 1 }, { code: :empty_configuration })
    expect(result.records).to be_empty
  end

  it "does not turn an inline pagination marker into a forbidden protocol version" do
    checks = { "snmp.versions" => { "expected" => [ "v3" ] } }
    report = audit(checks, body: "sysname LAB\nsnmp-agent sys-info version v3 --More--\n", complete: true)
    expect(report.findings.first.status).to eq(:unknown)
    expect(report.configuration.fact("snmp.versions")).to be_nil
    expect(report.findings.first.diagnostics).to include(code: :incomplete_configuration, line: 2)
  end

  it "discards a password line interrupted by pagination while retaining other complete facts" do
    checks = { "services.disabled" => { "expected" => [ "http" ] },
      "credentials.strength" => { "expected" => { "min_length" => 12, "min_classes" => 3 } } }
    body = "sysname LAB\nip http enable\nlocal-user observer class manage\n password simple admin--More--\n"
    report = audit(checks, body: body, complete: true)
    expect(finding(report, "services.disabled").status).to eq(:fail)
    expect(finding(report, "credentials.strength").status).to eq(:unknown)
  end

  it "does not leak excluded final-line state into the next parse session" do
    parser = Baseline::H3c::Parser.new
    prefix = "sysname LAB\nntp-service unicast-server 192.0.2.10"
    first = parser.parse(prefix, complete: false)
    expect(first.records.first.fetch("facts")).not_to have_key("ntp.servers")
    second = parser.parse(prefix + "\n", complete: true)
    expect(second.records.first.fetch("facts").fetch("ntp.servers")).to eq([ "192.0.2.10" ])
    expect(second.issues).not_to include(hash_including(code: :incomplete_final_line))
  end
  it "keeps an ACL unknown when paging erased a preceding deny rule" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "management.sources" => { "expected" => [ "192.0.2.0/24" ] } })
    samples = {
      "h3c" => "sysname LAB\nacl number 2000\n rule 5 deny source 198.51.100.0 0.0.0.255\n rule 10 permit source 198.51.100.0 0.0.0.255\n rule 20 permit source 192.0.2.0 0.0.0.255\n#\nline vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n acl 2000 inbound\n#\nreturn\n",
      "cisco_ios" => "hostname LAB\nip access-list standard MGMT\n 5 deny 198.51.100.0 0.0.0.255\n 10 permit 198.51.100.0 0.0.0.255\n 20 permit 192.0.2.0 0.0.0.255\n!\nline vty 0 4\n transport input ssh\n login local\n access-class MGMT in\n!\nend\n"
    }
    samples.each do |platform, source|
      runner = Baseline::Audit.new(policy: policy)
      expect(runner.call(configuration: source, platform: platform, complete: true).findings.first.status).to eq(:pass)
      damaged = source.sub(/deny(?: source)? 198\.51\.100\.0 0\.0\.0\.255/, "deny source 198.51.100.--More--")
      expect(runner.call(configuration: damaged, platform: platform, complete: true).findings.first.status).to eq(:unknown)
    end
    numbered = "hostname LAB\naccess-list 10 deny 198.51.100.0 0.0.0.255\naccess-list 10 permit 198.51.100.0 0.0.0.255\naccess-list 10 permit 192.0.2.0 0.0.0.255\nline vty 0 4\n transport input ssh\n login local\n access-class 10 in\nend\n"
    runner = Baseline::Audit.new(policy: policy)
    expect(runner.call(configuration: numbered, platform: "cisco_ios", complete: true).findings.first.status).to eq(:pass)
    damaged = numbered.sub("deny 198.51.100.0 0.0.0.255", "deny 198.51.100.--More--")
    expect(runner.call(configuration: damaged, platform: "cisco_ios", complete: true).findings.first.status).to eq(:unknown)
    [ "access-list 10--More--", "access-list 1--More--", "access-list --More--" ].each do |header|
      damaged = numbered.sub("access-list 10 deny 198.51.100.0 0.0.0.255", header)
      expect(runner.call(configuration: damaged, platform: "cisco_ios", complete: true).findings.first.status).to eq(:unknown)
    end
  end
end

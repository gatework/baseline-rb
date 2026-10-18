# frozen_string_literal: true

require_relative "spec_helper"
require "baseline"

RSpec.describe "Baseline SNMP access permissions" do
  it "removes cancelled IOS communities and their credential evidence" do
    source = "hostname LAB\nsnmp-server community SYNTHETIC RW\nno snmp-server community SYNTHETIC\n"
    definition = Baseline::Policy.new("version" => 1, "checks" => { "snmp.write_enabled" => { "expected" => false } })
    report = Baseline::Audit.new(policy: definition).call(configuration: source, platform: "cisco_ios", complete: true)

    expect(report.findings.first.status).to eq(:pass)
    expect(report.configuration.fact("snmp.communities")).to eq([])
    expect(report.configuration.fact("credentials.records")).to eq([])
    restored = Baseline::Audit.new(policy: definition).call(configuration: source + "snmp-server community SYNTHETIC RW\n",
      platform: "cisco_ios", complete: true)
    expect(restored.findings.first.status).to eq(:fail)
    expect(restored.configuration.fact("snmp.communities").first[:line]).to eq(4)
    expect(restored.configuration.fact("credentials.records").map { |row| row[:line] }).to eq([ 4 ])
  end

  it "keeps independently configured IOS communities when another is removed" do
    report = audit("cisco_ios", "snmp-server community ONE RW", "snmp-server community TWO RW", "no snmp-server community ONE")
    expect(permission(report).status).to eq(:fail)
    expect(report.configuration.fact("snmp.communities").size).to eq(1)
    expect(report.configuration.fact("credentials.records").map { |row| row[:line] }).to eq([ 4 ])
  end

  it "does not certify an old IOS community ACL after contradictory access declarations" do
    source = "hostname LAB\nip access-list standard SNMP\n permit 192.0.2.0 0.0.0.255\n!\n" \
      "snmp-server community SYNTHETIC RO SNMP\n"
    definition = Baseline::Policy.new("version" => 1, "checks" => { "snmp.sources" => { "expected" => [ "192.0.2.0/24" ] } })
    [ "snmp-server community SYNTHETIC RO\n", "snmp-server community SYNTHETIC RO OTHER\n" ].each do |last|
      report = Baseline::Audit.new(policy: definition).call(configuration: source + last, platform: "cisco_ios", complete: true)
      expect(report.findings.first.status).to eq(:unknown)
      expect(report.configuration.fact("snmp.communities").first).not_to have_key(:acl)
    end
    repeated = Baseline::Audit.new(policy: definition).call(configuration: source + "snmp-server community SYNTHETIC RO SNMP\n",
      platform: "cisco_ios", complete: true)
    expect(repeated.findings.first.status).to eq(:pass)
  end

  let(:policy) do
    Baseline::Policy.new("version" => 1, "checks" => {
      "snmp.write_enabled" => { "expected" => false }, "ssh.enabled" => { "expected" => true }
    })
  end

  def audit(platform, *commands, definition: policy)
    prefix = case platform
    when "cisco_ios" then "hostname LAB\nip ssh version 2\n"
    when "cisco_nxos" then "hostname LAB\nfeature ssh\n"
    when "huawei" then "sysname LAB\nstelnet server enable\n"
    else "sysname LAB\nssh server enable\n"
    end
    Baseline::Audit.new(policy: definition).call(configuration: prefix + commands.join("\n") + "\n", platform: platform, complete: true)
  end

  def user(platform, group: "OPS")
    platform == "cisco_ios" ? "snmp-server user observer #{group} v3 auth sha FIXTURE-AUTH priv aes 128 FIXTURE-PRIV" :
      "snmp-agent usm-user v3 observer #{group} authentication-mode sha cipher FIXTURE-AUTH privacy-mode aes128 cipher FIXTURE-PRIV"
  end

  def group(platform, options = "")
    platform == "cisco_ios" ? "snmp-server group OPS v3 priv #{options}".strip : "snmp-agent group v3 OPS privacy #{options}".strip
  end

  def permission(report) = report.findings.find { |finding| finding.id == "snmp.write_enabled" }

  %w[cisco_ios h3c huawei].each do |platform|
    context platform do
      let(:write_option) { platform == "cisco_ios" ? "write" : "write-view" }
      let(:read_option) { platform == "cisco_ios" ? "read" : "read-view" }

      it "reports an explicit SNMPv3 write grant even without a write community" do
        report = audit(platform, group(platform, "#{write_option} WRITEVIEW"), user(platform))
        expect(permission(report).status).to eq(:fail)
        expect(report.configuration.fact("snmp.write_enabled")).to be(true)
        expect(permission(report).lines).to include(3)
      end

      it "applies the default read-only rule to pure SNMPv3 configurations" do
        report = audit(platform, group(platform, "#{write_option} WRITEVIEW"), user(platform), definition: Baseline::Policy.default)
        expect(permission(report).status).to eq(:fail)
      end

      it "uses documented no-write-view semantics for a completely parsed group" do
        report = audit(platform, group(platform, "#{read_option} READVIEW"), user(platform))
        expect(permission(report).status).to eq(:pass)
        expect(report.configuration.fact("snmp.write_enabled")).to be(false)
      end

      it "does not require visible users before reporting configured group write access" do
        report = audit(platform, group(platform, "#{write_option} WRITEVIEW"))
        expect(permission(report).status).to eq(:fail)
      end

      it "keeps unresolved group permissions local while independent SSH evidence remains usable" do
        [ [ user(platform) ], [ group(platform, "unsupported-option VALUE"), user(platform) ],
          [ group(platform, write_option), user(platform) ] ].each do |commands|
          report = audit(platform, *commands)
          expect(permission(report).status).to eq(:unknown)
          expect(permission(report).diagnostics).to include(hash_including(code: :snmp_permission_unresolved))
          expect(report.findings.find { |finding| finding.id == "ssh.enabled" }.status).to eq(:pass)
        end
      end

      it "preserves write access across multiple security-level definitions of the same group" do
        readonly = group(platform, "#{read_option} READVIEW").sub(/\b(?:priv|privacy)\b/, platform == "cisco_ios" ? "auth" : "authentication")
        report = audit(platform, group(platform, "#{write_option} WRITEVIEW"), readonly, user(platform))
        expect(permission(report).status).to eq(:fail)
      end

      it "does not confuse a view's name with a write-permission option" do
        report = audit(platform, group(platform, "#{read_option} #{write_option}"), user(platform))
        expect(permission(report).status).to eq(:pass)
      end

      it "preserves a confirmed write grant alongside unsupported legacy user syntax" do
        legacy = platform == "cisco_ios" ? "snmp-server user legacy LEGACY v2c" : "snmp-agent usm-user v2c legacy"
        report = audit(platform, group(platform, "#{write_option} WRITEVIEW"), legacy, definition: Baseline::Policy.default)
        expect(permission(report).status).to eq(:fail)
        expect(report.configuration.fact_known?("snmp.v3_auth_priv")).to be(false)
        expect(report.configuration.fact_known?("snmp.acl.bound")).to be(false)
        expect(report.findings.find { |finding| finding.id == "ssh.enabled" }.status).to eq(:pass)
      end
    end
  end

  context "cisco_nxos" do
    def nxos_user(role)
      "snmp-server user observer #{role} auth sha FIXTURE-AUTH priv aes-128 FIXTURE-PRIV"
    end

    it "maps documented administrator and operator roles to write and read-only grants" do
      { "network-admin" => :fail, "vdc-admin" => :fail, "network-operator" => :pass, "vdc-operator" => :pass }.each do |role, status|
        expect(permission(audit("cisco_nxos", nxos_user(role))).status).to eq(status)
      end
    end

    it "does not assume that a custom role is read-only" do
      report = audit("cisco_nxos", nxos_user("custom-role"))
      expect(permission(report).status).to eq(:unknown)
      expect(permission(report).diagnostics).to include(hash_including(code: :snmp_permission_unresolved))
      expect(report.findings.find { |finding| finding.id == "ssh.enabled" }.status).to eq(:pass)
    end

    it "unions multiple user roles without losing an earlier write grant or authentication settings" do
      report = audit("cisco_nxos", nxos_user("network-admin"), "snmp-server user observer network-operator")
      expect(permission(report).status).to eq(:fail)
      expect(report.configuration.fact("snmp.v3_auth_priv")).to be(true)
      expect(report.configuration.fact("snmp.users").first.fetch(:roles)).to eq(%w[network-admin network-operator])
    end

    it "keeps unknown roles unknown unless another role explicitly grants write access" do
      operator = audit("cisco_nxos", nxos_user("custom-role"), "snmp-server user observer network-operator")
      administrator = audit("cisco_nxos", nxos_user("custom-role"), "snmp-server user observer network-admin")
      expect(permission(operator).status).to eq(:unknown)
      expect(permission(administrator).status).to eq(:fail)
    end

    it "does not let unknown authentication hide an explicit administrator grant" do
      report = audit("cisco_nxos", "snmp-server user observer network-admin")
      expect(permission(report).status).to eq(:fail)
      expect(report.configuration.fact_known?("snmp.v3_auth_priv")).to be(false)
    end

    it "applies the default read-only rule to a pure SNMPv3 administrator" do
      report = audit("cisco_nxos", nxos_user("network-admin"), definition: Baseline::Policy.default)
      expect(permission(report).status).to eq(:fail)
    end

    it "keeps unrepresented CLI accounts unknown without inventing SNMP users" do
      report = audit("cisco_nxos", "username cli-admin password 5 FIXTURE-HASH role network-admin", definition: Baseline::Policy.default)
      expect(report.configuration.fact("snmp.enabled")).to be(true)
      expect(permission(report).status).to eq(:unknown)
      expect(permission(report).diagnostics).to include(hash_including(code: :snmp_user_sync_unconfirmed, lines: [ 3 ]))
      expect(report.configuration.fact("snmp.users")).to eq([])
      expect(report.findings.find { |finding| finding.id == "ssh.enabled" }.status).to eq(:pass)
      expect(report.to_h.to_json).not_to include("FIXTURE-HASH")
    end

    it "requires each CLI role to be represented in explicit SNMP role evidence" do
      uncovered = audit("cisco_nxos", nxos_user("network-operator"), "username observer role network-admin")
      covered = audit("cisco_nxos", nxos_user("network-operator"), "username observer role network-operator")
      expect(permission(uncovered).status).to eq(:unknown)
      expect(permission(covered).status).to eq(:pass)
    end

    it "does not let incomplete CLI synchronization coverage hide a known write grant" do
      report = audit("cisco_nxos", nxos_user("network-admin"), "username cli-operator role network-operator")
      expect(permission(report).status).to eq(:fail)
    end

    it "honors explicit disabling and re-enabling of CLI/SNMP synchronization" do
      commands = [ nxos_user("network-operator"), "username cli-admin role network-admin", "snmp-server disable snmp-aaa sync" ]
      expect(permission(audit("cisco_nxos", *commands)).status).to eq(:pass)
      expect(permission(audit("cisco_nxos", *commands, "no snmp-server disable snmp-aaa sync")).status).to eq(:unknown)
    end

    it "excludes explicitly disabled SNMP without creating synchronization uncertainty" do
      commands = [ "username cli-admin role network-admin", "no snmp-server protocol enable" ]
      report = audit("cisco_nxos", *commands, definition: Baseline::Policy.default)
      expect(report.configuration.fact("snmp.enabled")).to be(false)
      expect(permission(report).status).to eq(:not_applicable)
      expect(report.configuration.fact_known?("snmp.write_enabled")).to be(true)
      enabled = audit("cisco_nxos", *commands, "snmp-server protocol enable", definition: Baseline::Policy.default)
      expect(permission(enabled).status).to eq(:unknown)
    end
  end

  it "retains a known write community violation alongside unresolved SNMPv3 permissions" do
    report = audit("cisco_ios", "snmp-server community FIXTURE-COMMUNITY RW", user("cisco_ios"))
    expect(permission(report).status).to eq(:fail)
    expect(report.to_h.to_json).not_to include("FIXTURE-COMMUNITY", "FIXTURE-AUTH", "FIXTURE-PRIV")
  end

  it "does not let legacy IOS group uncertainty erase a known community write grant" do
    report = audit("cisco_ios", "snmp-server community FIXTURE-COMMUNITY RW", "snmp-server group LEGACY v2c read VIEW")
    expect(permission(report).status).to eq(:fail)
    expect(report.configuration.fact_known?("snmp.acl.bound")).to be(false)
    unresolved = audit("cisco_ios", "snmp-server group LEGACY v2c read VIEW")
    expect(permission(unresolved).status).to eq(:unknown)
    expect(permission(unresolved).diagnostics).to include(hash_including(code: :unsupported_snmp_group))
  end

  it "does not let malformed access declarations erase a confirmed write view" do
    report = audit("cisco_ios", group("cisco_ios", "write WRITEVIEW"), "snmp-server community", definition: Baseline::Policy.default)
    expect(permission(report).status).to eq(:fail)
    expect(report.configuration.fact_known?("snmp.community_present")).to be(false)
  end

  it "keeps the no-SNMP case explicitly read-only without manufacturing a v3 user" do
    report = audit("h3c")
    expect(permission(report).status).to eq(:pass)
    expect(report.configuration.fact("snmp.users")).to eq([])
  end

  {
    "cisco_ios" => [ "snmp-server group", "snmp-server group OPS", "snmp-server group OPS v3x", "snmp-server group OPS v3-extra" ],
    "cisco_nxos" => [ "snmp-server group", "snmp-server group OPS", "snmp-server group OPS v3x", "snmp-server group OPS v3-extra" ],
    "h3c" => [ "snmp-agent group", "snmp-agent group v3", "snmp-agent group v2c OPS" ],
    "huawei" => [ "snmp-agent group", "snmp-agent group v3", "snmp-agent group v2c OPS" ]
  }.each do |platform, commands|
    it "keeps incomplete or unsupported #{platform} group declarations unknown" do
      commands.each do |command|
        report = audit(platform, command)
        expect(permission(report).status).to eq(:unknown), command
        expect(permission(report).diagnostics).to include(hash_including(code: :snmp_permission_unresolved))
        expect(report.findings.find { |finding| finding.id == "ssh.enabled" }.status).to eq(:pass)
      end
    end

    it "retains a confirmed #{platform} write grant alongside an incomplete group" do
      write = platform.start_with?("cisco") ? "snmp-server community FIXTURE-COMMUNITY RW" : "snmp-agent community write cipher FIXTURE-COMMUNITY"
      report = audit(platform, write, commands.first)
      expect(permission(report).status).to eq(:fail)
      expect(report.configuration.fact_known?("snmp.community_present")).to be(false)
    end
  end
end

# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline effective declarations" do
  it "does not prove management restrictions from conflicting explicit ACL sequence identities" do
    samples = {
      "cisco_ios" => "hostname LAB\nip access-list standard MGMT\n 10 deny any\n 10 permit any\n!\nline vty 0 4\n transport input ssh\n login local\n access-class MGMT in\n",
      "h3c" => "sysname LAB\nacl number 2000\n rule 10 deny source any\n rule 10 permit source any\n#\nline vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n acl 2000 inbound\n",
      "huawei" => "sysname LAB\nacl number 2000\n rule 10 deny source any\n rule 10 permit source any\n#\nuser-interface vty 0 4\n protocol inbound ssh\n authentication-mode aaa\n acl 2000 inbound\n"
    }
    samples.each do |platform, source|
      report = audit(platform, source, "management.sources" => [ "192.0.2.0/24" ])
      expect(report.findings.first.status).to eq(:unknown)
      ordered = source.sub("10 permit", "20 permit")
      expect(audit(platform, ordered, "management.sources" => [ "192.0.2.0/24" ]).findings.first.status).to eq(:pass)
    end
  end

  def audit(platform, body, checks)
    policy = Baseline::Policy.new("version" => 1, "checks" => checks.transform_values { |expected| { "expected" => expected } })
    Baseline::Audit.new(policy: policy).call(configuration: body, platform: platform, complete: true)
  end

  it "uses the final Cisco VTY login declaration instead of an earlier local login" do
    [ "login", "no login" ].each do |last|
      report = audit("cisco_ios", "hostname LAB\nline vty 0 4\n login local\n #{last}\n", "ssh.vty_aaa" => true)
      expect(report.findings.first.status).to eq(:fail)
    end
    report = audit("cisco_ios", "hostname LAB\nline vty 0 4\n login local\n login authentication\n", "ssh.vty_aaa" => true)
    expect(report.findings.first.status).to eq(:unknown)
  end

  {
    "cisco_ios" => [ "hostname LAB", "ip access-list standard MGMT\n permit 192.0.2.0 0.0.0.255", "line vty 0 4", "transport input ssh", "login local", "access-class MGMT in", "no access-class MGMT in", "access-class" ],
    "h3c" => [ "sysname LAB", "acl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.255", "line vty 0 4", "protocol inbound ssh", "authentication-mode scheme", "acl 2000 inbound", "undo acl 2000 inbound", "acl" ],
    "huawei" => [ "sysname LAB", "acl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.255", "user-interface vty 0 4", "protocol inbound ssh", "authentication-mode aaa", "acl 2000 inbound", "undo acl 2000 inbound", "acl" ]
  }.each do |platform, (hostname, acl, vty, protocol, authentication, binding, reset, malformed)|
    it "does not retain the old #{platform} ACL after cancellation or a malformed replacement" do
      body = "#{hostname}\n#{acl}\n#\n#{vty}\n #{protocol}\n #{authentication}\n #{binding}\n"
      expect(audit(platform, body, "management.sources" => [ "192.0.2.0/24" ]).findings.first.status).to eq(:pass)
      [ reset, malformed ].each do |last|
        report = audit(platform, body + " #{last}\n", "management.sources" => [ "192.0.2.0/24" ])
        expect(report.findings.first.status).to eq(:unknown)
      end
      report = audit(platform, body + " #{reset}\n", "management.acl_bound" => true)
      expect(report.findings.first.status).to eq(:fail)
      outbound = binding.sub(/\bin(?:bound)?\z/, platform == "cisco_ios" ? "out" : "outbound")
      [ body + " #{outbound}\n", body.sub(" #{binding}\n", " #{outbound}\n #{binding}\n") ].each do |source|
        expect(audit(platform, source, "management.sources" => [ "192.0.2.0/24" ]).findings.first.status).to eq(:pass)
      end
    end
  end

  it "keeps an incomplete Cisco SSH version declaration from reusing the old value" do
    [ "ip ssh version", "ip ssh version 3", "no ip ssh version" ].each do |last|
      report = audit("cisco_ios", "hostname LAB\nip ssh version 2\n#{last}\n", "ssh.versions" => [ "2" ])
      expect(report.findings.first.status).to eq(:unknown)
    end
  end

  it "does not confuse a Cisco IPv4 ACL named ipv6 with the independent IPv6 command family" do
    body = "hostname LAB\nip access-list standard MGMT\n permit 192.0.2.0 0.0.0.255\n!\nip access-list standard ipv6\n permit any\n!\nline vty 0 4\n transport input ssh\n login local\n access-class MGMT in\n"
    report = audit("cisco_ios", body + " ipv6 access-class V6 in\n", "management.sources" => [ "192.0.2.0/24" ])
    expect(report.findings.first.status).to eq(:pass)
    report = audit("cisco_ios", body + " access-class ipv6 in\n", "management.sources" => [ "192.0.2.0/24" ])
    expect(report.findings.first.status).to eq(:fail)
  end

  {
    "cisco_ios" => [ "hostname LAB", "ntp source", "no" ],
    "cisco_nxos" => [ "hostname LAB", "ntp source-interface", "no" ],
    "h3c" => [ "sysname LAB", "ntp-service source", "undo" ],
    "huawei" => [ "sysname LAB", "ntp-service source-interface", "undo" ]
  }.each do |platform, (hostname, command, negate)|
    it "does not retain a cancelled or incomplete #{platform} NTP source" do
      [ "#{negate} #{command}", command ].each do |last|
        report = audit(platform, "#{hostname}\n#{command} Loopback0\n#{last}\n", "ntp.source" => "Loopback0")
        expect(report.findings.first.status).to eq(:unknown)
      end
      report = audit(platform, "#{hostname}\n#{command} Loopback0\n#{command} Loopback1\n", "ntp.source" => "Loopback1")
      expect(report.findings.first.to_h).to include(status: :pass, lines: [ 3 ])
    end
  end

  %w[h3c huawei].each do |platform|
    it "does not reuse the previous #{platform} VTY authentication mode after malformed input" do
      mode = platform == "h3c" ? "scheme" : "aaa"
      report = audit(platform, "sysname LAB\nline vty 0 4\n authentication-mode #{mode}\n authentication-mode\n", "ssh.vty_aaa" => true)
      expect(report.findings.first.status).to eq(:unknown)
    end

    it "does not reuse a cancelled or incomplete #{platform} global SSH ACL" do
      body = "sysname LAB\nacl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n#\nssh server acl 2000\nline vty 0 4\n protocol inbound ssh\n authentication-mode scheme\n#\n"
      expect(audit(platform, body, "management.sources" => [ "192.0.2.0/24" ]).findings.first.status).to eq(:pass)
      [ "undo ssh server acl", "ssh server acl" ].each do |last|
        report = audit(platform, body + last + "\n", "management.sources" => [ "192.0.2.0/24" ])
        expect(report.findings.first.status).to eq(:unknown)
      end
      [ "ssh server acl name", "ssh server acl ipv4", "ssh server acl ipv4 name" ].each do |last|
        report = audit(platform, body + last + "\n", "management.acl_bound" => true)
        expect(report.findings.first.status).to eq(:unknown)
      end
      report = audit(platform, "sysname LAB\nline vty 0 4\n acl name\n", "management.acl_bound" => true)
      expect(report.findings.first.status).to eq(:unknown)
      expect(audit(platform, body + "ssh server acl ipv6 2001\n", "management.sources" => [ "192.0.2.0/24" ]).findings.first.status).to eq(:pass)
    end
  end

  {
    "cisco_ios" => [ "hostname LAB", "line vty 0 4", "transport input", "no" ],
    "cisco_nxos" => [ "hostname LAB", "line vty 0 4", "transport input", "no" ],
    "h3c" => [ "sysname LAB", "line vty 0 4", "protocol inbound", "undo" ],
    "huawei" => [ "sysname LAB", "user-interface vty 0 4", "protocol inbound", "undo" ]
  }.each do |platform, (hostname, section, command, negate)|
    it "does not reuse #{platform} VTY protocols after an incomplete or reset declaration" do
      body = "#{hostname}\n#{section}\n #{command} ssh\n"
      [ command, "#{negate} #{command}", "#{command} unsupported" ].each do |last|
        report = audit(platform, body + " #{last}\n", "ssh.vty_ssh_only" => true)
        expect(report.findings.first.status).to eq(:unknown)
      end
      report = audit(platform, body + " #{command} telnet\n", "ssh.vty_ssh_only" => true)
      expect(report.findings.first.status).to eq(:fail)
      unless platform.start_with?("cisco")
        report = audit(platform, body + " #{command} stelnet\n", "ssh.vty_ssh_only" => true)
        expect(report.findings.first.status).to eq(:pass)
      end
    end
  end

  {
    "cisco_ios" => [ "hostname LAB", "logging source-interface", "no" ],
    "cisco_nxos" => [ "hostname LAB", "logging source-interface", "no" ],
    "h3c" => [ "sysname LAB", "info-center loghost source", "undo" ],
    "huawei" => [ "sysname LAB", "info-center loghost source", "undo" ]
  }.each do |platform, (hostname, command, negate)|
    it "does not retain a cancelled or incomplete #{platform} Syslog source" do
      [ "#{negate} #{command}", command ].each do |last|
        report = audit(platform, "#{hostname}\n#{command} Loopback0\n#{last}\n", "syslog.source" => "Loopback0")
        expect(report.findings.first.status).to eq(:unknown)
      end
      report = audit(platform, "#{hostname}\n#{command} Loopback0\n#{command} Loopback1\n", "syslog.source" => "Loopback1")
      expect(report.findings.first.to_h).to include(status: :pass, lines: [ 3 ])
    end
  end

  it "requires every final Cisco authorization and accounting action to select TACACS" do
    body = "hostname LAB\ntacacs-server host 192.0.2.10\n"
    [ "authorization", "accounting" ].each do |kind|
      mode = kind == "accounting" ? "start-stop " : ""
      selected = "aaa #{kind} exec default #{mode}group tacacs+\n"
      local = "aaa #{kind} exec default #{kind == 'accounting' ? 'none' : 'local'}\n"
      checks = { "tacacs.#{kind}" => true }
      expect(audit("cisco_ios", body + selected + local, checks).findings.first.status).to eq(:fail)
      expect(audit("cisco_ios", body + local + selected, checks).findings.first.status).to eq(:pass)
      other = "aaa #{kind} commands 15 default #{kind == 'accounting' ? 'none' : 'local'}\n"
      expect(audit("cisco_ios", body + selected + other, checks).findings.first.status).to eq(:fail)
      expect(audit("cisco_ios", body + selected + "aaa #{kind} exec default\n", checks).findings.first.status).to eq(:unknown)
      expect(audit("cisco_ios", body + selected + "no aaa #{kind} exec default\n", checks).findings.first.status).to eq(:unknown)
    end
  end

  it "does not reuse Cisco TACACS login lists after cancellation or malformed replacement" do
    body = "hostname LAB\naaa new-model\ntacacs-server host 192.0.2.10\n"
    %w[cisco_ios cisco_nxos].each do |platform|
      %w[default OPERATORS].each do |name|
        selected = "aaa authentication login #{name} group tacacs+\n"
        vty = "line vty 0 4\n transport input ssh\n login authentication #{name}\n"
        [ "no aaa authentication login #{name}", "aaa authentication login #{name}" ].each do |replacement|
          report = audit(platform, body + selected + replacement + "\n" + vty, "tacacs.login" => true)
          expect(report.findings.first.status).to eq(:unknown)
          expect(report.findings.first.lines).not_to include(4)
          restored = audit(platform, body + replacement + "\n" + selected + vty, "tacacs.login" => true)
          expect(restored.findings.first.status).to eq(:pass)
        end
        local = audit(platform, body + selected + "aaa authentication login #{name} local\n" + vty, "tacacs.login" => true)
        expect(local.findings.first.status).to eq(:fail)
        independent = audit(platform, body + selected + "no aaa authentication login UNUSED\n" + vty, "tacacs.login" => true)
        expect(independent.findings.first.status).to eq(:pass)
      end
    end
  end

  it "uses the final selected Comware domain method for each AAA function" do
    body = "sysname LAB\nhwtacacs scheme OPS\n primary authentication 192.0.2.10\n primary authorization 192.0.2.10\n primary accounting 192.0.2.10\n#\ndomain default enable ADMIN\nline vty 0 4\n authentication-mode scheme\n#\ndomain ADMIN\n"
    %w[authentication authorization accounting].each do |kind|
      fact = kind == "authentication" ? "login" : kind
      checks = { "tacacs.#{fact}" => true }
      selected = " #{kind} login hwtacacs-scheme OPS local\n"
      local = " #{kind} login #{kind == 'accounting' ? 'none' : 'local'}\n"
      expect(audit("h3c", body + selected + local, checks).findings.first.status).to eq(:fail)
      expect(audit("h3c", body + local + selected, checks).findings.first.status).to eq(:pass)
      expect(audit("h3c", body + selected + " #{kind} login\n", checks).findings.first.status).to eq(:unknown)
      expect(audit("h3c", body + selected + " undo #{kind} login\n", checks).findings.first.status).to eq(:unknown)
      expect(audit("h3c", body + selected.sub("login", "default") + local, checks).findings.first.status).to eq(:fail)
    end
  end
end

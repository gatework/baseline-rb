# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline server address evidence" do
  commands = {
    "h3c" => { hostname: "sysname LAB", ntp: "ntp-service unicast-server", syslog: "info-center loghost", tacacs: "hwtacacs scheme AAA\n primary authentication" },
    "huawei" => { hostname: "sysname LAB", ntp: "ntp-service unicast-server", syslog: "info-center loghost", tacacs: "hwtacacs-server template AAA\n hwtacacs-server authentication" },
    "cisco_ios" => { hostname: "hostname LAB", ntp: "ntp server", syslog: "logging host", tacacs: "tacacs-server host" },
    "cisco_nxos" => { hostname: "hostname LAB", ntp: "ntp server", syslog: "logging server", tacacs: "tacacs server AAA\n address ipv4" }
  }

  commands.each do |platform, syntax|
    %i[ntp syslog tacacs].each do |service|
      it "keeps malformed #{service} endpoints unknown on #{platform}" do
        policy = Baseline::Policy.new("version" => 1, "checks" => { "#{service}.minimum_servers" => { "expected" => 1 } })
        audit = Baseline::Audit.new(policy: policy)
        [ "999.999.999.999", "192.0.2.0/24", "-invalid.example", "" ].each do |address|
          report = audit.call(configuration: "#{syntax[:hostname]}\n#{syntax[service]} #{address}\n", platform: platform, complete: true)
          finding = report.findings.first
          expect(finding.status).to eq(:unknown), address.inspect
          expect(finding.diagnostics).to include(hash_including(code: :invalid_server_address))
          expect(report.configuration.fact("#{service}.servers")).not_to include(address)
        end
      end
    end

    %i[ntp syslog].each do |service|
      it "removes cancelled #{service} endpoints on #{platform}" do
        negate = platform.start_with?("cisco") ? "no" : "undo"
        policy = Baseline::Policy.new("version" => 1, "checks" => { "#{service}.minimum_servers" => { "expected" => 1 } })
        source = "#{syntax[:hostname]}\n#{syntax[service]} 192.0.2.10\n#{negate} #{syntax[service]} 192.0.2.10\n"
        report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: platform, complete: true)
        expect(report.findings.first.status).to eq(:fail)
        expect(report.configuration.fact("#{service}.servers")).to eq([])
      end
    end

    it "removes cancelled TACACS endpoints on #{platform}" do
      negate = platform.start_with?("cisco") ? "no" : "undo"
      lines = syntax[:tacacs].split("\n")
      command = lines.last.strip
      indent = lines.size > 1 ? " " : ""
      source = "#{syntax[:hostname]}\n#{syntax[:tacacs]} 192.0.2.10\n#{indent}#{negate} #{command} 192.0.2.10\n"
      policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.minimum_servers" => { "expected" => 1 } })
      report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: platform, complete: true)
      expect(report.findings.first.status).to eq(:fail)
      expect(report.configuration.fact("tacacs.servers")).to eq([])
    end

    it "accepts supported address families without confusing NTP options on #{platform}" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.minimum_servers" => { "expected" => 2 } })
      source = "#{syntax[:hostname]}\n#{syntax[:ntp]} time.example.test\n#{syntax[:ntp]} 2001:db8::10\n"
      source = "sysname LAB\nntp-service unicast-server 192.0.2.10\nntp-service unicast-server ipv6 2001:db8::10\n" if platform == "huawei"
      report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: platform, complete: true)
      expect(report).to be_compliant
      expect(report.configuration.fact("ntp.servers")).to eq(platform == "huawei" ? %w[192.0.2.10 2001:db8::10] : %w[time.example.test 2001:db8::10])
    end
  end

  it "does not retain an IOS TACACS key after removing and re-adding its host" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "tacacs.keys" => { "expected" => true } })
    source = "hostname LAB\ntacacs-server host 192.0.2.10 key 7 SYNTHETIC\nno tacacs-server host 192.0.2.10\ntacacs-server host 192.0.2.10\n"
    report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: "cisco_ios", complete: true)
    expect(report.findings.first.status).to eq(:fail)
    expect(report.configuration.fact("credentials.records")).to eq([])
  end

  it "reduces IOS legacy and modern logging declarations in their original order" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.minimum_servers" => { "expected" => 1 } })
    [ "logging 192.0.2.10\nno logging host 192.0.2.10", "logging host 192.0.2.10\nno logging 192.0.2.10" ].each do |body|
      report = Baseline::Audit.new(policy: policy).call(configuration: "hostname LAB\n#{body}\n", platform: "cisco_ios", complete: true)
      expect(report.findings.first.status).to eq(:fail)
    end
  end

  it "does not treat a Comware IPv6 address-family keyword as a log server" do
    %w[h3c huawei].each do |platform|
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "2001:db8::10" ] } })
      source = "sysname LAB\ninfo-center loghost ipv6 2001:db8::10\n"
      report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: platform, complete: true)
      expect(report).to be_compliant
    end
  end

  it "keeps Comware log servers in another VPN after cancellation" do
    %w[h3c huawei].each do |platform|
      policy = Baseline::Policy.new("version" => 1, "checks" => { "syslog.servers" => { "expected" => [ "2001:db8::10" ] } })
      source = "sysname LAB\ninfo-center loghost vpn-instance A ipv6 2001:db8::10\ninfo-center loghost vpn-instance B ipv6 2001:db8::10\nundo info-center loghost vpn-instance A ipv6 2001:db8::10\n"
      report = Baseline::Audit.new(policy: policy).call(configuration: source, platform: platform, complete: true)
      expect(report).to be_compliant
    end
  end
end

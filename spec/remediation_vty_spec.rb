# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "VTY protocol remediation" do
  {
    "h3c" => [ "sysname LAB", "ssh server enable", "line vty", "protocol inbound", "authentication-mode scheme", "system-view", "return" ],
    "huawei" => [ "sysname LAB", "stelnet server enable", "user-interface vty", "protocol inbound", "authentication-mode aaa", "system-view", "return" ],
    "cisco_ios" => [ "hostname LAB", "ip ssh version 2", "line vty", "transport input", "login local", "configure terminal", "end" ]
  }.each do |platform, (host, ssh, view, protocol, login, enter, leave)|
    it "changes only unsafe #{platform} VTY protocols and preserves authentication and other ranges" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true }, "ssh.vty_aaa" => { "expected" => true } })
      service = Baseline::Remediation.new(policy: policy)
      input = "#{host}\n#{ssh}\n#{view} 0 4\n #{protocol} all\n #{login}\n!\n#{view} 5 15\n #{protocol} ssh\n #{login}\n!\n"
      result = service.call(configuration: input, platform: platform, complete: true)
      expect(result.status).to eq(:ready)
      expect(result.configuration_commands).to eq([ enter, "#{view} 0 4", "#{protocol} ssh", leave ])
      expect(result.operations.first.risk).to eq("high")
      expect(result.checks.last.status).to eq(:not_needed)
      after = input.sub("#{protocol} all", "#{protocol} ssh")
      expect(after).to include(login, "#{view} 5 15")
      second = service.call(configuration: after, platform: platform, complete: true)
      expect(second.audit).to be_compliant
      expect(second.status).to eq(:noop)
    end

    it "does not force SSH-only transport without #{platform} SSH enable evidence" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true } })
      result = Baseline::Remediation.new(policy: policy).call(configuration: "#{host}\n#{view} 0 4\n #{protocol} all\n #{login}\n", platform: platform, complete: true)
      expect(result.status).to eq(:blocked)
      expect(result.configuration_commands).to be_empty
      expect(result.checks.first.requirements).to include("ssh.enabled")
    end
  end

  { "h3c" => [ "ssh server enable", "line", "scheme" ], "huawei" => [ "stelnet server enable", "user-interface", "aaa" ] }.each do |platform, (enable, view, mode)|
    it "blocks #{platform} protocol edits without explicit compatible range authentication" do
      policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true } })
      [ "password", "none", nil ].each do |authentication|
        input = "sysname LAB\n#{enable}\n#{view} vty 0 4\n protocol inbound all\n"
        input += " authentication-mode #{authentication}\n" if authentication
        result = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: platform, complete: true)
        expect(result.status).to eq(:blocked)
        expect(result.checks.first.reason).to eq(:vty_authentication_dependency)
        expect(result.operations).to be_empty
      end
      inherited = "sysname LAB\n#{enable}\nline class vty\n authentication-mode #{mode}\n protocol inbound all\n#\n#{view} vty 0 4\n#\n"
      result = Baseline::Remediation.new(policy: policy).call(configuration: inherited, platform: platform, complete: true)
      expect(result.checks.first.reason).to eq(:vty_authentication_dependency)
      expect(result.configuration_commands).to be_empty
    end
  end

  it "does not choose a new authentication chain merely to satisfy account authentication" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_aaa" => { "expected" => true } })
    result = Baseline::Remediation.new(policy: policy).call(configuration: "sysname LAB\nline vty 0 4\n authentication-mode password\n protocol inbound ssh\n", platform: "h3c", complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.requirements).to include("approved_authentication_chain")
  end

  it "withholds all range edits when VTY identities overlap" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true } })
    input = "sysname LAB\nssh server enable\nline vty 0 4\n protocol inbound all\n authentication-mode scheme\n#\nline vty 3 8\n protocol inbound telnet\n authentication-mode scheme\n"
    result = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
    expect(result.status).to eq(:blocked)
    expect(result.checks.first.reason).to eq(:vty_scope_unresolved)
    expect(result.operations).to be_empty
  end

  it "does not narrow transports to SSH while policy requires SSH disabled" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true }, "ssh.enabled" => { "expected" => false } })
    input = "sysname LAB\nssh server enable\nline vty 0 4\n protocol inbound all\n authentication-mode scheme\n"
    result = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
    expect(result.checks.first.reason).to eq(:policy_conflict)
    expect(result.operations).to be_empty
  end

  it "renders separate view paths for multiple unsafe ranges without overwriting the safe range" do
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.vty_ssh_only" => { "expected" => true } })
    input = "sysname LAB\nssh server enable\nline vty 0 4\n protocol inbound all\n authentication-mode scheme\n#\n" \
      "line vty 5 9\n protocol inbound ssh\n authentication-mode scheme\n#\nline vty 10 15\n protocol inbound telnet\n authentication-mode scheme\n"
    result = Baseline::Remediation.new(policy: policy).call(configuration: input, platform: "h3c", complete: true)
    expect(result.configuration_commands).to eq([ "system-view", "line vty 0 4", "protocol inbound ssh", "quit", "line vty 10 15", "protocol inbound ssh", "return" ])
    expect(result.checks.first.operation_ids.size).to eq(2)
  end
end

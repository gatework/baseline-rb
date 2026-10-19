# frozen_string_literal: true

require "baseline"

source = "sysname LAB\nntp-service ipv6 unicast-server 2001:0DB8:0:0:0:0:0:10 version 3\n" \
  "ntp-service ipv6 unicast-server 2001:db8::10 version 3\n"
policy = Baseline::Policy.new("version" => 1, "checks" => { "ntp.associations" => {
  "expected" => [ { "identity" => { "address" => "2001:db8::10", "role" => "server" }, "scope" => { "vrf" => "default" }, "attributes" => { "version" => 4 } } ],
  "managed_scopes" => [ { "vrf" => "default" } ]
} })
service = Baseline::Remediation.new(policy: policy)
plan = service.call(configuration: source, platform: "h3c", complete: true)
raise "Aliases counted as separate targets" unless plan.checks.first.details[:initial_targets] == 1
raise "Expected a single attribute replacement" unless plan.status == :ready && plan.operations.one? && plan.operations.first.action == :replace
raise "Noncanonical operation identity" unless plan.operations.first.identity["address"] == "2001:db8::10"
after = "sysname LAB\nntp-service ipv6 unicast-server 2001:db8::10 version 4\n"
raise "Not converged" unless service.call(configuration: after, platform: "h3c", complete: true).status == :noop
puts plan.to_text

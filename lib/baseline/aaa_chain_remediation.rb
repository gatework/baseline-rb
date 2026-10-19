# frozen_string_literal: true

require_relative "management_authentication"

module Baseline
  # 仅修改现有管理域的 login 链，不借端点规划推导未来材料及引用证明。
  class AaaChainRemediation
    Blocked = TargetRemediation::Blocked

    def initialize(policy:) = @policy = policy

    def call(finding, audit)
      options = @policy.rules.find { |rule| rule.id == finding.id }.remediation
      role = AaaChainSchema::IDS.fetch(finding.id)
      row = ManagementAuthentication.new(audit: audit).call(options: options, role: role)
      raise Blocked, :policy_conflict unless (options["methods"].first["kind"] == "tacacs") == finding.expected
      if role == "authentication" && finding.expected && !(row[:vtys].any? && row[:vtys].all? { |vty| vty[:complete] && vty[:authentication] == "scheme" })
        raise Blocked.new(:authentication_chain_evidence_required, requirements: [ "existing_scheme_vty_authentication" ])
      end
      ConfigurationOperation.new(kind: AaaChainSchema::KIND, identity: { "role" => role },
        scope: { "domain" => row[:domain], "syntax_profile" => options["syntax_profile"] },
        before: { "methods" => row[:methods].map { |method| method.transform_keys(&:to_s) }, "inherited" => row[:inherited] },
        after: { "methods" => options["methods"] }, action: :replace, phase: :activate, risk: finding.severity == "critical" ? "critical" : "high")
    end
  end
end

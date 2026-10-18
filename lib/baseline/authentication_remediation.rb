# frozen_string_literal: true

module Baseline
  # 在管理认证链获批准前列出具体对象和缺证，不根据现有候选组擅自切换登录路径。
  class AuthenticationRemediation
    ROLES = { "tacacs.login" => "authentication", "tacacs.authorization" => "authorization",
      "tacacs.accounting" => "accounting", "ssh.vty_aaa" => "authentication" }.freeze
    REQUIREMENTS = %w[approved_management_domain approved_ordered_method_chain approved_tacacs_group local_fallback_access_verified].freeze

    # VTY 的 AAA 要求也允许批准的本地方案，不强制把 AAA 等同于 TACACS。
    def self.requirements_for(id)
      return REQUIREMENTS.dup unless id == "ssh.vty_aaa"

      REQUIREMENTS.reject { |value| value == "approved_tacacs_group" } + %w[approved_vty_scope approved_authentication_mode approved_authentication_scheme]
    end

    # 只处理本适配器明确给出的引用图，缺策略和不适用范围仍由通用规划器控制。
    def self.applicable?(finding, evidence)
      ROLES.key?(finding.id) && evidence.complete? && !finding.expected.nil? &&
        [ :fail, :unknown ].include?(finding.status) && [ :deviation, :fact_unavailable ].include?(finding.reason) && evidence.fact_known?("aaa.bindings")
    end

    # 候选服务器组只是当前配置事实，不能冒充已经批准的目标引用。
    def call(finding, evidence)
      role = ROLES.fetch(finding.id)
      bindings = evidence.fact("aaa.bindings").select { |binding| binding[:role] == role }
      requirements = finding.expected ? self.class.requirements_for(finding.id) : %w[approved_management_domain approved_alternative_authentication_chain local_fallback_access_verified]
      requirements.concat(%w[approved_vty_scope approved_authentication_mode approved_authentication_scheme]) if finding.id == "ssh.vty_aaa" && !finding.expected
      reasons = bindings.filter_map { |binding| binding[:reason] }
      requirements << "resolved_management_domain" if reasons.any? { |reason| %i[authentication_domain_unknown authentication_domain_unresolved].include?(reason) }
      requirements << "parsed_ordered_method_chain" if reasons.include?(:unsupported_authentication_method) || reasons.include?(:authentication_list_unresolved)
      requirements << "resolved_tacacs_role_endpoints" if reasons.include?(:tacacs_scheme_unresolved)
      requirements << "resolved_vty_authentication" if reasons.include?(:vty_authentication_unknown)
      requirements << "existing_tacacs_key_evidence" if finding.expected && finding.id != "ssh.vty_aaa"
      available = if evidence.fact_known?("tacacs.schemes")
        evidence.fact("tacacs.schemes").filter_map do |name, scheme|
          servers = scheme[:server_types].fetch(role, [])
          next if servers.empty?
          { name: name, role: role, servers: servers, lines: [ scheme[:line] ] }
        end
      else
        requirements << "resolved_tacacs_group_inventory"
        []
      end
      { reason: bindings.any? && bindings.all? { |binding| binding[:complete] } ? :authentication_chain_approval_required : :authentication_chain_evidence_required,
        requirements: requirements.uniq, details: { required_role: role, expected: finding.expected, risk: "high", bindings: bindings, available_groups: available } }
    end
  end
end

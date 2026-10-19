# frozen_string_literal: true

require_relative "tacacs_remediation"
require_relative "aaa_chain_schema"

module Baseline
  # 仅修改选中现有域的 login 链；端点生命周期与链切换不能靠未经验证的阶段组合推导。
  class AaaChainRemediation
    Blocked = TargetRemediation::Blocked

    def initialize(policy:) = @policy = policy

    def call(finding, audit)
      evidence = audit.configuration
      options = @policy.rules.find { |rule| rule.id == finding.id }.remediation
      require!(evidence.platform == "h3c" && options["syntax_profile"] == "comware7", "native_management_method_syntax_profile")
      require!(evidence.complete?, "complete_configuration")
      %w[management_domain methods local_fallback_access_verified management_consumers_verified].each do |key|
        require!(options[key] && (!key.end_with?("verified") || options[key] == true), key)
      end
      methods = options["methods"]
      raise Blocked, :policy_conflict unless (methods.first["kind"] == "tacacs") == finding.expected
      role = AaaChainSchema::IDS.fetch(finding.id)
      rows = evidence.fact("aaa.bindings").select { |row| row[:role] == role }
      require!(rows.one? && rows.first[:complete] && rows.first[:selected] && rows.first[:domain] == options["management_domain"], "resolved_selected_management_domain")
      row = rows.first
      require!(AaaChainSchema.methods?(row[:methods].map { |method| method.transform_keys(&:to_s) }), "parsed_ordered_method_chain")
      if role == "authentication" && finding.expected
        require!(row[:vtys].any? && row[:vtys].all? { |vty| vty[:complete] && vty[:authentication] == "scheme" }, "existing_scheme_vty_authentication")
      end
      # 其他指标的端点变化需要单独完成和复查，不能以旧密钥和引用证明未来端点。
      related = audit.findings.select { |item| TacacsRemediation::IDS.include?(item.id) && item.status != :not_applicable }
      require!(related.all? { |item| item.status == :pass }, "stable_approved_tacacs_endpoints")
      verify_target!(methods.first["group"], role, evidence, options) if finding.expected
      verify_binding_policy!(audit, row, methods, role)
      ConfigurationOperation.new(kind: AaaChainSchema::KIND, identity: { "role" => role },
        scope: { "domain" => row[:domain], "syntax_profile" => options["syntax_profile"] },
        before: { "methods" => row[:methods].map { |method| method.transform_keys(&:to_s) }, "inherited" => row[:inherited] },
        after: { "methods" => methods }, action: :replace, phase: :activate, risk: finding.severity == "critical" ? "critical" : "high")
    end

    private

    def require!(condition, requirement)
      raise Blocked.new(:authentication_chain_evidence_required, requirements: [ requirement ]) unless condition
    end

    # 服务器组身份和职责密钥必须同时明确，不能从同地址、其他职责或候选名称借用材料证明。
    def verify_target!(group, role, evidence, options)
      require!(options["tacacs_peer_compatibility_verified"] == true, "tacacs_peer_compatibility_verified")
      require!(%w[tacacs.schemes tacacs.endpoints tacacs.key_slots].all? { |fact| evidence.fact_known?(fact) }, "resolved_tacacs_reference_inventory")
      schemes = evidence.fact("tacacs.schemes")
      require!(schemes.key?(group) && schemes[group][:target_context_supported], "existing_default_routing_scheme")
      targets = evidence.fact("tacacs.endpoints").select { |target| target["scope"]["group"] == group && target["identity"]["role"] == role }
      require!(targets.any? && targets.all? { |target| target["scope"]["vrf"] == "default" }, "resolved_tacacs_role_endpoints")
      slots = evidence.fact("tacacs.key_slots").select { |slot| slot[:group] == group && slot[:role] == role }
      require!(slots.one? && slots.first[:complete] && slots.first[:present] == true, "existing_scheme_role_key")
    end

    # 显式批准的端点绑定也是最终约束；不能在修复标量指标时破坏其使用关系。
    def verify_binding_policy!(audit, row, methods, role)
      expected = audit.findings.find { |finding| finding.id == "tacacs.endpoints" && finding.status != :not_applicable }&.expected
      expected.to_a.each do |target|
        next unless target.key?("bindings") && target["identity"]["role"] == role
        current = audit.configuration.fact("tacacs.endpoints").find { |item| item["identity"] == target["identity"] && item["scope"] == target["scope"] }
        require!(current && current.key?("bindings"), "resolved_tacacs_reference_inventory")
        bindings = current["bindings"].reject { |binding| binding["domain"]&.casecmp?(row[:domain]) && binding["role"] == role }
        position = methods.index { |method| method["kind"] == "tacacs" && method["group"].casecmp?(target["scope"]["group"]) }
        bindings += [ { "kind" => "aaa.domain", "domain" => row[:domain], "role" => role, "position" => position.zero? ? "primary" : "fallback", "selected" => true } ] if position
        raise Blocked, :policy_conflict if ResourceBindings.compare(bindings, target["bindings"]).values.any?(&:any?)
      end
    end
  end
end

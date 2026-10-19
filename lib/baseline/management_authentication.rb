# frozen_string_literal: true

require_relative "tacacs_remediation"
require_relative "aaa_chain_schema"

module Baseline
  # 方法链和 VTY 模式共享同一管理域、恢复及材料证据，批准不由当前候选组推导。
  class ManagementAuthentication
    Blocked = TargetRemediation::Blocked

    def initialize(audit:) = @audit = audit

    def call(options:, role:)
      evidence = @audit.configuration
      profile = { "h3c" => "comware7", "huawei" => "vrp_s_series" }[evidence.platform]
      require!(profile && profile == options["syntax_profile"], "native_management_method_syntax_profile")
      require!(evidence.complete?, "complete_configuration")
      %w[management_domain methods local_fallback_access_verified management_consumers_verified].each do |key|
        require!(options[key] && (!key.end_with?("verified") || options[key] == true), key)
      end
      require!(evidence.fact_known?("aaa.bindings"), "resolved_selected_management_domain")
      rows = evidence.fact("aaa.bindings").select { |row| row[:role] == role }
      require!(rows.one? && rows.first[:complete] && rows.first[:selected] && rows.first[:domain] == options["management_domain"], "resolved_selected_management_domain")
      row = rows.first
      require!(AaaChainSchema.methods?(row[:methods].map { |method| method.transform_keys(&:to_s) }, syntax_profile: options["syntax_profile"]), "parsed_ordered_method_chain")
      related = @audit.findings.select { |item| TacacsRemediation::IDS.include?(item.id) && item.status != :not_applicable && !item.expected.nil? }
      require!(related.all? { |item| item.status == :pass }, "stable_approved_tacacs_endpoints")
      verify_target!(options["methods"].first["group"], role, evidence, options) if options["methods"].first["kind"] == "tacacs"
      verify_binding_policy!(@audit, row, options["methods"], role)
      row
    end

    # 切入 AAA 会启用整条登录路径；未解析的授权/计费不能由认证职责的证明代替。
    def login_path!(options:)
      authentication = call(options: options, role: "authentication")
      methods = authentication[:methods].map { |method| method.transform_keys(&:to_s) }
      require!(methods == options["methods"], "existing_approved_management_method_chain")
      selected = @audit.configuration.fact("aaa.bindings")
      roles = selected.group_by { |row| row[:role] }
      complete = roles.keys.sort == %w[accounting authentication authorization] && roles.values.all? do |rows|
        row = rows.first
        methods = row[:methods].map { |method| method.transform_keys(&:to_s) }
        rows.one? && row[:selected] && row[:domain] == authentication[:domain] && row[:complete] &&
          AaaChainSchema.methods?(methods, syntax_profile: options["syntax_profile"]) && methods.all? { |method| %w[local none tacacs].include?(method["kind"]) }
      end
      require!(complete, "resolved_management_login_roles")
      selected.reject { |row| row[:role] == "authentication" }.each do |row|
        row[:methods].select { |method| method[:kind] == "tacacs" }.each do |method|
          verify_target!(method[:group], row[:role], @audit.configuration, options)
        end
      end
      authentication
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
      material_role = evidence.platform == "huawei" ? "shared" : role
      slots = evidence.fact("tacacs.key_slots").select { |slot| slot[:group] == group && slot[:role] == material_role }
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

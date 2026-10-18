# frozen_string_literal: true

module Baseline
  # 在对象命令实现前暴露共享绑定的改动范围，禁止把省略绑定当成删除授权。
  class ResourceBindingRemediation
    # 只在完整策略范围内列出对象引用，不接管缺策略或不适用结果。
    def self.applicable?(finding, evidence)
      finding.id == "tacacs.endpoints" && evidence.complete? && finding.expected.is_a?(Array) &&
        [ :fail, :unknown ].include?(finding.status) && %i[deviation resource_binding_unresolved resource_attribute_unresolved fact_unavailable].include?(finding.reason) &&
        (finding.expected.any? { |object| object.key?("bindings") } || evidence.resources.any? { |resource| resource.kind == "tacacs.endpoint" && resource.bindings.to_a.any? })
    end

    # 当前和批准引用分别展示；引用迁移与认证链修改必须在厂商命令验证后执行。
    def call(finding, evidence)
      resources = evidence.resources.select { |resource| resource.kind == "tacacs.endpoint" }
      requirements = %w[approved_binding_change_scope preserved_or_approved_reference_migration approved_ordered_method_chain local_fallback_access_verified vendor_verified_tacacs_binding_commands]
      requirements << "resolved_domain_reference_inventory" if resources.any? { |resource| resource.bindings.nil? }
      { reason: :resource_binding_changes_required, requirements: requirements,
        details: { risk: "high", current_references: resources.map { |resource| { identity: resource.identity, scope: resource.scope, bindings: resource.bindings } },
          requested_objects: finding.expected, differences: finding.details.except(:verification_scope) } }
    end
  end
end

# frozen_string_literal: true

module Baseline
  # HWTACACS 方案密钥只输出逐职责材料要求，不生成秘密或占位配置。
  class TacacsKeyRemediation
    # 方案槽位由适配器明确建模；其他厂商不能套用 Comware 密钥继承规则。
    def self.applicable?(finding, evidence)
      finding.id == "tacacs.keys" && evidence.complete? && !finding.expected.nil? &&
        [ :fail, :unknown ].include?(finding.status) && [ :deviation, :fact_unavailable ].include?(finding.reason) &&
        evidence.fact_known?("tacacs.key_slots")
    end

    # 每项材料关联实际已知消费者，未知引用仍保留为人工前提。
    def call(finding, evidence)
      return { reason: :unsupported_setting, requirements: [ "approved_tacacs_key_policy" ], details: {} } unless finding.expected == true

      slots = evidence.fact("tacacs.key_slots")
      if slots.empty?
        return { reason: :unresolved_prerequisites, requirements: %w[approved_tacacs_scheme approved_tacacs_endpoints approved_tacacs_key_material], details: {} }
      end
      missing = slots.reject { |slot| slot[:present] == true }.map do |slot|
        endpoints = evidence.resources.select do |resource|
          resource.kind == "tacacs.endpoint" && resource.scope["group"] == slot[:group] &&
            (slot[:role] == "shared" || resource.identity["role"] == slot[:role])
        end
        provision = slot[:present] == false
        requirements = provision ? %w[approved_tacacs_key_material supported_protected_storage_format manual_material_provisioning] : [ "tacacs_key_state_evidence" ]
        dependencies = provision ? %w[tacacs_peer_key_update authentication_reference_evidence local_fallback_access_verified] : []
        dependencies << "resolved_tacacs_endpoints" if endpoints.any? { |resource| !resource.complete? }
        dependencies << "confirm_key_consumer_scope" if endpoints.empty?
        slot.merge(action: provision ? "provision" : "verify", risk: "high", requirements: requirements, dependencies: dependencies,
          endpoints: endpoints.map { |resource| { identity: resource.identity, scope: resource.scope, lines: resource.lines, complete: resource.complete? } })
      end
      { reason: missing.any? { |slot| slot[:action] == "provision" } ? :credential_material_required : :credential_material_evidence_required,
        requirements: missing.flat_map { |slot| slot[:requirements] + slot[:dependencies] }.uniq, details: { key_slots: missing } }
    end
  end
end

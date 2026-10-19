# frozen_string_literal: true

require "ctx_parser/immutable"
require_relative "configuration_operation"

module Baseline
  # 复查、持久化提示和恢复意图独立于修正命令；不执行命令，也不复用旧依赖批准。
  class RemediationReview
    INSPECTION = CtxParser::Immutable.copy({ "h3c" => [ "display current-configuration" ], "huawei" => [ "display current-configuration" ],
      "cisco_ios" => [ "show running-config" ], "cisco_nxos" => [ "show running-config" ], "hillstone" => [ "show configuration" ],
      "palo_alto" => [ "show config diff", "show config candidate" ] })
    PERSISTENCE = CtxParser::Immutable.copy({ "h3c" => [ "save" ], "huawei" => [],
      "cisco_ios" => [ "copy running-config startup-config" ], "cisco_nxos" => [ "copy running-config startup-config" ],
      "hillstone" => [ "save" ], "palo_alto" => [ "commit" ] })
    RUNTIME = CtxParser::Immutable.copy({ "ntp" => "time_synchronization_and_peer_authentication", "syslog" => "receiver_delivery",
      "snmp" => "nms_read_notify_and_denied_write", "ssh" => "management_access_and_recovery", "management" => "management_access_and_recovery",
      "services" => "management_access_and_recovery", "tacacs" => "aaa_roles_and_local_fallback" })

    def call(platform:, operations:, checks:, renderer:)
      changed = operations.any?
      domains = checks.select { |check| check.operation_ids.any? }.map { |check| check.id.split(".").first }.uniq
      inverse, unavailable = [], []
      operations.reverse_each do |operation|
        restored, reason = inverse_operation(operation, renderer)
        if restored
          inverse << restored.to_h.merge(source_operation_id: operation.id)
        else
          unavailable << { operation_id: operation.id, reason: reason }
        end
      end
      CtxParser::Immutable.copy({
        validation: { status: changed ? :not_executed : :not_needed, commands: changed ? INSPECTION.fetch(platform, []) : [], view: :operational,
          scope: platform == "palo_alto" ? :candidate : :configuration_inspection,
          requires_full_snapshot: changed, requires_running_reaudit: changed, requires_same_policy: changed,
          audit_format: platform == "palo_alto" ? :set : :cli, requires_target_version_confirmation: changed,
          configuration_output_requires_controlled_handling: changed, runtime_requirements: changed ? domains.filter_map { |domain| RUNTIME[domain] }.uniq : [] },
        persistence: { status: changed ? :manual_only : :not_needed, commands: changed ? PERSISTENCE.fetch(platform, []) : [],
          view: platform == "palo_alto" ? :configuration : :operational, requires_review_and_validation: changed,
          requires_target_version_commit_decision: changed && platform == "huawei", contains_unresolved_checks: checks.any? { |check| check.status == :blocked } },
        rollback: { status: !changed ? :not_applicable : unavailable.any? ? :manual_required : :requires_replanning,
          inverse_operations: inverse, unavailable: unavailable, configuration_commands: [], restores_previous_state: changed,
          approved_baseline_status: changed ? :not_verified : :not_applicable, requires_baseline_revalidation: changed,
          requires_fresh_snapshot: changed, requires_separate_approval: changed, requires_dependency_revalidation: changed }
      })
    end

    private

    # 只生成类型可表达的非秘密恢复意图；共享 ACL、认证和材料迁移仍须专门的恢复规划。
    def inverse_operation(operation, renderer)
      if operation.kind == "setting"
        id = operation.identity["rule"]
        return [ nil, :native_restore_not_modelled ] unless %w[ntp.source syslog.source].include?(id) && renderer.class::SOURCE_COMMANDS.key?(id)
        return [ nil, :old_state_unavailable ] unless ResourceSchema.interface_name(operation.before)
      elsif operation.kind == "ntp.authentication" || operation.kind.start_with?("tacacs.", "snmp.group", "snmp.user_group")
        return [ nil, :authentication_or_material_reassessment_required ]
      elsif operation.kind == "access.acl"
        return [ nil, :shared_acl_reference_reassessment_required ]
      elsif %w[access.binding snmp.binding].include?(operation.kind)
        return [ nil, :old_state_unavailable ] unless operation.before&.key?("acl")
      elsif !%w[syslog.destination syslog.reference ntp.association ntp.server].include?(operation.kind)
        return [ nil, :native_restore_not_modelled ]
      elsif operation.kind.start_with?("ntp.") && [ operation.before, operation.after ].compact.any? { |fields| fields.key?("key_id") || fields["authenticated"] == true }
        return [ nil, :authentication_or_material_reassessment_required ]
      end
      action = { add: :remove, remove: :add, replace: :replace, set: :set }.fetch(operation.action)
      phase = { add: :create, remove: :remove, replace: :update, set: :update }.fetch(action)
      restored = ConfigurationOperation.new(**operation.to_h.except(:id).merge(before: operation.after, after: operation.before,
        action: action, phase: phase, risk: operation.risk == "critical" ? "critical" : "high"))
      [ restored, nil ]
    rescue ArgumentError
      [ nil, :native_restore_not_modelled ]
    end
  end
end

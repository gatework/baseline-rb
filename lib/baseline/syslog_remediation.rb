# frozen_string_literal: true

require_relative "target_remediation"
require_relative "palo_alto/syslog_binding_remediation"

module Baseline
  # 日志对象共享目标集合规划，但保留自身身份和审批规则。
  class SyslogRemediation < TargetRemediation
    IDS = %w[syslog.minimum_servers syslog.servers syslog.destinations].freeze
    KIND = "syslog.destination"

    # 命名 profile 的原生命令必须保留配置引用，不能只通过最终地址集合证明安全。
    def call(finding, audit)
      @panos = audit.configuration.platform == "palo_alto"
      structured = audit.findings.find { |item| item.id == "syslog.destinations" && item.status != :not_applicable }
      approved = @policy.rules.find { |rule| rule.id == "syslog.destinations" && rule.enabled? } if structured
      @migrations = approved&.remediation&.fetch("binding_migrations", []) || []
      raise Blocked, :unsupported_syslog_binding_migration if !@panos && @migrations.any?
      result = super
      return result unless @panos
      projection = if @migrations.any?
        PaloAlto::SyslogBindingRemediation.new.call(migrations: @migrations, evidence: audit.configuration,
          managed_scopes: approved.managed_scopes, targets: structured.expected)
      end
      references = verify_panos_profiles!(result, audit, projection)
      tls_operations = result.operations.select do |operation|
        operation.after&.fetch("protocol", nil) == "ssl" && %w[address port protocol].any? { |field| operation.after[field] != operation.before&.[](field) }
      end
      if tls_operations.any? && approved&.remediation&.fetch("syslog_tls_peer_compatibility_verified", false) != true
        raise Blocked.new(:syslog_tls_peer_compatibility_required, requirements: [ "syslog_tls_peer_compatibility_verified" ])
      end
      operations = result.operations + (projection&.operations || [])
      raise Blocked, :resource_unresolved if operations.empty?
      Result.new(operations: operations.freeze, details: CtxParser::Immutable.copy(result.details.merge(
        verified_syslog_operation_ids: operations.map(&:id), preserved_profile_reference_counts: references)))
    end

    private

    # 共享及未挂接的转发引用均保留；创建新对象不等于批准新的日志使用链。
    def allow_empty_operations? = @panos && @migrations.any?

    def verify_panos_profiles!(result, audit, projection)
      evidence = audit.configuration
      unless evidence.fact_known?("syslog.profile_references") && evidence.fact_known?("syslog.declared_profile_references") &&
          evidence.fact("syslog.reference_inventory_complete") == true
        raise Blocked.new(:resource_binding_unresolved, requirements: [ "resolved_syslog_reference_inventory" ])
      end
      unless result.operations.all? { |operation| operation.identity.keys == [ "name" ] && operation.scope.keys == [ "profile" ] }
        raise Blocked, :approved_scope_required
      end
      current = evidence.fact("syslog.destinations")
      targets = audit.findings.find { |item| item.id == "syslog.destinations" }&.expected || []
      references = projection&.references || evidence.fact("syslog.profile_references")
      declared = projection&.declared || evidence.fact("syslog.declared_profile_references")
      targets.each do |target|
        next unless target.key?("bindings")
        difference = ResourceBindings.compare(references.fetch(target["scope"]["profile"], []), target["bindings"])
        if difference.values.any?(&:any?)
          raise Blocked.new(:resource_binding_changes_required, requirements: %w[approved_log_forwarding_binding_scope preserved_log_filters vendor_verified_syslog_binding_commands])
        end
      end
      removed = result.operations.select { |operation| operation.action == :remove }.to_h { |operation| [ [ operation.scope, operation.identity ], true ] }
      projected = current.reject { |object| removed.key?(key(object)) }
      projected += result.operations.select { |operation| operation.action == :add }.map { |operation| { "identity" => operation.identity, "scope" => operation.scope } }
      remaining = projected.group_by { |object| object["scope"]["profile"] }
      if projection&.profiles&.any? { |profile| declared.fetch(profile, 0).positive? && !remaining.key?(profile) }
        raise Blocked.new(:syslog_profile_references_required, requirements: [ "approved_referenced_syslog_server" ])
      end
      current_profiles = current.group_by { |object| object["scope"]["profile"] }
      if projection && projection.operations.any?
        counts = current_profiles.transform_values(&:size)
        result.operations.select { |operation| operation.phase == :prepare }.each do |operation|
          profile = operation.scope.fetch("profile")
          counts[profile] -= 1
          if counts[profile].zero? && evidence.fact("syslog.declared_profile_references").fetch(profile, 0).positive?
            raise Blocked.new(:syslog_reference_order_conflict, requirements: [ "capacity_for_reference_migration" ])
          end
        end
      end
      targets_by_key = targets.to_h { |target| [ key(target), target ] }
      result.operations.each do |operation|
        profile = operation.scope.fetch("profile")
        if declared.fetch(profile, 0).positive? && !remaining.key?(profile)
          raise Blocked.new(:syslog_profile_references_required, requirements: %w[preserved_or_approved_reference_migration approved_log_forwarding_binding_scope])
        end
        if operation.action == :add && declared.fetch(profile, 0).positive? && !current_profiles.key?(profile)
          target = targets_by_key[[ operation.scope, operation.identity ]]
          unless target&.key?("bindings")
            raise Blocked.new(:syslog_reference_approval_required, requirements: [ "approved_existing_profile_references" ])
          end
        end
        next unless operation.after
        required = operation.action == :add ? %w[address protocol port format facility] : []
        endpoint_change = %w[address port protocol].any? { |field| operation.after[field] != operation.before&.[](field) }
        required |= %w[protocol port] if endpoint_change
        missing = required.reject { |field| operation.after.key?(field) }
        raise Blocked.new(:missing_syslog_parameters, requirements: missing.map { |field| "syslog.#{field}" }) if missing.any?
      end
      profiles = result.operations.map { |operation| operation.scope.fetch("profile") } + (projection&.profiles || [])
      profiles.uniq.to_h { |profile| [ profile, declared.fetch(profile, 0) ] }
    end

    # 设备总容量批准不能覆盖原生每个 profile 四服务器上限；中间候选树也不能超限。
    def order_for_capacity(operations, current, projected, findings)
      ordered, details = super
      return [ ordered, details ] unless @panos
      counts = ->(objects) { objects.group_by { |object| object["scope"]["profile"] }.transform_values(&:size) }
      initial, final = counts.call(current), counts.call(projected)
      raise Blocked, :capacity_evidence_conflict if initial.values.any? { |count| count > 4 }
      raise Blocked, :capacity_exceeded if final.values.any? { |count| count > 4 }
      by_profile = ordered.group_by { |operation| operation.scope["profile"] }
      replacements = {}
      initial.each do |profile, count|
        group = by_profile.fetch(profile, [])
        additions = group.count { |operation| operation.action == :add }
        prepared = group.count { |operation| operation.phase == :prepare }
        needed = [ count + additions - prepared - 4, 0 ].max
        candidates = group.select { |operation| operation.action == :remove && operation.phase != :prepare }.take(needed)
        raise Blocked, :capacity_exceeded if candidates.size < needed
        candidates.each do |operation|
          risk = operation.risk == "critical" ? "critical" : "high"
          replacements[operation.id] = ConfigurationOperation.new(**operation.to_h.except(:id).merge(phase: :prepare, risk: risk))
        end
      end
      details = details.merge(native_profile_capacity: 4, early_removals: details[:early_removals] + replacements.size)
      details[:effective_order] = "remove_to_fit_then_add" if replacements.any?
      [ ordered.map { |operation| replacements.fetch(operation.id, operation) }, details ]
    end
  end
end

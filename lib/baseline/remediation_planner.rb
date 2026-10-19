# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "remediation_plan"
require_relative "syslog_remediation"
require_relative "ntp_remediation"
require_relative "vty_remediation"
require_relative "access_remediation"
require_relative "snmp_access_remediation"
require_relative "snmp_permission_remediation"
require_relative "credential_remediation"
require_relative "tacacs_key_remediation"
require_relative "authentication_remediation"
require_relative "resource_binding_remediation"
require_relative "tacacs_remediation"

module Baseline
  # 每个指标都必须有规划结果；缺少实现或前提时显式受阻。
  class RemediationPlanner
    REQUIREMENTS = CtxParser::Immutable.copy({
      "snmp.enabled" => [ "snmp_endpoint_configuration" ], "snmp.versions" => [ "approved_snmp_users" ],
      "snmp.write_enabled" => [ "approved_snmp_principal_permissions" ], "snmp.auth_priv" => [ "approved_snmp_users", "replacement_credential_reference" ],
      "snmp.acl_bound" => [ "approved_acl_identity", "shared_reference_evidence" ], "snmp.acl_restricted" => [ "approved_access_targets", "shared_reference_evidence" ],
      "snmp.sources" => [ "approved_acl_identity", "approved_access_targets" ],
      "ntp.minimum_servers" => [ "approved_ntp_targets" ], "ntp.servers" => [ "approved_ntp_associations" ],
      "ntp.authentication" => [ "ntp_key_reference_evidence" ], "ntp.source" => [],
      "syslog.minimum_servers" => [ "approved_syslog_targets" ], "syslog.servers" => [ "approved_syslog_destinations" ], "syslog.source" => [],
      "ssh.enabled" => [ "existing_key_material", "management_endpoint_scope" ], "ssh.versions" => [],
      "ssh.vty_ssh_only" => [ "management_endpoint_scope", "existing_ssh_service" ], "ssh.vty_aaa" => [ "approved_authentication_chain" ],
      "management.acl_bound" => [ "approved_acl_identity", "approved_access_targets", "shared_reference_evidence" ],
      "management.acl_restricted" => [ "approved_acl_identity", "approved_access_targets", "shared_reference_evidence" ],
      "management.sources" => [ "approved_acl_identity", "approved_access_targets", "shared_reference_evidence" ], "services.disabled" => [],
      "credentials.storage" => [ "credential_object_evidence", "approved_replacement_credential", "supported_protected_storage_format", "manual_rotation_procedure" ],
      "credentials.strength" => [ "credential_object_evidence", "external_password_strength_evidence", "approved_replacement_for_observed_weak_passwords", "manual_rotation_procedure" ],
      "tacacs.minimum_servers" => [ "approved_tacacs_targets" ], "tacacs.servers" => [ "approved_tacacs_endpoints", "authentication_reference_evidence" ],
      "tacacs.login" => [ "approved_authentication_chain", "local_fallback_evidence" ],
      "tacacs.authorization" => [ "approved_authorization_chain" ], "tacacs.accounting" => [ "approved_accounting_chain" ],
      "tacacs.keys" => [ "approved_tacacs_scheme", "approved_tacacs_key_material", "authentication_reference_evidence", "local_fallback_access_verified" ],
      "syslog.destinations" => [ "supported_resource_renderer" ], "ntp.associations" => [ "supported_resource_renderer" ],
      "tacacs.endpoints" => [ "supported_resource_renderer", "authentication_reference_evidence" ]
    })

    # 与本次审计绑定相同策略，禁止把其他策略的报告拿来生成方案。
    def initialize(policy:, renderer:, reserved_acl_identifiers: nil)
      @policy, @renderer = policy, renderer
      @reserved_acl_identifiers = reserved_acl_identifiers && CtxParser::Immutable.copy(reserved_acl_identifiers)
    end

    # 编译每项结果；独立可生成操作不受其他指标缺参影响。
    def call(audit)
      raise ArgumentError, "Remediation policy does not match audit" unless audit.policy_sha256 == @policy.sha256
      operations, steps = [], []
      conflicting_access_domains = conflicting_acl_allocations(audit)
      checks = audit.findings.map do |finding|
        status = { pass: :not_needed, not_applicable: :not_applicable }[finding.status]
        if status
          check(finding, status, nil)
        elsif CredentialRemediation.applicable?(finding, audit.configuration)
          result = CredentialRemediation.new.call(finding, audit.configuration)
          check(finding, :blocked, result.fetch(:reason), requirements: result.fetch(:requirements), details: result.fetch(:details))
        elsif SnmpPermissionRemediation.applicable?(finding, audit.configuration)
          result = SnmpPermissionRemediation.new.call(finding, audit.configuration)
          check(finding, :blocked, result.fetch(:reason), requirements: result.fetch(:requirements), details: result.fetch(:details))
        elsif TacacsKeyRemediation.applicable?(finding, audit.configuration)
          result = TacacsKeyRemediation.new.call(finding, audit.configuration)
          check(finding, :blocked, result.fetch(:reason), requirements: result.fetch(:requirements), details: result.fetch(:details))
        elsif AuthenticationRemediation.applicable?(finding, audit.configuration)
          result = AuthenticationRemediation.new.call(finding, audit.configuration)
          check(finding, :blocked, result.fetch(:reason), requirements: result.fetch(:requirements), details: result.fetch(:details))
        elsif ResourceBindingRemediation.applicable?(finding, audit.configuration) &&
            (!@renderer.supports?(finding.id) || finding.details.fetch(:binding_differences, []).any? || finding.reason == :resource_binding_unresolved)
          result = ResourceBindingRemediation.new.call(finding, audit.configuration)
          check(finding, :blocked, result.fetch(:reason), requirements: result.fetch(:requirements), details: result.fetch(:details))
        elsif !audit.configuration.complete? || finding.status == :unknown && !((AccessRemediation::IDS + SnmpAccessRemediation::IDS).include?(finding.id) && finding.reason == :fact_unavailable && !finding.expected.nil?)
          reason = audit.configuration.complete? ? finding.reason : audit.configuration.status == :unsupported ? :unsupported_platform : :input_incomplete
          reason = :tacacs_context_unresolved if audit.configuration.complete? && TacacsRemediation::IDS.include?(finding.id) && finding.diagnostics.any? { |issue| issue[:code] == :tacacs_context_unresolved }
          check(finding, :blocked, reason)
        elsif @renderer.supports?(finding.id)
          if (AccessRemediation::IDS + SnmpAccessRemediation::IDS).include?(finding.id) && conflicting_access_domains.include?(finding.id.split(".").first)
            next check(finding, :blocked, :policy_conflict)
          end
          if finding.id == "ssh.enabled" && finding.expected == true
            next check(finding, :blocked, :unresolved_prerequisites, requirements: REQUIREMENTS.fetch(finding.id))
          end
          if finding.id == "ssh.enabled" && audit.findings.any? { |item| item.id == "ssh.vty_ssh_only" && item.status != :not_applicable && item.expected == true }
            next check(finding, :blocked, :policy_conflict)
          end
          if finding.id == "snmp.versions" && audit.findings.any? { |item| item.id == "snmp.enabled" && item.status != :not_applicable && item.expected == false }
            next check(finding, :blocked, :policy_conflict)
          end
          missing = @renderer.prerequisites(finding.id).reject do |fact, expected|
            audit.configuration.fact_known?(fact) && audit.configuration.fact(fact) == expected
          end.keys
          if missing.any?
            check(finding, :blocked, :unresolved_prerequisites, requirements: missing)
          elsif finding.id == "snmp.versions" && (required = snmp_version_requirements(audit)).any?
            check(finding, :blocked, :unresolved_prerequisites, requirements: required)
          elsif (AccessRemediation::IDS + SnmpAccessRemediation::IDS).include?(finding.id)
            compile_access(finding, audit, operations, steps)
          elsif (SyslogRemediation::IDS + NtpRemediation::IDS + TacacsRemediation::IDS).include?(finding.id)
            compile_targets(finding, audit, operations, steps)
          elsif finding.id == "ssh.vty_ssh_only"
            compile_vty(finding, audit, operations, steps)
          else
            compile_setting(finding, operations, steps)
          end
        else
          reason = finding.id.start_with?("credentials.") || finding.id == "tacacs.keys" ? :credential_rotation_required : :remediation_unmodeled
          check(finding, :blocked, reason, requirements: REQUIREMENTS.fetch(finding.id, [ "supported_rule_handler" ]))
        end
      end
      RemediationPlan.new(audit: audit, checks: checks, operations: operations.uniq(&:id), steps: steps.uniq(&:to_h), renderer: @renderer)
    end

    private

    # 同一设备上的不同端点不能分别创建同一 ACL，跨领域也不能靠命令顺序合并权限。
    def conflicting_acl_allocations(audit)
      applicable = audit.findings.reject { |item| item.status == :not_applicable }.map(&:id)
      targets = @policy.rules.select { |rule| applicable.include?(rule.id) }.flat_map do |rule|
        rule.remediation.fetch("access_targets", []).map { |target| [ rule.id.split(".").first, target ] }
      end
      targets.group_by do |_, target|
        name = target.fetch("acl")
        /\A[0-9]+\z/.match?(name) ? name.sub(/\A0+(?=[0-9])/, "") : name.downcase
      end.values.select { |uses| uses.map { |domain, target| [ domain, target.fetch("endpoint") ] }.uniq.size > 1 }
        .flat_map { |uses| uses.map(&:first) }.uniq
    end

    # 整个访问领域先完整渲染，再加入创建及重绑；不能只暴露前半段方案。
    def compile_access(finding, audit, operations, steps)
      handler = SnmpAccessRemediation::IDS.include?(finding.id) ? SnmpAccessRemediation : AccessRemediation
      result = handler.new(policy: @policy, reserved_identifiers: @reserved_acl_identifiers).call(finding, audit)
      rendered = result.operations.flat_map { |operation| @renderer.render(operation) }
      operations.concat(result.operations)
      steps.concat(rendered)
      check(finding, :planned, nil, operation_ids: result.operations.map(&:id), details: result.details)
    rescue TargetRemediation::Blocked => error
      check(finding, :blocked, error.reason, requirements: error.requirements)
    rescue CommandRenderer::UnsupportedOperation
      check(finding, :blocked, :unsupported_setting)
    rescue ArgumentError
      check(finding, :blocked, :invalid_command_parameter)
    end

    # 认证材料不能单独证明可用；保留组引用证据并要求审核方确认已验证 v3 管理路径。
    def snmp_version_requirements(audit)
      rule = @policy.rules.find { |item| item.id == "snmp.versions" }
      required = rule.remediation["existing_v3_access_verified"] == true ? [] : [ "existing_v3_access_verified" ]
      evidence = audit.configuration
      groups, users = evidence.fact("snmp.groups"), evidence.fact("snmp.users")
      usable = evidence.fact_known?("snmp.groups") && evidence.fact_known?("snmp.users") && groups.is_a?(Hash) && users.is_a?(Array) &&
        users.any? { |user| user[:auth] && user[:priv] && groups.key?(user[:group]) && !groups[user[:group]][:write].nil? }
      required << "snmp_v3_group_reference" unless usable
      required
    end

    # 所有范围先验证并完整渲染，再一次性加入方案。
    def compile_vty(finding, audit, operations, steps)
      proposed = VtyRemediation.new.call(finding, audit)
      rendered = proposed.flat_map { |operation| @renderer.render(operation) }
      operations.concat(proposed)
      steps.concat(rendered)
      check(finding, :planned, nil, operation_ids: proposed.map(&:id))
    rescue TargetRemediation::Blocked => error
      check(finding, :blocked, error.reason)
    rescue CommandRenderer::UnsupportedOperation
      check(finding, :blocked, :unsupported_setting)
    rescue ArgumentError
      check(finding, :blocked, :invalid_command_parameter)
    end

    # 整个指标的操作全部成功呈现后才加入方案，避免删除后才发现新增语法不支持。
    def compile_targets(finding, audit, operations, steps)
      handler = if TacacsRemediation::IDS.include?(finding.id)
        TacacsRemediation
      elsif NtpRemediation::IDS.include?(finding.id)
        NtpRemediation
      else
        SyslogRemediation
      end
      result = handler.new(policy: @policy).call(finding, audit)
      proposed = result.operations
      rendered = proposed.flat_map do |operation|
        @renderer.render(operation, verified_ntp_key_ids: result.details.fetch(:verified_ntp_key_ids, []),
          verified_ntp_slots: result.details.fetch(:verified_ntp_slots, []))
      end
      operations.concat(proposed)
      steps.concat(rendered)
      check(finding, :planned, nil, operation_ids: proposed.map(&:id), details: result.details)
    rescue TargetRemediation::Blocked => error
      check(finding, :blocked, error.reason, requirements: error.requirements)
    rescue CommandRenderer::UnsupportedOperation
      check(finding, :blocked, :unsupported_setting)
    rescue ArgumentError
      check(finding, :blocked, :invalid_command_parameter)
    end

    # 任何子命令失败都不把该操作部分加入输出；未知服务状态单独保留。
    def compile_setting(finding, operations, steps)
      operation = ConfigurationOperation.new(kind: "setting", identity: { "rule" => finding.id }, before: finding.actual,
        after: finding.expected, risk: %w[ssh.enabled snmp.versions].include?(finding.id) && finding.severity != "critical" ? "high" : finding.severity)
      rendered = @renderer.render(operation)
      operations << operation
      steps.concat(rendered)
      unresolved = if finding.id == "services.disabled"
        finding.expected.reject { |name| [ true, false ].include?(finding.actual[name]) }.map { |name| "service_state:#{name}" }
      else []
      end
      check(finding, unresolved.empty? ? :planned : :blocked, unresolved.empty? ? nil : :service_state_unknown,
        operation_ids: [ operation.id ], requirements: unresolved)
    rescue CommandRenderer::UnsupportedOperation
      check(finding, :blocked, :unsupported_setting)
    rescue ArgumentError
      check(finding, :blocked, :invalid_command_parameter)
    end

    # 逐项状态保留原规则标识，便于与审计结果一一核对。
    def check(finding, status, reason, operation_ids: [], requirements: [], details: {})
      RemediationPlan::Check.new(id: finding.id, status: status, reason: reason, operation_ids: operation_ids, requirements: requirements, details: details)
    end
  end
end

# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "remediation_plan"

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
      "credentials.storage" => [ "replacement_credential_reference" ], "credentials.strength" => [ "replacement_credential_reference" ],
      "tacacs.minimum_servers" => [ "approved_tacacs_targets" ], "tacacs.servers" => [ "approved_tacacs_endpoints", "authentication_reference_evidence" ],
      "tacacs.login" => [ "approved_authentication_chain", "local_fallback_evidence" ],
      "tacacs.authorization" => [ "approved_authorization_chain" ], "tacacs.accounting" => [ "approved_accounting_chain" ],
      "tacacs.keys" => [ "replacement_credential_reference" ],
      "syslog.destinations" => [ "supported_resource_renderer" ], "ntp.associations" => [ "supported_resource_renderer" ],
      "tacacs.endpoints" => [ "supported_resource_renderer", "authentication_reference_evidence" ]
    })

    # 与本次审计绑定相同策略，禁止把其他策略的报告拿来生成方案。
    def initialize(policy:, renderer:)
      @policy, @renderer = policy, renderer
    end

    # 编译每项结果；独立可生成操作不受其他指标缺参影响。
    def call(audit)
      raise ArgumentError, "Remediation policy does not match audit" unless audit.policy_sha256 == @policy.sha256
      operations, steps = [], []
      checks = audit.findings.map do |finding|
        status = { pass: :not_needed, not_applicable: :not_applicable }[finding.status]
        if status
          check(finding, status, nil)
        elsif !audit.configuration.complete? || finding.status == :unknown
          reason = audit.configuration.complete? ? finding.reason : audit.configuration.status == :unsupported ? :unsupported_platform : :input_incomplete
          check(finding, :blocked, reason)
        elsif @renderer.supports?(finding.id)
          missing = @renderer.prerequisites(finding.id).reject do |fact, expected|
            audit.configuration.fact_known?(fact) && audit.configuration.fact(fact) == expected
          end.keys
          if missing.any?
            check(finding, :blocked, :unresolved_prerequisites, requirements: missing)
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

    # 任何子命令失败都不把该操作部分加入输出；未知服务状态单独保留。
    def compile_setting(finding, operations, steps)
      operation = ConfigurationOperation.new(kind: "setting", identity: { "rule" => finding.id }, before: finding.actual,
        after: finding.expected, risk: finding.severity)
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
    def check(finding, status, reason, operation_ids: [], requirements: [])
      RemediationPlan::Check.new(id: finding.id, status: status, reason: reason, operation_ids: operation_ids, requirements: requirements)
    end
  end
end

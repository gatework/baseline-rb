# frozen_string_literal: true

require_relative "audit"
require_relative "acl_reservations"
require_relative "remediation_planner"
require_relative "h3c/command_renderer"
require_relative "huawei/command_renderer"
require_relative "cisco_ios/command_renderer"
require_relative "cisco_nxos/command_renderer"
require_relative "palo_alto/command_renderer"
require_relative "hillstone/command_renderer"

module Baseline
  # 同一次解析产生审计与修正意图，不接受另一份配置拼接既有报告。
  class Remediation
    RENDERERS = { "h3c" => H3c::CommandRenderer, "huawei" => Huawei::CommandRenderer,
      "cisco_ios" => CiscoIos::CommandRenderer, "cisco_nxos" => CiscoNxos::CommandRenderer,
      "palo_alto" => PaloAlto::CommandRenderer, "hillstone" => Hillstone::CommandRenderer }.freeze

    # 查询的是实际生成覆盖，不将审计支持自动标记为生成支持。
    def self.capabilities(platform:)
      name = Audit.normalize_platform(platform)
      renderer = RENDERERS.fetch(name, CommandRenderer).new
      CtxParser::Immutable.copy(Audit.capabilities(platform: name).to_h do |id, capability|
        supported = capability[:status] != :unsupported && renderer.supports?(id)
        requirements = RemediationPlanner::REQUIREMENTS.fetch(id, [ "supported_rule_handler" ])
        if supported && id == "snmp.versions"
          requirements = [ "existing_v3_access_verified", "snmp_v3_group_reference", "existing_enabled_snmp_v3" ]
        elsif supported && SnmpAccessRemediation::IDS.include?(id)
          requirements = [ "fresh_acl_identity", "approved_access_limits", "global_acl_support_evidence", "explicit_targets_for_unbound_principals" ]
        elsif supported && AccessRemediation::IDS.include?(id)
          requirements = [ "fresh_acl_identity", "approved_access_limits", "access_targets_for_initial_binding", "resolved_endpoint_protocol_permissions" ]
          requirements += [ "vrf_scope_for_initial_binding" ] if name == "cisco_ios"
        elsif supported && SyslogRemediation::IDS.include?(id)
          requirements = [ "approved_syslog_targets", "maximum_targets_for_additions" ]
          requirements += [ "managed_scopes" ] if id == "syslog.destinations"
        elsif supported && NtpRemediation::IDS.include?(id)
          requirements = [ "approved_ntp_associations", "maximum_targets_for_net_additions", "authentication_dependencies" ]
          requirements += [ "managed_scopes" ] if id == "ntp.associations"
        elsif supported && TacacsRemediation::IDS.include?(id)
          requirements = %w[approved_tacacs_endpoints managed_scopes syntax_profile local_fallback_access_verified
            tacacs_key_compatibility_verified existing_scheme_role_key preserved_domain_references maximum_targets_for_net_additions]
        elsif capability[:status] != :unsupported && AuthenticationRemediation::ROLES.key?(id) && %w[h3c huawei].include?(name)
          requirements = AuthenticationRemediation.requirements_for(id)
        end
        reason = if capability[:status] != :unsupported && CredentialRemediation::IDS.include?(id)
          id == "credentials.storage" ? :credential_rotation_required : :credential_strength_verification_required
        elsif capability[:status] != :unsupported && id == "tacacs.keys" && %w[h3c huawei].include?(name)
          :credential_material_required
        elsif capability[:status] != :unsupported && AuthenticationRemediation::ROLES.key?(id) && %w[h3c huawei].include?(name)
          :authentication_chain_approval_required
        else
          supported ? nil : capability[:reason] || :remediation_unmodeled
        end
        [ id, { status: supported ? :conditional : :unsupported,
          reason: reason,
          requirements: requirements, prerequisites: renderer.prerequisites(id) } ]
      end)
    end

    # 审计与规划器共用同一冻结策略。
    def initialize(policy:)
      @policy = policy
      @audit = Audit.new(policy: policy)
    end

    # 只生成审核产物，不读取文件、访问设备或提交配置。
    def call(configuration:, platform:, complete: false, context: {})
      snapshot = configuration.is_a?(String) ? configuration.dup.freeze : configuration
      audit = @audit.call(configuration: snapshot, platform: platform, complete: complete, context: context)
      renderer = RENDERERS.fetch(audit.configuration.platform, CommandRenderer).new
      identifiers = @policy.rules.select(&:enabled?).flat_map { |rule| rule.remediation.fetch("access_targets", []).map { |target| target.fetch("acl") } }
      reserved = audit.configuration.complete? ? AclReservations.from(configuration: snapshot, identifiers: identifiers) : nil
      RemediationPlanner.new(policy: @policy, renderer: renderer, reserved_acl_identifiers: reserved).call(audit)
    end

    # 不在调试输出中展示策略值或配置内容。
    def inspect = "#<#{self.class}>"
  end
end

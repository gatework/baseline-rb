# frozen_string_literal: true

module Baseline
  # 写权限审核保留具体主体和消费者，不用删除组或含秘密的配置绕过权限基线。
  class SnmpPermissionRemediation
    REQUIREMENTS = %w[approved_snmp_principal_permissions verified_vendor_permission_transition].freeze
    FACTS = %w[snmp.communities snmp.groups snmp.users].freeze

    # 只使用适配器提供的权限对象；不完整输入不能授权权限迁移。
    def self.applicable?(finding, evidence)
      finding.id == "snmp.write_enabled" && evidence.complete? && !finding.expected.nil? &&
        %i[fail unknown].include?(finding.status) && %i[deviation fact_unavailable].include?(finding.reason) &&
        FACTS.any? { |fact| evidence.fact(fact) }
    end

    # 已知授予与待核验对象分别列出，未声明写权限目标时不自动扩大权限。
    def call(finding, evidence)
      return { reason: :unsupported_setting, requirements: [ "approved_snmp_principal_permissions" ], details: {} } unless finding.expected == false

      communities = evidence.fact("snmp.communities") || []
      groups = evidence.fact("snmp.groups") || {}
      users = evidence.fact("snmp.users") || []
      definitions = evidence.fact("snmp.group_definitions") || []
      users_by_group = users.group_by { |entry| entry[:group] }
      definitions_by_group = definitions.group_by { |entry| entry[:name] }
      grants = communities.each_with_index.filter_map do |entry, index|
        next if entry[:write] == false
        known = entry[:write] == true
        { kind: "snmp.community", name: "community:#{index + 1}", action: known ? "replace_with_read_only" : "verify", risk: "high",
          lines: [ entry[:line] ].compact, permissions_known: !entry[:write].nil?,
          requirements: known ? %w[approved_replacement_credential manual_material_provisioning nms_consumer_update preserve_read_view_and_acl] : [ "snmp_permission_evidence" ],
          access: entry.slice(:read_view, :acl, :acl_ipv6) }
      end
      groups.each do |name, entry|
        next if entry[:write] == false
        grants << { kind: "snmp.group", name: name, action: entry[:write] == true ? "revoke_write" : "verify", risk: "high",
          lines: entry[:lines] || [ entry[:line] ].compact, permissions_known: !entry[:write].nil?,
          definitions: definitions_by_group.fetch(name, []).map { |definition| definition.slice(:name, :version, :security, :read_view, :write_view, :notify_view, :acl, :acl_ipv6, :line, :complete) },
          users: users_by_group.fetch(name, []).map { |user| user.slice(:name, :auth, :priv, :line, :acl, :acl_ipv6, :acl_chain) },
          requirements: %w[preserve_read_notify_views preserve_security_and_acl verified_vendor_permission_transition nms_consumer_update] }
      end
      users.each do |entry|
        next if entry[:write] == false || entry[:group] && groups.key?(entry[:group])
        grants << { kind: "snmp.user", name: entry[:name], action: "verify", risk: "high", lines: [ entry[:line] ].compact,
          permissions_known: false, requirements: %w[resolved_snmp_group_reference snmp_permission_evidence] }
      end
      grants.select { |grant| grant[:kind] == "snmp.group" }.each do |grant|
        grant[:requirements] << "snmp_group_definition_evidence" if grant[:definitions].empty? || grant[:definitions].any? { |definition| !definition[:complete] }
      end
      complete = FACTS.all? { |fact| evidence.fact_known?(fact) } && grants.all? { |grant| grant[:permissions_known] } && grants.none? { |grant| grant[:requirements].include?("snmp_group_definition_evidence") }
      requirements = self.class::REQUIREMENTS.dup
      requirements << "resolved_snmp_permission_inventory" unless complete
      requirements << "snmp_permission_evidence" if grants.empty?
      { reason: grants.any? { |grant| grant[:action] != "verify" } ? :snmp_permission_approval_required : :snmp_permission_evidence_required,
        requirements: requirements, details: { permission_grants: grants, inventory_complete: complete, risk: "high" } }
    end
  end
end

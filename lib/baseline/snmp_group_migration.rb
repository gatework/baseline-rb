# frozen_string_literal: true

require_relative "target_remediation"
require_relative "snmp_group_migration_schema"

module Baseline
  # 创建新只读组、迁移完整用户集合、最后删除旧组，避免组删除连带丢失材料。
  class SnmpGroupMigration
    Result = Data.define(:operations, :details)
    Blocked = TargetRemediation::Blocked

    def initialize(policy:) = @policy = policy

    def call(finding, audit)
      evidence = audit.configuration
      rule = @policy.rules.find { |item| item.id == finding.id }
      approval = rule.remediation
      raise Blocked, :unsupported_setting unless finding.expected == false
      unless evidence.complete? && %w[snmp.communities snmp.users snmp.groups snmp.group_definitions].all? { |fact| evidence.fact_known?(fact) } &&
          evidence.fact("snmp.permission_scope_complete") == true
        block!(:snmp_permission_evidence_required, "resolved_snmp_permission_inventory")
      end
      unless evidence.fact_known?("snmp.enabled") && evidence.fact("snmp.enabled") == true
        block!(:snmp_service_dependency, "snmp.enabled")
      end
      if audit.findings.any? { |item| item.id == "snmp.enabled" && item.status != :not_applicable && item.expected == false }
        raise Blocked, :policy_conflict
      end
      unless approval["snmp_group_migration_verified"] == true
        block!(:snmp_permission_approval_required, "snmp_group_migration_verified")
      end
      profile = approval["syntax_profile"]
      unless { "h3c" => "comware7", "huawei" => "vrp_v600" }[evidence.platform] == profile
        block!(:unsupported_setting, "native_snmp_permission_syntax_profile")
      end
      groups, users = evidence.fact("snmp.groups"), evidence.fact("snmp.users")
      definitions = evidence.fact("snmp.group_definitions")
      users_by_group = users.group_by { |user| user[:group] }
      definitions_by_group = definitions.group_by { |row| row[:name] }
      if evidence.fact("snmp.communities").any? { |community| community[:write] != false }
        block!(:snmp_permission_approval_required, "snmp_community_material_provisioning")
      end
      unless groups.values.all? { |group| [ true, false ].include?(group[:write]) } &&
          users.all? { |user| groups.key?(user[:group]) } && definitions.all? { |row| row[:complete] && row[:version] == "v3" }
        block!(:snmp_permission_evidence_required, "resolved_snmp_permission_inventory")
      end
      migrations = approval.fetch("group_migrations")
      writable = groups.select { |_, group| group[:write] == true }.keys.sort
      unless writable == migrations.map { |value| value["from_group"] }.sort
        block!(:snmp_permission_approval_required, "complete_writable_snmp_group_scope")
      end
      occupied = groups.keys + users.filter_map { |user| user[:group] }
      if migrations.any? { |value| occupied.any? { |name| name.casecmp?(value["to_group"]) } }
        block!(:snmp_group_identity_in_use, "fresh_snmp_group_identity")
      end
      risk = finding.severity == "critical" ? "critical" : "high"
      operations = migrations.flat_map do |migration|
        from, to = migration.values_at("from_group", "to_group")
        members = users_by_group.fetch(from, []).map { |user| user[:name] }.sort
        unless members == migration["users"].sort
          block!(:snmp_consumer_scope_mismatch, "complete_matching_snmp_users")
        end
        if members.any? && profile == "comware7"
          block!(:snmp_permission_approval_required, "snmp_user_material_provisioning")
        end
        if members.any? && approval["snmp_user_group_transition_verified"] != true
          block!(:snmp_permission_approval_required, "snmp_user_group_transition_verified")
        end
        rows = definitions_by_group.fetch(from, [])
        if rows.empty? || rows.map { |row| row[:security] }.uniq.size != rows.size
          block!(:snmp_permission_evidence_required, "resolved_snmp_group_definitions")
        end
        scope = { "syntax_profile" => profile }
        created, removed = [], []
        rows.each do |row|
          fields = row.slice(*SnmpGroupMigrationSchema::FIELDS.map(&:to_sym)).transform_keys(&:to_s)
          created << ConfigurationOperation.new(kind: "snmp.group", identity: { "name" => to, "security" => row[:security] }, scope: scope,
            before: nil, after: fields.except("write_view"), action: :add, phase: :create, risk: risk)
          removed << ConfigurationOperation.new(kind: "snmp.group", identity: { "name" => from, "security" => row[:security] }, scope: scope,
            before: fields, after: nil, action: :remove, phase: :remove, risk: risk)
        end
        bindings = members.map do |name|
          ConfigurationOperation.new(kind: "snmp.user_group", identity: { "name" => name }, scope: scope,
            before: { "group" => from }, after: { "group" => to }, action: :replace, phase: :update, risk: risk)
        end
        created + bindings + removed
      end
      slots = approval["available_group_slots"]
      block!(:capacity_confirmation_required, "available_snmp_group_slots") unless slots
      required = operations.count { |operation| operation.action == :add }
      raise Blocked, :capacity_exceeded if required > slots
      Result.new(operations: operations.freeze, details: CtxParser::Immutable.copy({ migrated_groups: migrations.size,
        migrated_users: operations.count { |operation| operation.kind == "snmp.user_group" }, preserved_material: true,
        required_group_slots: required, available_group_slots: slots,
        verification_scope: :complete_configured_principals_and_external_native_transition }))
    end

    private

    def block!(reason, *requirements) = raise Blocked.new(reason, requirements: requirements)
  end
end

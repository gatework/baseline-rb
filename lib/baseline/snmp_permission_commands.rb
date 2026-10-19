# frozen_string_literal: true

require_relative "snmp_group_migration_schema"

module Baseline
  # 非秘密权限命令只能来自完整迁移计划，禁止独立假定用户材料与共享范围已核验。
  module SnmpPermissionCommands
    private

    def render_snmp_permission(operation, verified_ids:)
      unless verified_ids.is_a?(Array) && verified_ids.all? { |id| id.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(id) }
        raise ArgumentError, "Invalid verified SNMP permission operations"
      end
      profile = operation.scope.fetch("syntax_profile")
      unless self.class::SNMP_PERMISSION_PROFILES.include?(profile) && verified_ids.include?(operation.id)
        raise CommandRenderer::UnsupportedOperation, "snmp_permission_preconditions_unverified"
      end
      if operation.kind == "snmp.user_group"
        raise CommandRenderer::UnsupportedOperation, "snmp_user_material_required" unless profile == "vrp_v600"
        command = "snmp-agent usm-user v3 #{operation.identity['name']} group #{operation.after['group']}"
      else
        security = operation.identity.fetch("security")
        target = "snmp-agent group v3 #{operation.identity['name']}#{security == 'noauthentication' && profile == 'comware7' ? '' : " #{security}"}"
        if operation.action == :remove
          command = "undo #{target}"
        else
          fields = operation.after
          if profile == "vrp_v600" && fields.key?("acl_ipv6")
            raise CommandRenderer::UnsupportedOperation, "unsupported_snmp_permission_options"
          end
          tail = %w[read_view notify_view].filter_map { |field| "#{field.tr('_', '-')} #{fields[field]}" if fields.key?(field) }
          %w[acl acl_ipv6].each do |field|
            next unless fields.key?(field)
            value = fields[field]
            numeric = /\A\d+\z/.match?(value)
            raise ArgumentError, "Invalid SNMP permission ACL" if numeric && !value.to_i.between?(2000, 3999)
            keyword = field == "acl" ? "acl" : "acl ipv6"
            qualifier = profile == "comware7" && !numeric ? "name " : ""
            tail << "#{keyword} #{qualifier}#{value}"
          end
          command = [ target, *tail ].join(" ")
        end
      end
      [ CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) ]
    end
  end
end

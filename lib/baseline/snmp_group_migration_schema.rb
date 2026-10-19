# frozen_string_literal: true

module Baseline
  # 仅允许非秘密组迁移，不接受密码、任意选项或命令模板。
  module SnmpGroupMigrationSchema
    KINDS = %w[snmp.group snmp.user_group].freeze
    LEVELS = %w[noauthentication authentication privacy].freeze
    PROFILES = %w[comware7 vrp_v600].freeze
    FIELDS = %w[read_view write_view notify_view acl acl_ipv6].freeze

    def self.name?(value) = value.is_a?(String) && value.bytesize.between?(1, 32) && /\A[a-zA-Z0-9_][a-zA-Z0-9_.-]*\z/.match?(value)

    def self.validate_approvals!(values)
      valid = values.is_a?(Array) && values.all? do |value|
        value.is_a?(Hash) && value.keys.sort == %w[from_group to_group users] &&
          name?(value["from_group"]) && name?(value["to_group"]) && !value["from_group"].casecmp?(value["to_group"]) &&
          value["users"].is_a?(Array) && value["users"].all? { |name| name?(name) } && value["users"].uniq == value["users"]
      end
      if valid
        names = values.flat_map { |value| value.values_at("from_group", "to_group") }.map(&:downcase)
        valid = names.uniq.size == names.size
      end
      raise ArgumentError, "Invalid SNMP group migrations" unless valid
    end

    def self.validate!(kind:, identity:, scope:, before:, after:, action:, phase:)
      valid = scope.is_a?(Hash) && scope.keys == [ "syntax_profile" ] && PROFILES.include?(scope["syntax_profile"])
      if kind == "snmp.group"
        valid &&= identity.is_a?(Hash) && identity.keys.sort == %w[name security] && name?(identity["name"]) && LEVELS.include?(identity["security"])
        valid &&= action == :add && before.nil? && after.is_a?(Hash) && !after.key?("write_view") && phase == :create ||
          action == :remove && before.is_a?(Hash) && after.nil? && phase == :remove
        valid &&= [ before, after ].compact.all? { |fields| (fields.keys - FIELDS).empty? && fields.values.all? { |value| name?(value) } }
      else
        valid &&= kind == "snmp.user_group" && identity.is_a?(Hash) && identity.keys == [ "name" ] && name?(identity["name"]) &&
          action == :replace && phase == :update && before != after &&
          [ before, after ].all? { |value| value.is_a?(Hash) && value.keys == [ "group" ] && name?(value["group"]) }
      end
      raise ArgumentError, "Invalid SNMP permission operation" unless valid
      true
    end
  end
end

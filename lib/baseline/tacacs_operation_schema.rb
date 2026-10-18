# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 主服务器用物理槽位标识，不能把新旧地址拆成会互相删除的两份对象。
  module TacacsOperationSchema
    KINDS = %w[tacacs.primary tacacs.secondary].freeze
    ROLES = %w[authentication authorization accounting].freeze

    # 操作只包含端点参数；不存在秘密、模板创建或任意视图路径。
    def self.validate!(kind:, identity:, scope:, before:, after:, action:, phase:)
      shape = action == :add && before.nil? && after.is_a?(Hash) && phase == :create ||
        action == :remove && before.is_a?(Hash) && after.nil? && %i[prepare remove].include?(phase) ||
        action == :replace && before.is_a?(Hash) && after.is_a?(Hash) && phase == :update
      valid = shape && identity.is_a?(Hash) && ROLES.include?(identity["role"]) && scope.is_a?(Hash) && scope.keys == [ "group" ] &&
        ResourceSchema.token?(scope["group"]) && scope["group"].bytesize <= 32
      if kind == "tacacs.primary"
        valid &&= identity.keys == [ "role" ] && [ before, after ].compact.all? { |value| endpoint?(value) }
      elsif kind == "tacacs.secondary"
        valid &&= identity.keys.sort == %w[address port role vrf] && endpoint?(identity.except("role").merge("single_connection" => false)) &&
          [ before, after ].compact.all? { |value| value.keys == [ "single_connection" ] && [ true, false ].include?(value["single_connection"]) }
      else
        valid = false
      end
      raise ArgumentError, "Invalid TACACS endpoint operation" unless valid
      true
    end

    # 路由域保留为类型字段，由具体厂商拒绝尚未验证的原生命令组合。
    def self.endpoint?(value)
      value.is_a?(Hash) && value.keys.sort == %w[address port single_connection vrf] && ResourceSchema.address?(value["address"]) &&
        value["port"].is_a?(Integer) && value["port"].between?(1, 65_535) && ResourceSchema.token?(value["vrf"]) &&
        [ true, false ].include?(value["single_connection"])
    end
  end
end

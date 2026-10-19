# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 迁移只批准既有匹配项的接收成员，不允许携带过滤式、动作或规则重绑命令。
  module SyslogReferenceSchema
    def self.reference?(value)
      return false unless value.is_a?(Hash)
      fields = value["kind"] == "syslog.device" ? %w[kind log_type match] : %w[kind log_type match forwarding_profile]
      types = value["kind"] == "syslog.device" ? ResourceBindings::SYSLOG_DEVICE_TYPES : ResourceBindings::SYSLOG_FORWARD_TYPES
      %w[syslog.device syslog.forwarding].include?(value["kind"]) && value.keys.sort == fields.sort &&
        types.include?(value["log_type"]) && (fields - %w[kind log_type]).all? { |field| ResourceSchema.name?(value[field]) }
    end

    # 每个来源只能有一个去向；共享匹配项的完整消费者批准由规划时的事实验证。
    def self.validate_migrations!(values)
      valid = values.is_a?(Array) && values.all? do |value|
        next false unless value.is_a?(Hash) && (value.keys - %w[from_profile to_profile reference consumers]).empty? &&
          (%w[from_profile to_profile reference] - value.keys).empty? && reference?(value["reference"])
        members = value.values_at("from_profile", "to_profile")
        next false if members.uniq.size == 1 || !members.all? { |name| name.nil? || ResourceSchema.name?(name) }
        if value.key?("consumers")
          next false unless value["reference"]["kind"] == "syslog.forwarding"
          ResourceBindings.validate!("syslog.destination", value["consumers"])
          value["consumers"].all? do |binding|
            %w[syslog.forwarding syslog.zone].include?(binding["kind"]) &&
              binding.slice("forwarding_profile", "match", "log_type") == value["reference"].slice("forwarding_profile", "match", "log_type")
          end
        else true
        end
      end
      keys = values.map { |value| [ value["reference"], value["from_profile"] ] } if valid
      raise ArgumentError, "Invalid Syslog binding migrations" unless valid && keys.uniq.size == keys.size
      true
    end

    # 原子替换包含完整前后成员集合，供操作指纹和独立呈现器校验。
    def self.validate_operation!(identity:, scope:, before:, after:, action:, phase:)
      valid = reference?(identity) && scope == {} && action == :replace && phase == :update && before != after &&
        [ before, after ].all? do |value|
          value.is_a?(Hash) && value.keys == [ "profiles" ] && value["profiles"].is_a?(Array) &&
            value["profiles"].all? { |name| ResourceSchema.name?(name) } && value["profiles"].uniq == value["profiles"]
        end
      raise ArgumentError, "Invalid Syslog reference operation" unless valid
      true
    end
  end
end

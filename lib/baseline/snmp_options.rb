# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 按参数位置消费 SNMP 选项，视图名、组名及秘密值不能被误当 ACL 关键字。
  module SnmpOptions
    LEVELS = %w[authentication privacy noauthentication].freeze
    USER_KEYS = %w[group authentication-mode privacy-mode acl local engineid remote cipher simple user-role].freeze

    # 只保留非秘密字段；组的各安全级别定义不能按名称静默合并。
    def self.group(settings)
      parts = settings.split
      security = LEVELS.include?(parts.first) ? parts.shift : "noauthentication"
      parse_access(parts, { security: security }, { "read-view" => :read_view, "write-view" => :write_view, "notify-view" => :notify_view })
    end

    # 团体字值已由调用者移除，选项仍须完整消费。
    def self.community(settings)
      parse_access(settings.split, {}, { "mib-view" => :read_view })
    end

    # 秘密参数只跳过，不进入返回值；组与密钥分行的 VRP 保持增量语义。
    def self.user(settings, group_required:)
      parts, result = settings.split, {}
      if group_required
        return { complete: false } unless parts.any? && parts.first != "user-role"
        result[:group] = parts.shift
      elsif parts.first == "group"
        parts.shift
        result[:group] = parts.shift
        return { complete: false } unless result[:group]
      elsif parts.any? && !USER_KEYS.include?(parts.first)
        result[:group] = parts.shift
      end
      access, seen = [], []
      until parts.empty?
        key = parts.shift
        case key
        when "authentication-mode", "privacy-mode"
          return result.merge(complete: false) if seen.include?(key) || parts.empty?
          seen << key
          parts.shift # 算法及秘密由专门的凭据分析校验，不保留到访问字段。
          parts.shift if %w[cipher simple].include?(parts.first)
          return result.merge(complete: false) unless parts.shift
        when "cipher", "simple"
          return result.merge(complete: false) if result.key?(:key_format)
          result[:key_format] = key
        when "local"
          next
        when "engineid"
          return result.merge(complete: false) unless parts.shift
        when "remote"
          parts.shift if parts.first == "ipv6"
          return result.merge(complete: false) unless parts.shift
          if parts.first == "vpn-instance"
            parts.shift
            return result.merge(complete: false) unless parts.shift
          end
        when "acl"
          access << key
          access << parts.shift if %w[ipv4 ipv6].include?(parts.first)
          access << parts.shift if parts.first == "name"
          return result.merge(complete: false) unless parts.any?
          access << parts.shift
        else
          return result.merge(complete: false)
        end
      end
      parse_access(access, result, {})
    end

    # 每类 ACL 只允许一个值；未知、缺值或重复选项保持未解决。
    def self.parse_access(parts, result, views)
      until parts.empty?
        option = parts.shift
        if views.key?(option)
          key = views.fetch(option)
        elsif %w[acl acl-ipv4 acl-ipv6].include?(option)
          family = option == "acl-ipv6" ? "ipv6" : "ipv4"
          family = parts.shift if option == "acl" && %w[ipv4 ipv6].include?(parts.first)
          parts.shift if parts.first == "name"
          key = family == "ipv6" ? :acl_ipv6 : :acl
        else
          return result.merge(complete: false)
        end
        value = parts.shift
        return result.merge(complete: false) unless ResourceSchema.token?(value) && !result.key?(key)
        result[key] = value
      end
      result.merge(complete: true)
    end
    private_class_method :parse_access
  end
end

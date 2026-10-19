# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 管理域登录方法只承载非秘密引用；批准的新链必须保留明确的本地恢复路径。
  module AaaChainSchema
    IDS = { "tacacs.login" => "authentication", "tacacs.authorization" => "authorization", "tacacs.accounting" => "accounting" }.freeze
    KIND = "aaa.login_chain"
    APPROVALS = %w[management_domain methods syntax_profile local_fallback_access_verified management_consumers_verified tacacs_peer_compatibility_verified].freeze

    def self.name?(value) = ResourceSchema.token?(value) && value.bytesize <= 32

    def self.methods?(value, approved: false, syntax_profile: nil)
      return false unless value.is_a?(Array) && value.any? && value.all? do |method|
        method.is_a?(Hash) && (method.keys == [ "kind" ] && %w[local none].include?(method["kind"]) ||
          syntax_profile == "vrp_s_series" && method == { "kind" => "local", "case_sensitive" => true } ||
          method.keys.sort == %w[group kind] && %w[tacacs radius ldap].include?(method["kind"]) && name?(method["group"]))
      end
      kinds = value.map { |method| method["kind"] }
      kinds.uniq == kinds && (!approved || [ [ "local" ], %w[tacacs local] ].include?(kinds))
    end

    def self.validate_approval!(value)
      valid = (!value.key?("management_domain") || name?(value["management_domain"])) &&
        (!value.key?("methods") || methods?(value["methods"], approved: true, syntax_profile: value["syntax_profile"]))
      raise ArgumentError, "Invalid management method approval" unless valid
    end

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      valid = identity.is_a?(Hash) && identity.keys == [ "role" ] && IDS.value?(identity["role"]) &&
        scope.is_a?(Hash) && scope.keys.sort == %w[domain syntax_profile] && name?(scope["domain"]) && scope["syntax_profile"] == "comware7" &&
        action == :replace && phase == :activate && before.is_a?(Hash) && before.keys.sort == %w[inherited methods] &&
        [ true, false ].include?(before["inherited"]) && methods?(before["methods"]) &&
        after.is_a?(Hash) && after.keys == [ "methods" ] && methods?(after["methods"], approved: true)
      raise ArgumentError, "Invalid management method operation" unless valid
    end
  end
end

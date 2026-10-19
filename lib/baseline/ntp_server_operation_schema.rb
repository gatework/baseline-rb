# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 地址级原生服务器操作把可变路由域纳入前后状态，避免增删同一地址互相覆盖。
  module NtpServerOperationSchema
    KIND = "ntp.server"

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      shape = action == :add && before.nil? && after.is_a?(Hash) && phase == :create ||
        action == :remove && before.is_a?(Hash) && after.nil? && %i[prepare remove].include?(phase) ||
        action == :replace && before.is_a?(Hash) && after.is_a?(Hash) && phase == :update
      unless shape && scope == {} && identity.is_a?(Hash) && identity.keys.sort == %w[address role] && identity["role"] == "server"
        raise ArgumentError, "Invalid native NTP server operation"
      end
      [ before, after ].compact.each do |value|
        raise ArgumentError, "Native NTP routing scope required" unless value.key?("vrf")
        if value["vrf"] != "default" && value["vrf_explicit"] == false
          raise ArgumentError, "Conflicting native NTP routing mode"
        end
        if value.key?("vrf_explicit") && ![ true, false ].include?(value["vrf_explicit"])
          raise ArgumentError, "Invalid native NTP routing mode"
        end
        ResourceSchema.validate!(kind: "ntp.association", identity: identity, scope: { "vrf" => value["vrf"] },
          attributes: value.except("vrf", "vrf_explicit"), lines: [], complete: true)
      end
      true
    end
  end
end

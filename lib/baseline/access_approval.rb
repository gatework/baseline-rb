# frozen_string_literal: true

require_relative "acl"
require_relative "resource_schema"

module Baseline
  # 批准的目标按实际 VTY 范围声明，不接受任意视图或命令模板。
  module AccessApproval
    # 返回可比较范围；无界、倒序和视图逃逸均拒绝。
    def self.range(name)
      match = name.is_a?(String) && /\A(?:line|user-interface) vty (\d+)(?: (\d+))?\z/.match(name)
      return unless match
      first, last = match[1].to_i, (match[2] || match[1]).to_i
      [ first, last ] if first <= last && last <= 65_535
    end

    # 同一 ACL 标识只批准给一个端点，避免意外建立共享生命周期。
    def self.validate!(targets, domain: :management)
      unless targets.is_a?(Array) && targets.all? do |target|
        target.is_a?(Hash) && (target.keys - %w[endpoint acl sources vrf_also]).empty? && (domain == :snmp ? target["endpoint"] == "snmp.global" && !target.key?("vrf_also") : range(target["endpoint"])) && ResourceSchema.token?(target["acl"]) &&
          (!target.key?("vrf_also") || [ true, false ].include?(target["vrf_also"])) &&
          (!target.key?("sources") || target["sources"].is_a?(Array) && target["sources"].all? { |network| network.is_a?(String) && Acl.ipv4_range(network) })
      end
        raise ArgumentError, "Invalid ACL access targets"
      end
      unless targets.map { |target| target["endpoint"] }.uniq.size == targets.size && targets.map { |target| target["acl"] }.uniq.size == targets.size
        raise ArgumentError, "Duplicate ACL access target"
      end
      true
    rescue IPAddr::Error
      raise ArgumentError, "Invalid ACL access target network"
    end
  end
end

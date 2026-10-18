# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "target_remediation"

module Baseline
  # 按实际 VTY 范围修正协议，不重写登录方式和已有 ACL。
  class VtyRemediation
    # 仅支持收紧到 SSH，不从布尔 false 推导应该开放哪些替代协议。
    def call(finding, audit)
      raise TargetRemediation::Blocked, :approved_protocols_required unless finding.expected == true
      enabled = audit.findings.find { |item| item.id == "ssh.enabled" && item.status != :not_applicable }
      raise TargetRemediation::Blocked, :policy_conflict if enabled&.expected == false
      evidence = audit.configuration
      raise TargetRemediation::Blocked, :vty_scope_unresolved unless evidence.fact_known?("ssh.vty")
      vtys = evidence.fact("ssh.vty")
      unless vtys.is_a?(Array) && vtys.any? && disjoint_ranges?(vtys)
        raise TargetRemediation::Blocked, :vty_scope_unresolved
      end
      vtys.filter_map do |vty|
        protocols = vty[:protocols]
        unless protocols.is_a?(Array) && protocols.any? && (protocols - %w[all none ssh stelnet telnet]).empty?
          raise TargetRemediation::Blocked, :vty_scope_unresolved
        end
        next if (protocols - %w[ssh stelnet]).empty?
        required = { "h3c" => "scheme", "huawei" => "aaa" }[evidence.platform]
        if required && vty[:local_authentication] != required
          raise TargetRemediation::Blocked, :vty_authentication_dependency
        end
        ConfigurationOperation.new(kind: "setting", identity: { "rule" => finding.id }, scope: { "vty" => vty.fetch(:name) },
          before: false, after: true, risk: finding.severity == "critical" ? "critical" : "high")
      end
    end

    private

    # 不明确的重复或交叠范围拒绝整项操作，避免声明顺序改变实际覆盖。
    def disjoint_ranges?(vtys)
      ranges = vtys.map do |vty|
        name = vty.is_a?(Hash) && vty[:name]
        match = name.is_a?(String) && /\A(?:line|user-interface) vty (\d+)(?: (\d+))?\z/.match(name)
        return false unless match
        first, last = match[1].to_i, (match[2] || match[1]).to_i
        return false unless first <= last && last <= 65_535
        [ first, last ]
      end.sort
      ranges.each_cons(2).all? { |left, right| left[1] < right[0] }
    end
  end
end

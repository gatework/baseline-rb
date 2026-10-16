# frozen_string_literal: true

module Baseline
  # 在归一化配置中区分输入完整性、已知事实与局部不支持的语法。
  class Configuration
    PARTIAL_SCOPE_FACTS = { "snmp.enabled" => true, "snmp.community_present" => true, "credentials.present" => true,
      "snmp.write_enabled" => true, "credentials.storage_safe" => false }.freeze
    attr_reader :platform, :sha256, :status, :facts, :sources, :issues

    # 冻结配置事实及其平台、来源身份。
    def initialize(platform:, sha256:, result:)
      @platform, @sha256, @status = platform.dup.freeze, sha256.dup.freeze, result.status
      record = result.records.first || {}
      @facts = Baseline.immutable(record.fetch("facts", {}))
      @sources = Baseline.immutable(record.fetch("sources", {}))
      @issues = Baseline.immutable(result.issues)
      freeze
    end

    # 判断配置采集与解析是否均已完成。
    def complete? = status == :complete
    # 读取已知值，同时保留事实缺失或未知的区别。
    def value(path) = facts[path]

    # 区分明确已知的事实与缺失、不支持的配置证据。
    def known?(path)
      facts.key?(path) && issues.none? do |issue|
        scope = issue[:fact]
        scope && (path == scope || path.start_with?("#{scope}."))
      end
    end

    # 局部输入可证明存在或明确违规，但不能证明缺失或所有成员均满足条件。
    def scope_known?(path)
      return false unless known?(path)
      return true if complete?
      return false unless status == :partial

      path == "hostname" || PARTIAL_SCOPE_FACTS.key?(path) && PARTIAL_SCOPE_FACTS[path] == value(path)
    end

    # 返回公开的数据结构，并保留状态与诊断信息。
    def to_h
      { platform: platform, sha256: sha256, status: status, facts: facts, sources: sources, issues: issues }
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} platform=#{platform} status=#{status} facts=#{facts.size}>"
  end
end

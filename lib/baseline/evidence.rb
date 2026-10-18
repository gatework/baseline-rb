# frozen_string_literal: true

require "ctx_parser/immutable"

module Baseline
  # 在归一化配置中区分输入完整性、已知事实与局部不支持的语法。
  class Evidence
    PARTIAL_SCOPE_FACTS = { "snmp.enabled" => true, "snmp.community_present" => true, "credentials.present" => true,
      "snmp.write_enabled" => true, "credentials.storage_safe" => false }.freeze
    attr_reader :platform, :sha256, :status, :facts, :sources, :issues

    # 冻结配置事实及其平台、来源身份。
    def initialize(platform:, sha256:, result:, input_complete: result.status == :complete)
      raise ArgumentError, "Input completeness must be boolean" unless input_complete == true || input_complete == false
      @input_complete = input_complete
      @platform, @sha256, @status = platform.dup.freeze, sha256.dup.freeze, result.status
      record = result.records.first || {}
      @facts = CtxParser::Immutable.copy(record.fetch("facts", {}))
      @sources = CtxParser::Immutable.copy(record.fetch("sources", {}))
      @issues = CtxParser::Immutable.copy(result.issues)
      freeze
    end

    # 仅记录调用方是否确认完整接收；局部解析不支持仍会降低 complete?。
    def input_complete? = @input_complete

    # 判断配置采集与解析是否均已完成。
    def complete? = input_complete? && status == :complete
    # 读取已知值，同时保留事实缺失或未知的区别。
    def fact(path) = facts[path]

    # 区分明确已知的事实与缺失、不支持的配置证据。
    def fact_known?(path)
      facts.key?(path) && issues.none? do |issue|
        scope = issue[:fact]
        scope && (path == scope || path.start_with?("#{scope}."))
      end
    end

    # 局部输入可证明存在或明确违规，但不能证明缺失或所有成员均满足条件。
    def applicability_fact_known?(path)
      return false unless fact_known?(path)
      return true if complete?
      return false unless status == :partial

      path == "hostname" || PARTIAL_SCOPE_FACTS.key?(path) && PARTIAL_SCOPE_FACTS[path] == fact(path)
    end

    # 返回公开的数据结构，并保留状态与诊断信息。
    def to_h
      { platform: platform, sha256: sha256, status: status, input_complete: input_complete?, facts: facts, sources: sources, issues: issues }
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} platform=#{platform} status=#{status} facts=#{facts.size}>"
  end
end

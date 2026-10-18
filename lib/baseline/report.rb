# frozen_string_literal: true

require_relative "evidence"

require "ctx_parser/immutable"
require "json"

module Baseline
  # 分别报告评估结果与输入覆盖率；未知项不计分，也不视为合规。
  class Report
    REASONS = {
      resource_attribute_unresolved: "配置对象存在，但部分批准属性未显式声明且缺省值未经验证",
      resource_binding_unresolved: "对象绑定关系尚未完整解析，不能从对象存在推断使用链已满足要求",
      input_incomplete: "配置不完整，需提供完整备份后重查", unsupported_platform: "尚未支持此平台的配置语法",
      scope_mismatch: "不在策略适用范围内", scope_unknown: "缺少判断适用范围或选择批准值所需的上下文",
      policy_missing: "未定义当前范围的批准值，请完善基线策略", fact_unavailable: "配置事实缺失或包含尚未支持的语法，请查看解析诊断",
      unsupported_capability: "此厂商的当前适配器尚未建模该能力，不能据此声明合规",
      fact_type_mismatch: "解析事实类型与检查要求不一致", unnecessary_service_enabled: "存在策略要求关闭的服务",
      service_state_unknown: "配置未明确声明部分服务状态，不能推断厂商默认值", deviation: "实际配置偏离批准值",
      unsupported_address_family: "地址格式超出当前 IPv4 检查能力", weak_password: "发现未满足强度要求的明文凭据",
      password_strength_unobservable: "加密或散列凭据无法从备份验证原始口令强度"
    }.freeze

    Finding = Data.define(:id, :title, :severity, :status, :reason, :actual, :expected, :lines, :policy_path, :diagnostics, :details) do
      # 冻结单条检查结果的策略路径、诊断和支持细节。
      def initialize(policy_path: [], diagnostics: [], details: {}, **attributes)
        super(**CtxParser::Immutable.copy(attributes.merge(policy_path: policy_path, diagnostics: diagnostics, details: details)))
      end

      # 将稳定的结果原因代码转换为易读说明。
      def explanation = reason ? Report::REASONS.fetch(reason, reason.to_s) : "满足基线要求"
      # 返回公开的数据结构，并保留状态与诊断信息。
      def to_h = super.merge(explanation: explanation)

      # 生成紧凑的评估与策略路径元数据，不内嵌大量事实或诊断数组。
      def summary
        { id: id, title: title, severity: severity, status: status, reason: reason, policy_path: policy_path }
      end
    end
    attr_reader :configuration, :policy_sha256, :findings, :context, :counts, :applicable

    # 冻结报告证据与检查结果，便于复现评估。
    def initialize(configuration:, policy_sha256:, findings:, context:)
      @configuration, @policy_sha256 = configuration, policy_sha256
      @findings = findings.dup.freeze
      @context = CtxParser::Immutable.copy(context)
      @counts = @findings.map(&:status).tally.freeze
      @applicable = @findings.reject { |finding| finding.status == :not_applicable }.freeze
      freeze
    end

    # 判断所有已选事实是否都有完整证据支持。
    def complete? = configuration.complete? && applicable.any? && counts.fetch(:pass, 0) + counts.fetch(:fail, 0) == applicable.size
    # 仅在证据完整且检查通过时声明合规。
    def compliant? = complete? && counts.fetch(:pass, 0) == applicable.size

    # 推导汇总状态，避免将证据缺失当作成功。
    def status
      return :fail if counts.fetch(:fail, 0).positive?
      return :pass if compliant?
      :unknown
    end

    # 独立衡量已评估证据的覆盖情况，不与设备是否通过混淆。
    def coverage
      return 0.0 if applicable.empty?
      (100.0 * (counts.fetch(:pass, 0) + counts.fetch(:fail, 0)) / applicable.size).round(1)
    end

    # 计算适用规则中证据完整且检查通过的占比。
    def score
      return 0.0 if applicable.empty?
      (100.0 * counts.fetch(:pass, 0) / applicable.size).round(1)
    end

    # 返回公开的数据结构，并保留状态与诊断信息。
    def to_h
      metadata.merge(configuration: configuration.to_h, findings: findings.map(&:to_h))
    end

    # 限制摘要大小；完整事实由 to_h 提供，避免 ACL 或账号数量膨胀元数据。
    def summary
      metadata.merge(configuration: { platform: configuration.platform, sha256: configuration.sha256, status: configuration.status, input_complete: configuration.input_complete?,
        issue_counts: configuration.issues.map { |issue| issue[:code] }.tally },
        findings: findings.map(&:summary))
    end

    # 以有长度限制且经过转义的文本展示运维证据；完整结构仍保留在 JSON 中。
    def to_text
      output = [ "baseline: #{status}, coverage=#{coverage}%, score=#{score}, #{counts.map { |name, count| "#{name}=#{count}" }.join(', ')}",
        "配置: #{display(configuration.platform)}, #{configuration.status}; SHA256: #{configuration.sha256}",
        "策略 SHA256: #{policy_sha256}; 上下文: #{display(context)}" ]
      findings.each do |finding|
        output << "  [#{finding.status}] #{finding.id} | #{finding.title} | #{finding.severity}"
        output << "    #{finding.explanation}#{finding.reason ? " (#{finding.reason})" : ''}"
        output << "    策略分支: #{display(finding.policy_path)}" if finding.policy_path.any?
        if %i[pass fail].include?(finding.status)
          output << "    预期: #{display(finding.expected)}; 实际: #{display(finding.actual)}"
        end
        details = finding.details
        if (scope = details[:verification_scope])
          label = scope == :objects_only ? "仅对象定义，未核验使用链" : "对象定义及声明的绑定"
          output << "    核验范围: #{label}"
          details = details.reject { |key, value| key == :verification_scope || value.respond_to?(:empty?) && value.empty? }
        end
        output << "    差异: #{display(details)}" if details.any?
        if finding.lines.any?
          output << "    行号: #{finding.lines.first(20).join(', ')}#{finding.lines.size > 20 ? "… (共 #{finding.lines.size} 行，详见 JSON 报告)" : ''}"
        end
        finding.diagnostics.first(10).each { |issue| output << "    解析诊断: #{display(issue)}" }
        output << "    另有 #{finding.diagnostics.size - 10} 条诊断，详见 JSON 报告" if finding.diagnostics.size > 10
      end
      output.join("\n")
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} status=#{status} coverage=#{coverage} findings=#{findings.size}>"

    private

    # 提供来源与策略身份，便于复现并追溯报告。
    def metadata
      { status: status, complete: complete?, compliant: compliant?, score: score, coverage: coverage, counts: counts,
        policy_sha256: policy_sha256, context: context }
    end

    # 格式化报告值，不改变序列化后的评估契约。
    def display(value)
      text = JSON.generate(value)
      text.length > 500 ? "#{text[0, 500]}… (详见 JSON 报告)" : text
    end
  end
end

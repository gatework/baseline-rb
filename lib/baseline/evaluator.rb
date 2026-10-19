# frozen_string_literal: true

require_relative "policy"
require_relative "report"
require_relative "resource_comparison"

module Baseline
  # 根据策略评估归一化事实；厂商语法差异由解析器负责。
  class Evaluator
    # 绑定归一化证据评估使用的策略。
    def initialize(policy:)
      raise ArgumentError, "A baseline policy is required" unless policy.is_a?(Policy)
      @policy = policy
    end

    # 评估适用基线规则，分别报告合规结果与证据覆盖率。
    def call(configuration:, context: {})
      raise ArgumentError, "Invalid baseline context" unless context.is_a?(Hash)
      unless context.keys.all? { |key| key.is_a?(String) || key.is_a?(Symbol) } && context.keys.map(&:to_s).uniq.size == context.size
        raise ArgumentError, "Ambiguous baseline context"
      end
      context = context.transform_keys(&:to_s).merge("vendor" => configuration.platform)
      unless (context.keys - Policy::SCOPES).empty? && context.values.all? { |value| value.is_a?(String) && !value.strip.empty? }
        raise ArgumentError, "Invalid baseline context"
      end
      findings = @policy.rules.select(&:enabled?).map { |rule| evaluate(rule, configuration, context) }
      Report.new(configuration: configuration, policy_sha256: @policy.sha256, findings: findings, context: context)
    end

    private

    # 使用已知事实和解析后的策略值评估单条适用规则。
    def evaluate(rule, configuration, context)
      attributes = { id: rule.id, title: rule.title, severity: rule.severity, actual: nil, expected: nil,
        lines: configuration.sources.fetch(rule.fact, []), policy_path: [], details: {}, diagnostics: diagnostics(rule, configuration) }
      applicable = applicability(rule, configuration, context)
      return finding(attributes, :not_applicable, :scope_mismatch) if applicable == false
      unless configuration.complete? || configuration.status == :partial
        return finding(attributes, :unknown, configuration.status == :unsupported ? :unsupported_platform : :input_incomplete)
      end
      return finding(attributes, :unknown, :scope_unknown) if applicable.nil?
      resolution = @policy.resolve_with_path(rule, context)
      attributes[:policy_path] = resolution.path
      return finding(attributes, :unknown, resolution.reason) if resolution.reason
      expected = attributes[:expected] = resolution.value
      unless configuration.fact_known?(rule.fact)
        unavailable = attributes[:diagnostics].any? { |issue| issue[:code] == :unsupported_capability && issue[:fact] == rule.fact }
        reason = !configuration.complete? ? :input_incomplete : unavailable ? :unsupported_capability : :fact_unavailable
        return finding(attributes, :unknown, reason)
      end
      actual = configuration.fact(rule.fact)
      if ServerAddress::FACTS.include?(rule.fact)
        begin
          actual = ServerAddress.normalize_set(actual)
        rescue ArgumentError
          attributes[:actual] = actual
          return finding(attributes, :unknown, :fact_type_mismatch)
        end
      end
      attributes[:actual] = actual
      status, reason, details = compare(rule, actual, expected)
      attributes[:details] = details if rule.operator == :resources_match && details
      # 不完整输入不能证明通过；仅保留补充记录也无法推翻的明确违规。
      if !configuration.complete? && (status == :pass || status == :fail && !conclusive_violation?(rule, actual, expected, configuration))
        status, reason = :unknown, :input_incomplete
      end
      if status == :fail
        attributes[:details] = details || differences(rule.operator, actual, expected)
        # 尚未采集的配置可能补齐缺项，因此不将缺项作为已确认偏差展示。
        attributes[:details].delete(:missing) unless configuration.complete?
      end
      finding(attributes, status, reason)
    end

    # 采集尚未完成时，仅报告后续缺失记录也无法推翻的明确违规。
    def conclusive_violation?(rule, actual, expected, configuration)
      case rule.operator
      when :all_disabled, :subset, :password_strength then true
      when :networks_within then configuration.input_complete?
      when :set_equals then (actual - expected).any?
      when :equals
        rule.fact == "snmp.write_enabled" && actual == true && expected == false ||
          rule.fact == "credentials.storage_safe" && actual == false && expected == true
      else false
      end
    end

    # 按事实路径关联诊断，说明未知原因，同时避免泄露配置文本或凭据。
    def diagnostics(rule, configuration)
      scopes = [ rule.fact, *rule.applies_to.fetch("facts", {}).keys ]
      configuration.issues.select do |issue|
        fact = issue[:fact]
        !fact || scopes.any? { |scope| scope == fact || scope.start_with?("#{fact}.") || fact.start_with?("#{scope}.") }
      end
    end

    # 说明事实与策略的偏差，不改变比较结果。
    def differences(operator, actual, expected)
      case operator
      when :set_equals then { missing: expected - actual, unexpected: actual - expected }
      when :subset then { unexpected: actual - expected }
      when :count_at_least then { minimum: expected, actual_count: actual.uniq.size }
      when :all_disabled then { enabled: expected.select { |name| actual[name] == true } }
      else {}
      end
    end

    # 构造包含稳定状态和原因代码的规则检查结果。
    def finding(attributes, status, reason)
      Report::Finding.new(**attributes, status: status, reason: reason)
    end

    # 根据平台与设备上下文判断规则是否适用。
    def applicability(rule, configuration, context)
      unknown = false
      rule.applies_to.each do |key, expected|
        values = key == "facts" ? expected : { key => expected }
        values.each do |name, criterion|
          known = key == "facts" ? configuration.applicability_fact_known?(name) : context.key?(name)
          value = key == "facts" ? configuration.fact(name) : context[name]
          known &&= valid_scope_fact?(name, value) if key == "facts"
          if !known
            unknown = true
          elsif !(criterion.is_a?(Array) ? criterion.include?(value) : criterion == value)
            return false
          end
        end
      end
      unknown ? nil : true
    end

    # 错误类型的范围事实不能作为不匹配条件排除检查。
    def valid_scope_fact?(name, value)
      case Rule::APPLICABILITY_FACTS[name]
      when :boolean then value == true || value == false
      when :string then value.is_a?(String) && !value.strip.empty?
      else false
      end
    end

    # 按声明的比较运算符处理归一化策略值。
    def compare(rule, actual, expected)
      operator = rule.operator
      case operator
      when :resources_match
        return ResourceComparison.call(kind: ResourceSchema::FACTS.key(rule.id), actual: actual, expected: expected, managed_scopes: rule.managed_scopes)
      when :password_strength then return password_strength(actual, expected)
      when :all_disabled
        return [ :unknown, :fact_type_mismatch ] unless actual.is_a?(Hash)
        return [ :fail, :unnecessary_service_enabled ] if expected.any? { |name| actual[name] == true }
        return [ :unknown, :service_state_unknown ] unless expected.all? { |name| actual[name] == false }
        passed = true
      when :equals
        return [ :unknown, :fact_type_mismatch ] unless actual.class == expected.class || [ true, false ].include?(actual) && [ true, false ].include?(expected)
        passed = actual == expected
      else
        return [ :unknown, :fact_type_mismatch ] unless actual.is_a?(Array) && actual.all? { |item| item.is_a?(String) }
        passed = case operator
        when :subset then (actual - expected).empty?
        when :set_equals then actual.uniq.sort == expected.sort
        when :count_at_least then actual.uniq.size >= expected
        when :networks_within
          outside = Acl.unapproved_networks(actual, expected)
          details = { outside_approved: outside }
          outside.empty?
        end
      end
      [ passed ? :pass : :fail, passed ? nil : :deviation, details ]
    rescue ArgumentError, IPAddr::InvalidAddressError
      [ :unknown, :unsupported_address_family ]
    end

    # 检查可度量的凭据属性，不保存秘密值。
    def password_strength(actual, expected)
      return [ :unknown, :fact_type_mismatch ] unless actual.is_a?(Array)
      valid = actual.select { |item| valid_strength_attributes?(item) }
      visible = valid.select { |item| item[:storage] == "plaintext" }
      weak = visible.any? do |item|
        item[:common] || item.fetch(:length) < expected.fetch("min_length") || item.fetch(:character_classes) < expected.fetch("min_classes")
      end
      return [ :fail, :weak_password ] if weak
      return [ :unknown, :fact_type_mismatch ] if valid.size != actual.size
      return [ :unknown, :password_strength_unobservable ] if actual.empty? || visible.size != actual.size
      [ :pass, nil ]
    end

    # 公开事实入口可接受外部解析结果；损坏属性不能冒充可比较的口令证据。
    def valid_strength_attributes?(item)
      return false unless item.is_a?(Hash) && %w[plaintext legacy protected unknown].include?(item[:storage])
      return true unless item[:storage] == "plaintext"

      [ true, false ].include?(item[:common]) && item[:length].is_a?(Integer) && item[:length] >= 0 &&
        item[:character_classes].is_a?(Integer) && item[:character_classes].between?(0, 4)
    end
  end
end

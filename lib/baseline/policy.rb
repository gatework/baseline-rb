# frozen_string_literal: true

require_relative "rule"

require "yaml"
require "digest"
require "json"

module Baseline
  # 按主机、型号、站点、角色或厂商选择批准值；缺少批准值时不回退到当前配置。
  class Policy
    SCOPES = Rule::CONTEXT_FIELDS
    SELECTORS = CtxParser::Immutable.copy(SCOPES.map { |scope| "by_#{scope}" } + [ "default" ])
    Resolution = Data.define(:value, :reason, :path) do
      # 冻结解析后的批准值、原因及策略选择路径。
      def initialize(value:, reason:, path:)
        super(value: CtxParser::Immutable.copy(value), reason: CtxParser::Immutable.copy(reason), path: CtxParser::Immutable.copy(path))
      end
    end
    attr_reader :rules, :sha256

    # 加载 gem 内附带的默认策略。
    def self.default = load(File.expand_path("../../policy.yml", __dir__))

    # 读取并校验策略文档，禁止实例化任意 YAML 对象。
    def self.load(path)
      text = File.binread(path)
      raise ArgumentError, "Baseline policy is too large" if text.bytesize > 1_048_576
      stream = Psych.parse_stream(text)
      raise ArgumentError, "One baseline YAML document is required" unless stream.children.one?
      validate_yaml!(stream)
      new(YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: false))
    rescue Psych::Exception
      raise ArgumentError, "Invalid baseline YAML", cause: nil
    end

    # 反序列化前拒绝不安全或嵌套过深的 YAML 结构。
    def self.validate_yaml!(node, depth = 0)
      raise ArgumentError, "Baseline YAML nesting is too deep" if depth > 32
      if node.is_a?(Psych::Nodes::Alias)
        raise ArgumentError, "Baseline YAML aliases are not allowed"
      elsif node.is_a?(Psych::Nodes::Mapping)
        keys = node.children.each_slice(2).map(&:first)
        unless keys.all? { |key| key.is_a?(Psych::Nodes::Scalar) } && keys.map(&:value).uniq.size == keys.size
          raise ArgumentError, "Duplicate or complex baseline YAML keys"
        end
      end
      Array(node.children).each { |child| validate_yaml!(child, depth + 1) }
    end
    private_class_method :validate_yaml!

    # 在设备评估前校验并冻结策略定义。
    def initialize(definition)
      unless definition.is_a?(Hash) && (definition.keys - %w[version checks]).empty? &&
          definition["version"].is_a?(Integer) && definition["version"] == 1 &&
          definition["checks"].is_a?(Hash) && !definition["checks"].empty?
        raise ArgumentError, "Invalid baseline policy"
      end
      @rules = definition["checks"].map { |id, options| Rule.new(id, options) }.freeze
      rules.each { |rule| validate_selection!(rule, rule.expected) }
      @sha256 = Digest::SHA256.hexdigest(JSON.generate(definition)).freeze
      freeze
    end

    # 解析上下文对应的策略值，并保留选择路径。
    def resolve(rule, context)
      resolution = resolve_with_path(rule, context)
      [ resolution.value, resolution.reason ]
    end

    # 保留相对于 expected 的命中范围、默认分支或未解析选择器路径。
    def resolve_with_path(rule, context)
      value = rule.expected
      path = []
      while selector?(value)
        selected = false
        SCOPES.each do |scope|
          selector = "by_#{scope}"
          mapping = value[selector]
          next unless mapping
          return Resolution.new(value: nil, reason: :scope_unknown, path: path + [ selector ]) unless context.key?(scope)
          next unless mapping.key?(context[scope])
          path.concat([ selector, context[scope] ])
          value, selected = mapping[context[scope]], true
          break
        end
        unless selected
          path << "default" if value.key?("default")
          value = value["default"]
        end
      end
      Resolution.new(value: value, reason: value.nil? ? :policy_missing : nil, path: path)
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} rules=#{rules.size}>"

    private

    # 识别依赖上下文的策略选择器，避免当作普通值处理。
    def selector?(value) = value.is_a?(Hash) && (value.keys & SELECTORS).any?

    # 校验嵌套策略选择及其最终规则值。
    def validate_selection!(rule, value, depth = 0)
      raise ArgumentError, "Baseline scope nesting is too deep" if depth > 8
      return if value.nil?
      unless selector?(value)
        rule.validate_expected!(value)
        return
      end
      raise ArgumentError, "Invalid baseline selector" unless (value.keys - SELECTORS).empty?
      value.each do |key, selection|
        if key == "default"
          validate_selection!(rule, selection, depth + 1)
        else
          unless selection.is_a?(Hash) && !selection.empty? && selection.keys.all? { |name| name.is_a?(String) && !name.strip.empty? }
            raise ArgumentError, "Invalid baseline scope"
          end
          selection.each_value { |item| validate_selection!(rule, item, depth + 1) }
        end
      end
    end
  end
end

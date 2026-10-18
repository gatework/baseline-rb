# frozen_string_literal: true

require "digest"
require "json"
require "ctx_parser/immutable"
require_relative "rule"

module Baseline
  # 离线变更意图与厂商命令分离；标识只由不可变领域数据计算。
  class ConfigurationOperation
    attr_reader :id, :kind, :action, :identity, :scope, :before, :after, :phase, :risk

    # 设置操作目前只接受已声明规则，后续资源操作沿用相同身份契约。
    def initialize(kind:, identity:, before:, after:, scope: {}, action: :set, phase: :update, risk: "medium")
      unless kind == "setting" && identity.is_a?(Hash) && identity.keys == [ "rule" ] && Rule::DEFINITIONS.key?(identity["rule"]) &&
          action == :set && phase == :update && %w[low medium high critical].include?(risk) && scope == {}
        raise ArgumentError, "Invalid configuration operation"
      end
      Rule.new(identity.fetch("rule"), { "expected" => after }).validate_expected!(after)
      @kind, @identity, @scope, @before, @after, @risk = CtxParser::Immutable.copy([ kind, identity, scope, before, after, risk ])
      @action, @phase = action, phase
      @id = Digest::SHA256.hexdigest(JSON.generate(canonical([ @kind, @action, @identity, @scope, @before, @after, @phase, @risk ]))).freeze
      freeze
    end

    # 导出操作意图，尚未包含任何执行结果。
    def to_h = { id: id, kind: kind, action: action, identity: identity, scope: scope, before: before, after: after, phase: phase, risk: risk }
    # 调试输出不携带设备对象或批准值。
    def inspect = "#<#{self.class} kind=#{kind} action=#{action}>"

    private

    # 参数 Hash 的插入顺序不影响操作标识。
    def canonical(value)
      case value
      when Hash then value.keys.sort_by(&:to_s).to_h { |key| [ key, canonical(value[key]) ] }
      when Array then value.map { |item| canonical(item) }
      else value
      end
    end
  end
end

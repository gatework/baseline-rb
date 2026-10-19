# frozen_string_literal: true

require "ctx_parser/immutable"
require_relative "resource_schema"

module Baseline
  # 保留配置对象的身份与作用域，不把地址去重结果当成可删除的对象。
  class ConfigurationResource
    attr_reader :kind, :identity, :scope, :attributes, :lines, :bindings

    # 复制安全的领域字段；未知语法保留不完整标记供规划器拒绝变更。
    def initialize(kind:, identity:, scope: {}, attributes: {}, lines: [], complete: true, bindings: nil)
      ResourceSchema.validate!(kind: kind, identity: identity, scope: scope, attributes: attributes, lines: lines, complete: complete)
      identity, attributes = ServerAddress.normalize_fields(identity), ServerAddress.normalize_fields(attributes)
      @kind, @identity, @scope, @attributes, @lines = CtxParser::Immutable.copy([ kind, identity, scope, attributes, lines.uniq.sort ])
      ResourceBindings.validate!(kind, bindings) unless bindings.nil?
      @bindings = bindings.nil? ? nil : CtxParser::Immutable.copy(ResourceBindings.normalize(bindings))
      @complete = complete
      freeze
    end

    # 只有完整理解的对象才能进入可执行差异规划。
    def complete? = @complete
    # 身份不包含可修改属性，允许区分更新与对象替换。
    def key = [ kind, scope, identity ].freeze

    # 已拥有的身份和属性始终不可变；新增绑定只复制新证据，不重复解析端点。
    def with_bindings(bindings:, lines: self.lines)
      ResourceBindings.validate!(kind, bindings) unless bindings.nil?
      unless lines.is_a?(Array) && lines.all? { |line| line.is_a?(Integer) && line.positive? }
        raise ArgumentError, "Invalid configuration resource lines"
      end
      normalized = bindings.nil? ? nil : ResourceBindings.normalize(bindings)
      snapshot = CtxParser::Immutable.copy([ normalized, lines.uniq.sort ])
      dup.replace_binding_evidence(*snapshot)
    end

    # 仅导出校验后的领域数据，不包含原始命令或秘密。
    def to_h
      record = { kind: kind, identity: identity, scope: scope, attributes: attributes, lines: lines, complete: complete? }
      record[:bindings] = bindings unless bindings.nil?
      record
    end
    # 日常调试不打印设备对象身份。
    def inspect = "#<#{self.class} kind=#{kind} complete=#{complete?}>"

    protected

    # 仅接收 with_bindings 已校验并拥有的快照，保留其他冻结字段的身份。
    def replace_binding_evidence(bindings, lines)
      @bindings, @lines = bindings, lines
      freeze
    end
  end
end

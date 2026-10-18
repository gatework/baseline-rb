# frozen_string_literal: true

require "ctx_parser/immutable"
require_relative "resource_schema"

module Baseline
  # 保留配置对象的身份与作用域，不把地址去重结果当成可删除的对象。
  class ConfigurationResource
    attr_reader :kind, :identity, :scope, :attributes, :lines

    # 复制安全的领域字段；未知语法保留不完整标记供规划器拒绝变更。
    def initialize(kind:, identity:, scope: {}, attributes: {}, lines: [], complete: true)
      ResourceSchema.validate!(kind: kind, identity: identity, scope: scope, attributes: attributes, lines: lines, complete: complete)
      @kind, @identity, @scope, @attributes, @lines = CtxParser::Immutable.copy([ kind, identity, scope, attributes, lines.uniq.sort ])
      @complete = complete
      freeze
    end

    # 只有完整理解的对象才能进入可执行差异规划。
    def complete? = @complete
    # 身份不包含可修改属性，允许区分更新与对象替换。
    def key = [ kind, scope, identity ].freeze

    # 仅导出校验后的领域数据，不包含原始命令或秘密。
    def to_h = { kind: kind, identity: identity, scope: scope, attributes: attributes, lines: lines, complete: complete? }
    # 日常调试不打印设备对象身份。
    def inspect = "#<#{self.class} kind=#{kind} complete=#{complete?}>"
  end
end

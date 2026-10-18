# frozen_string_literal: true

require "ctx_parser/immutable"

module Baseline
  # 一条厂商命令及其视图来源；步骤数据本身不具有执行能力。
  class CommandStep < Data.define(:view, :command, :phase, :operation_id)
    # 只接受单行文本，避免将参数里的换行变成额外命令。
    def initialize(view:, command:, phase:, operation_id:)
      raise ArgumentError, "Invalid configuration command phase" unless %i[prepare create update remove verify].include?(phase)
      unless view.is_a?(Array) && [ *view, command, operation_id ].all? do |value|
        value.is_a?(String) && !value.empty? && !/[[:cntrl:]]/.match?(value)
      end
        raise ArgumentError, "Invalid configuration command step"
      end
      super(**CtxParser::Immutable.copy({ view: view, command: command, phase: phase, operation_id: operation_id }))
    end

    # 不将配置命令打印到普通调试输出。
    def inspect = "#<#{self.class} phase=#{phase}>"
  end
end

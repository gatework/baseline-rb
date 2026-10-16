# frozen_string_literal: true

require_relative "document"

module Baseline
  # 多行引号内容始终作为数据处理，即使正文看起来像全局命令。
  class QuotedDocument < Document
    protected

    # 区分配置结构行与引号、横幅中的文本内容。
    def classify(line)
      was_quoted = !@quote.nil?
      # 注释和横幅具有独立语法，其中的单引号不能开启配置值。
      unless was_quoted
        kind = super
        return kind unless kind == :entry && line.text.match?(/["']/)
      end
      escaped = false
      line.text.each_char do |character|
        if escaped
          escaped = false
        elsif character == "\\"
          escaped = true
        elsif @quote
          @quote = nil if character == @quote
        elsif character == '"' || character == "'"
          @quote = character
        end
      end
      if !was_quoted && @quote && multiline_fact?(line.text)
        issues << { code: :multiline_fact_value, line: line.number }
      end
      return :ignored if was_quoted || @quote

      kind
    end

    # 由领域文档识别不能安全跨行的已建模语句。
    def multiline_fact?(_text) = false

    # 保留父级词法诊断，并报告未闭合的引号值。
    def finish
      super
      issues << { code: :incomplete_quoted_value } if @quote
    end
  end
end

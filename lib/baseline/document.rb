# frozen_string_literal: true

require "ctx_parser/document"
require "ctx_parser/banner"

module Baseline
  # 复用游标与配置树，识别厂商注释、横幅及不完整回显。
  class Document < CtxParser::Document
    protected

    # 区分配置结构行与引号、横幅中的文本内容。
    def classify(line)
      text = line.text
      return :ignored if text.empty?
      @banner ||= CtxParser::Banner.new
      return :ignored if @banner.consume(text)
      if /--\s*More\s*--|\e\[|\A(?:%\s*(?:Invalid|Incomplete|Ambiguous)|Error:)/i.match?(text)
        issues << { code: :incomplete_configuration, line: line.number }
        return :ignored
      end
      return :boundary if text.start_with?("!", "#") || %w[end return].include?(text)
      return :ignored if /\A(?:Building configuration|Current configuration)/i.match?(text)

      :entry
    end

    # 报告配置文档结束时仍未闭合的横幅。
    def finish
      issues << { code: :incomplete_banner } if @banner&.open?
    end
  end
end

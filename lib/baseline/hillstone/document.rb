# frozen_string_literal: true

require_relative "../quoted_document"

module Baseline
  module Hillstone
    # StoneOS 导出内容可能包含命令回显、显式退出及引号包裹的界面状态。
    class Document < QuotedDocument
      protected

      # 区分配置结构行与引号、横幅中的文本内容。
      def classify(line)
        unless @quote
          return :ignored if line.text.match?(/\A(?:show (?:configuration|config)|Running configuration|Version\b|[\w.():-]+#\s*\z)/)
          return :ignored if line.text == "exit"
          return :boundary if line.text == "End"
        end
        super
      end

      # 识别配置值可能跨行延续的语句。
      def multiline_fact?(text)
        text.match?(/\A(?:hostname|admin host|snmp-server|ntp|logging syslog|password|secret|host|backup[12])\b/)
      end
    end
  end
end

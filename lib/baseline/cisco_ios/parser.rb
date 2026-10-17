# frozen_string_literal: true

require_relative "../cisco/parser"

module Baseline
  module CiscoIos
    # 解析 IOS、IOS-XE 的 VTY 协议和 AAA 登录列表。
    class Parser < Cisco::Parser
      private

      # 选择共享 Cisco 解析逻辑中的 NX-OS 分支。
      def nxos? = false
    end
  end
end

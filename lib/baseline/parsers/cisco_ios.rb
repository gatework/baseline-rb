# frozen_string_literal: true

module Baseline
  module Parsers
    # 解析 IOS、IOS-XE 的 VTY 协议和 AAA 登录列表。
    class CiscoIos < Cisco
      private

      # 选择共享 Cisco 解析逻辑中的 NX-OS 分支。
      def nxos? = false
    end
  end
end

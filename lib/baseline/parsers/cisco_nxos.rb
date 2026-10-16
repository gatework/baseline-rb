# frozen_string_literal: true

module Baseline
  module Parsers
    # 解析 NX-OS 功能开关、角色权限及命名扩展 ACL。
    class CiscoNxos < Cisco
      private

      # 选择共享 Cisco 解析逻辑中的 NX-OS 分支。
      def nxos? = true
    end
  end
end

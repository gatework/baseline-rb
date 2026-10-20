# frozen_string_literal: true

require_relative "../cisco/parser"
require_relative "authentication"

module Baseline
  module CiscoNxos
    # 解析 NX-OS 功能开关、角色权限及命名扩展 ACL。
    class Parser < Cisco::Parser
      include Authentication
      private

      # 选择共享 Cisco 解析逻辑中的 NX-OS 分支。
      def nxos? = true
    end
  end
end

# frozen_string_literal: true

require_relative "../comware/parser"

module Baseline
  module H3c
    # 解析 H3C Comware 的 SSH、域认证及三类 TACACS 密钥角色。
    class Parser < Comware::Parser
      private

      # 匹配当前平台显式启用 SSH 的命令。
      def ssh_enable_pattern = /\Assh server enable\z/
      # 匹配当前平台显式禁用 SSH 的命令。
      def ssh_disable_pattern = /\A(?:undo ssh server enable|ssh server disable)\z/
      # 匹配当前平台 TACACS 配置块的根语句。
      def tacacs_section_pattern = /\Ahwtacacs scheme\s+/
      # 匹配认证、授权或计费服务器声明。
      def tacacs_server_pattern = /\A(?:primary|secondary) (?:authentication|authorization|accounting)\s+(\S+)/
      # 完整选择服务器命令族，缺失地址也必须保留为损坏证据。
      def tacacs_server_family_pattern = /\A(?:undo )?(?:primary|secondary) (?:authentication|authorization|accounting)(?:\s|\z)/
      # 匹配已配置 TACACS 密钥的存储格式。
      def tacacs_key_pattern = /\Akey (authentication|authorization|accounting) (simple|cipher) (.+)\z/
      # 要求具备当前平台 TACACS 方案使用的全部密钥角色。
      def tacacs_keys_complete?(types) = (%w[authentication authorization accounting] - types).empty?
    end
  end
end

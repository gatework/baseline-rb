# frozen_string_literal: true

require_relative "../comware/parser"

module Baseline
  module Huawei
    # 区分 Huawei VRP 的 AAA 嵌套、模板引用与 Comware 域语法。
    class Parser < Comware::Parser
      private

      # VRP 的域名目标使用 domain 关键字，不能把该词当成服务器地址。
      def loghost_pattern
        /\Ainfo-center loghost\s+(?:vpn-instance\s+\S+\s+)?(?:ipv6\s+|domain\s+)?((?!(?:vpn-instance|ipv6|domain)(?:\s|\z))\S+)/
      end

      # 匹配当前平台显式启用 SSH 的命令。
      def ssh_enable_pattern = /\Astelnet server enable\z/
      # 匹配当前平台显式禁用 SSH 的命令。
      def ssh_disable_pattern = /\A(?:undo stelnet server enable|stelnet server disable)\z/
      # 模板进入与整组撤销共用相同身份边界。
      def tacacs_section_command = "hwtacacs-server template"
      # 匹配认证、授权或计费服务器声明。
      def tacacs_server_pattern = /\Ahwtacacs-server (?:authentication|authorization|accounting)\s+(\S+)/
      # 完整选择服务器命令族，缺失地址也必须保留为损坏证据。
      def tacacs_server_family_pattern = /\A(?:undo )?hwtacacs-server (?:authentication|authorization|accounting)(?:\s|\z)/
      # 匹配已配置 TACACS 密钥的存储格式。
      def tacacs_key_pattern = /\Ahwtacacs-server (shared)-key (cipher|simple) (.+)\z/
      # VRP 模板共享密钥的损坏声明也必须参与最终状态归约。
      def tacacs_key_family_pattern = /\A(?:undo )?hwtacacs-server shared-key(?:\s|\z)/
      # VRP 共享密钥撤销不携带密钥值。
      def tacacs_key_reset_pattern = /\Aundo hwtacacs-server shared-key\z/
      # VRP 模板只使用一个方案级共享密钥槽位。
      def tacacs_key_roles = %w[shared]
      # 返回当前平台修改 SNMP 监听端口的命令模式。
      def snmp_port_command = "snmp-agent udp-port"
      # 从实际所属配置作用域中选取 AAA 声明。
      def aaa_configuration_entries = matching_blocks(/\Aaaa\z/).flat_map(&:children)
      # 解析认证域引用及其服务器组。
      def authentication_domains
        name = last_configured_value(/\Adomain\s+(\S+)\s+admin\z/)
        unless name
          %w[login authorization accounting].each { |kind| record_unknown_fact("tacacs.#{kind}", code: :authentication_domain_unknown) }
          return []
        end
        aaa_configuration_entries.select { |entry| entry.text == "domain #{name}" }
      end

      # 解析 VRP 认证域引用，避免将 VRP 语法应用到 Comware。
      def domain_tacacs_references(kind, domains)
        domains.filter_map do |domain|
          template = last_configured_value(/\Ahwtacacs-server\s+(\S+)\z/, domain.children)
          scheme = last_configured_value(/\A#{kind}-scheme\s+(\S+)\z/, domain.children)
          next unless template && scheme
          definition = aaa_configuration_entries.find { |entry| entry.text == "#{kind}-scheme #{scheme}" }
          unless definition
            record_unknown_fact("tacacs.#{kind == 'authentication' ? 'login' : kind}", [ domain ], code: :tacacs_scheme_unresolved)
            next
          end
          template if last_configured_value(/\A#{kind}-mode\s+(.+)\z/, definition.children).to_s.split.first == "hwtacacs"
        end
      end

      # 提取本地账号角色及凭据存储属性。
      def parse_local_accounts
        matching_blocks(/\Alocal-user\s+\S+\s+password\b/, aaa_configuration_entries).each do |entry|
          match = /\Alocal-user\s+(\S+)\s+password\s+(cipher|irreversible-cipher|simple)\s+(.+)\z/.match(entry.text)
          if match
            record_credential(match[1], "local_user", match[2], match[3], entry)
          else
            record_credential("local-user", "local_user", "unknown", nil, entry)
          end
        end
      end
    end
  end
end

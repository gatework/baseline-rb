# frozen_string_literal: true

require_relative "../comware/parser"

module Baseline
  module H3c
    # 解析 H3C Comware 的 SSH、域认证及三类 TACACS 密钥角色。
    class Parser < Comware::Parser
      private

      # 新建专用基本 ACL 前也检查其他业务的悬空引用，避免创建后意外激活。
      def parse_access_lists
        super
        uses, pending = [], roots.dup
        until pending.empty?
          entry = pending.shift
          pending.concat(entry.children)
          entry.text.scan(/(?:\A|\s)(?:acl(?: (?:number|basic|advanced|name|ipv4|ipv6))*|packet-filter(?: (?:ipv4|ipv6|name))?)\s+(0*[2-3]\d{3})(?=\s|\z)/) do |match|
            uses << { id: match.first.to_i.to_s, line: entry.line }
          end
        end
        record_fact("acl.reference_uses", uses.uniq)
        record_fact("acl.reserved_numeric_ids", uses.map { |use| use[:id] }.uniq)
      end

      # 全局 SNMP ACL 在组和用户 ACL 之前过滤，独立 IPv6 声明不改变 IPv4 绑定。
      def snmp_access_options
        entries = matching_blocks(/\A(?:undo )?snmp-agent acl(?:\s|\z)/).reject { |entry| /\A(?:undo )?snmp-agent acl ipv6(?:\s|\z)/.match?(entry.text) }
        name = effective_configured_value(/\Asnmp-agent acl\s+(?:name\s+)?(\S+)\z/, entries: entries,
          family: /\A/, fact: "snmp.global_access", reset: /\Aundo snmp-agent acl\z/)
        if name && !/\A[0-9]+\z/.match?(name) && !entries.last.text.start_with?("snmp-agent acl name ")
          record_unknown_fact("snmp.global_access", entries)
        end
        { layered_acls: true, global_acl: name, global_acl_supported: entries.any? }
      end

      # 同名 VACM 用户的完整声明以最后一次为准，不从旧声明保留认证或 ACL。
      def snmp_user_definitions_replace? = true

      # 密钥摘要计算不会隐式启用 Comware SNMP，也不保留工具参数。
      def snmp_service_utility?(text) = /\Asnmp-agent calculate-password(?:\s|\z)/.match?(text)

      # 全局 ACL 的完整绑定也是隐式启用命令，命名形式不能缺少实际名称。
      def snmp_implicit_enable?(text)
        return true if super || /\Asnmp-agent acl (?:ipv6 )?[23][0-9]{3}\z/.match?(text)

        match = /\Asnmp-agent acl (?:ipv6 )?name (\S+)\z/.match(text)
        !match.nil? && ResourceSchema.token?(match[1]) && match[1].bytesize <= 63
      end

      # Comware 范围内任一非默认登录设置会使协议及认证同时取范围级值。
      # 未出现的范围级默认值仍保留未知，不从 class 另一项推导已通过。
      def vty_login_entries(defaults, local)
        return local if defaults.empty?
        protocol = local.reverse.find { |entry| /\A(?:undo )?protocol inbound\b/.match?(entry.text) }
        authentication = local.reverse.find { |entry| /\A(?:undo )?authentication-mode\b/.match?(entry.text) }
        default_protocol = !protocol || /\A(?:protocol inbound all|undo protocol inbound)\z/.match?(protocol.text)
        default_authentication = !authentication || /\A(?:authentication-mode password|undo authentication-mode)\z/.match?(authentication.text)
        default_protocol && default_authentication ? defaults : local
      end

      # 启用与撤销只更新列出的版本；损坏声明不能回落到旧的通过值。
      def snmp_versions
        versions = nil
        matching_blocks(/\A(?:undo )?snmp-agent(?: sys-info version(?:\s|\z)|\z)/).each do |entry|
          if entry.text == "undo snmp-agent"
            versions = []
            next
          end
          next if entry.text == "snmp-agent"
          match = /\A(undo )?snmp-agent sys-info version (all|(?:v1|v2c|v3)(?: (?:v1|v2c|v3))*)\z/.match(entry.text)
          unless match
            record_unknown_fact("snmp.versions", [ entry ])
            next
          end
          selected = match[2] == "all" ? %w[v1 v2c v3] : match[2].split.uniq
          if match[1] && selected.size < 3 && versions.nil?
            record_unknown_fact("snmp.versions", [ entry ], code: :snmp_versions_unresolved)
          end
          analyze(entry) { selected }
          versions = if match[1]
            selected.size == 3 ? [] : versions && versions - selected
          else
            (versions.to_a + selected).uniq
          end
        end
        versions
      end

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

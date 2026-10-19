# frozen_string_literal: true

require_relative "../comware/parser"

module Baseline
  module Huawei
    # 区分 Huawei VRP 的 AAA 嵌套、模板引用与 Comware 域语法。
    class Parser < Comware::Parser
      VTY_AUTHENTICATION_MODES = %w[aaa password none].freeze
      private

      # VRP 的 IPv6 和 VPN 位于目标之后，优选标志为 preference，不能复用 Comware 命令位置。
      def parse_ntp_associations(role)
        entries = matching_blocks(/\A(?:undo )?ntp-service (?:ipv6 )?unicast-#{role}(?:\s|\z)/)
        pattern = /\Antp-service unicast-#{role}\s+(?:ipv6\s+)?((?!(?:vpn-instance|ip|ipv6)(?:\s|\z))\S+)/
        configured_server_addresses(role == "server" ? "ntp.servers" : "ntp.associations", pattern, entries, negate: "undo") do |text, match, negative, entry|
          ipv6 = text.start_with?("ntp-service unicast-#{role} ipv6 ")
          address = begin
            IPAddr.new(match[1])
          rescue IPAddr::Error
            nil
          end
          next unless address && address.ipv6? == ipv6
          integers = { "authentication-keyid" => 1..4_294_967_295 }
          integers["version"] = 1..4 unless ipv6
          options = parse_server_options(match.post_match, flags: [ "preference" ], integers: integers,
            names: [ "vpn-instance" ], interfaces: [ "source-interface" ])
          next unless options
          unambiguous = options["vpn-instance"] != "default"
          record_unknown_fact("ntp.associations", [ entry ], code: :ambiguous_routing_scope) unless unambiguous
          record_ntp_resource(address: match[1], role: role, vrf: options["vpn-instance"], options: options,
            entry: entry, negative: negative, complete: unambiguous)
          [ match[1], options["vpn-instance"] ]
        end
      end

      # VRP 使用无连字符的 SHA256 名称，并允许未限定格式的明文材料。
      def ntp_key_algorithms = %w[md5 hmac-sha256 aes-128-cmac aes-256-cmac]
      def ntp_key_secret(value)
        match = /\A(?:(cipher) )?(\S+)\z/.match(value)
        match ? [ match[1] || "plain", match[2] ] : [ nil, nil ]
      end

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
      # VRP HWTACACS 模板名区分大小写，不能借用 Comware 的别名折叠。
      def tacacs_name_key(name) = name

      # 域名不区分大小写，命名 AAA 方案保持完整名称匹配。
      def authentication_section_name_key(command, name) = command == "domain" ? name.downcase : name
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
      # VRP 域定义位于 AAA 视图，不能把系统视图的默认域选择当成定义。
      def authentication_domain_entries = aaa_configuration_entries
      # VRP 管理域选择独立于 Comware，损坏或撤销不得回落到旧选择。
      def authentication_binding_domain
        entry = matching_blocks(/\A(?:undo )?domain\b.*\badmin(?:\s|\z)/).last
        name = if entry&.text == "undo domain admin" || entry.nil? && @fact_builder.complete?
          "default_admin"
        else
          entry&.text&.[](/\Adomain (\S+) admin\z/, 1)
        end
        selected_authentication_domain(name, aaa_configuration_entries, lines: entry ? [ entry.line ] : [])
      end

      # VRP 域引用命名方案和服务器模板；方法必须完整解析，不能只取首个词。
      def authentication_binding_chain(role, domain)
        entries = domain[:entries]
        ref = matching_blocks(/\A(?:undo )?#{role}-scheme(?:\s|\z)/, entries).last
        name = ref&.text&.[](/\A#{role}-scheme (\S+)\z/, 1)
        template = matching_blocks(/\A(?:undo )?hwtacacs-server(?:\s|\z)/, entries).last
        group = template&.text&.[](/\Ahwtacacs-server (\S+)\z/, 1)
        lines = [ ref, template ].compact.map(&:line)
        sections, valid = name ? authentication_named_sections(aaa_configuration_entries, "#{role}-scheme", name) : [ [], false ]
        unless valid && sections.any?
          return { methods: nil, lines: lines, scheme: name, reason: :authentication_list_unresolved }
        end
        entry = matching_blocks(/\A(?:undo )?#{role}-mode(?:\s|\z)/, sections.flat_map(&:children)).last
        lines.concat(sections.map(&:line))
        lines << entry.line if entry
        if entry.nil? || entry.text == "undo #{role}-mode"
          # VRP 认证/授权缺省本地；计费缺省在此不跨型号推断。
          methods = role == "accounting" ? nil : [ { kind: "local" } ]
          return { methods: methods, lines: lines, scheme: name, inherited: true, reason: methods ? nil : :unsupported_authentication_method }
        end
        match = /\A#{role}-mode (.+)\z/.match(entry.text)
        tokens = match && match[1].split
        allowed = case role
        when "authentication" then %w[hwtacacs radius local local-case none]
        when "authorization" then %w[hwtacacs local local-case if-authenticated none]
        else %w[hwtacacs radius none]
        end
        valid = tokens && tokens.any? && tokens.uniq == tokens && (tokens - allowed).empty? && (!tokens.include?("none") || tokens.last == "none")
        valid &&= !(tokens.include?("local") && tokens.include?("local-case"))
        valid &&= tokens.one? if role == "accounting"
        methods = valid ? tokens.map do |token|
          if token == "hwtacacs"
            { kind: "tacacs", group: group }
          elsif token == "local-case"
            { kind: "local", case_sensitive: true }
          else
            { kind: token }
          end
        end : nil
        reason = methods ? nil : :unsupported_authentication_method
        reason = :tacacs_scheme_unresolved if methods&.any? { |method| method[:kind] == "tacacs" } && !ResourceSchema.token?(group)
        analyze(entry) { true } if methods
        { methods: reason ? nil : methods, lines: lines, scheme: name, reason: reason }
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

# frozen_string_literal: true

require_relative "../parser"
require_relative "../snmp_options"

module Baseline
  module Comware
    # 复用 Comware 与 VRP 结构，由厂商子类选择账号、SSH 和 TACACS 语法。
    class Parser < Baseline::Parser
      private

      # 解析管理访问暴露检查使用的有序 ACL 定义。
      def parse_access_lists
        matching_blocks(/\Aacl\s+/).each do |section|
          # IPv6 ACL 不能误建为名为 ipv6 的 IPv4 ACL，也不能覆盖其别名。
          if /\Aacl\s+ipv6\b/.match?(section.text)
            record_unknown_fact("ipv6.acls", [ section ], code: :unsupported_acl_family)
            next
          end
          match = /\Aacl\s+(?:number\s+|basic\s+|advanced\s+)?(?:name\s+)?(\S+)(?:\s+name\s+(\S+))?(?:\s+.*)?\z/.match(section.text)
          next unless match
          register_acl(match[2] || match[1], section.children, source: section, aliases: [ match[1] ], supported: !section.text.include?("match-order auto")) do |entry, index|
            parse_acl_rule(entry, index)
          end
        end
      end

      # 解析单条有序 Comware ACL 规则及来源限制。
      def parse_acl_rule(entry, _index)
        match = /\Arule\s+(\d+)\s+(permit|deny)(?:\s+(.*))?\z/.match(entry.text)
        return unless match
        parts = match[3].to_s.split
        protocol = %w[ip tcp udp icmp].include?(parts.first) ? parts.shift : "ip"
        network = if parts.first == "source"
          parts.shift
          parse_acl_source_network(parts)
        else
          "0.0.0.0/0"
        end
        if parts.first == "destination"
          parts.shift
          return unless parse_acl_source_network(parts) == "0.0.0.0/0"
        end
        if parts.first == "destination-port"
          return unless %w[tcp udp].include?(protocol)
          parts.shift
          return unless parts.shift == "eq"
          port = parse_service_port(parts.shift)
          return if port.nil?
        end
        return unless (parts - %w[logging counting]).empty?
        rule = { sequence: match[1].to_i, action: match[2], protocol: protocol, source: network, line: entry.line }
        port.nil? ? rule : rule.merge(destination_port: port)
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      # 根据监听服务、认证方式与 ACL 绑定关系归纳管理访问事实。
      def parse_management
        record_fact("ssh.enabled", configured_state(ssh_enable_pattern, ssh_disable_pattern), matching_blocks(/\A(?:undo )?(?:ssh|stelnet)/))
        compatible = configured_state(/\Assh server compatible-ssh1x enable\z/, /\A(?:undo ssh server compatible-ssh1x enable|ssh server compatible-ssh1x disable)\z/)
        record_fact("ssh.versions", compatible.nil? ? nil : compatible ? [ "1", "2" ] : [ "2" ])
        ssh_acl_entries = matching_blocks(/\A(?:undo )?ssh server acl(?:\s|\z)/).reject { |entry| /\A(?:undo )?ssh server acl ipv6\b/.match?(entry.text) }
        ssh_acl = effective_configured_value(/\Assh server acl(?: ipv4)?\s+(?!name\z|ipv4\z)(?:name\s+)?(\S+)\z/, entries: ssh_acl_entries,
          family: /\A(?:undo )?ssh server acl(?:\s|\z)/, fact: "management.acl", reset: /\Aundo ssh server acl(?: ipv4)?(?: (?:name )?\S+)?\z/)
        defaults = matching_blocks(/\Aline class vty\z/).flat_map(&:children)
        vtys = matching_blocks(/\A(?:line|user-interface) vty\b/).map do |section|
          entries = defaults + section.children
          login_entries = vty_login_entries(defaults, section.children)
          acl_entries = entries.reject { |entry| /\A(?:undo )?acl\s+ipv6\b|\A(?:undo )?acl\s+(?:name\s+)?\S+\s+outbound(?:\s|\z)/.match?(entry.text) }
          { name: section.text, protocols: effective_configured_value(/\Aprotocol inbound\s+((?:all|ssh|stelnet|telnet)(?:\s+(?:ssh|stelnet|telnet))*)\z/, entries: login_entries,
              family: /\A(?:undo )?protocol inbound\b/, fact: "ssh.vty_ssh_only", reset: /\Aundo protocol inbound(?:\s+\S+)*\z/)&.split,
            authentication: effective_configured_value(/\Aauthentication-mode\s+(scheme|aaa|password|none)\z/, entries: login_entries,
              family: /\A(?:undo )?authentication-mode\b/, fact: "ssh.vty_aaa", reset: /\Aundo authentication-mode(?: \S+)?\z/),
            local_authentication: effective_configured_value(/\Aauthentication-mode\s+(scheme|aaa|password|none)\z/, entries: section.children,
              family: /\A(?:undo )?authentication-mode\b/, fact: "ssh.vty_aaa", reset: /\Aundo authentication-mode(?: \S+)?\z/),
            acl: effective_configured_value(/\Aacl\s+(?!name\z)(?:name\s+)?(\S+)(?:\s+inbound)?\z/, entries: acl_entries,
              family: /\A(?:undo )?acl\b/, fact: "management.acl", reset: /\Aundo acl(?:\s+(?:name\s+)?\S+(?:\s+inbound)?)?\z/), line: section.line }
        end
        @fact_builder.record_management_access(vtys: vtys, ssh_acl: ssh_acl,
          ssh_port: listener_port("ssh server port", default: 22, scope: "management.acl"),
          telnet_port: listener_port("telnet server port", default: 23, scope: "management.acl"))
        definitions = { "telnet" => "telnet server", "http" => "ip http", "https" => "ip https", "ftp" => "ftp server", "tftp" => "tftp server" }
        record_fact("services", definitions.to_h do |name, command|
          [ name, configured_state(/\A#{command} enable\z/, /\A(?:undo #{command} enable|#{command} disable)\z/) ]
        end)
      end

      # 默认按独立命令继承；厂商可覆盖绑定的登录设置语义。
      def vty_login_entries(defaults, local) = defaults + local

      # 提取时间服务器、认证要求与源接口。
      def parse_ntp
        parse_ntp_associations("peer")
        ntp_entries = matching_blocks(/\A(?:undo )?ntp-service (?:ipv6 )?unicast-server(?:\s|\z)/)
        record_fact("ntp.servers", parse_ntp_associations("server"), ntp_entries)
        record_configured_state("ntp.authentication", /\Antp-service authentication enable\z/, /\Aundo ntp-service authentication enable\z/)
        source_entries = matching_blocks(/\A(?:undo )?ntp-service source(?:-interface)?(?:\s|\z)/)
        source = effective_configured_value(/\Antp-service source(?:-interface)?\s+(.+)\z/, entries: source_entries,
          family: /\A/, fact: "ntp.source", reset: /\Aundo ntp-service source(?:-interface)?(?:\s+[a-zA-Z][\w.:\/-]*(?:\s+\d[\d.:\/-]*)?)?\z/)
        record_source_interface("ntp.source", source, source_entries.last(1))
      end

      # 对等关联与客户端服务器分别归约，撤销其中一种不能删除另一种。
      def parse_ntp_associations(role)
        entries = matching_blocks(/\A(?:undo )?ntp-service (?:ipv6 )?unicast-#{role}(?:\s|\z)/)
        pattern = /\Antp-service (?:ipv6 )?unicast-#{role}\s+(?:vpn-instance\s+\S+\s+)?((?!(?:vpn-instance|ip|ipv6)(?:\s|\z))\S+)/
        configured_server_addresses(role == "server" ? "ntp.servers" : "ntp.associations", pattern, entries, negate: "undo") do |text, match, negative, entry|
          options = parse_server_options(match.post_match, flags: [ "priority" ],
            integers: { "version" => 1..4, "authentication-keyid" => 1..4_294_967_295, "authkey" => 1..4_294_967_295 },
            names: [ "vpn-instance" ], interfaces: [ "source-interface" ])
          vpn = text[/\Antp-service (?:ipv6 )?unicast-#{role}\s+vpn-instance\s+(\S+)/, 1]
          if options && !(vpn && options.key?("vpn-instance")) && !(options.key?("authkey") && options.key?("authentication-keyid"))
            unambiguous = (vpn || options["vpn-instance"]) != "default"
            record_unknown_fact("ntp.associations", [ entry ], code: :ambiguous_routing_scope) unless unambiguous
            record_ntp_resource(address: match[1], role: role, vrf: vpn || options["vpn-instance"], options: options, entry: entry, negative: negative, complete: unambiguous)
            [ match[1], vpn || options["vpn-instance"] ]
          end
        end
      end

      # 提取日志目标与源接口，厂商命令不进入事实归约层。
      def parse_syslog
        log_entries = matching_blocks(/\A(?:undo )?info-center loghost(?:\s|\z)/).reject { |entry| /\A(?:undo )?info-center loghost source(?:-port)?(?:\s|\z)/.match?(entry.text) }
        hosts = configured_server_addresses("syslog.servers", loghost_pattern, log_entries, negate: "undo") do |text, match, negative, entry|
          record_loghost_resource(text, match, negative, entry)
          [ match[1], text[/\bvpn-instance\s+(\S+)/, 1] ]
        end
        record_fact("syslog.servers", hosts, log_entries)
        source_entries = matching_blocks(/\A(?:undo )?info-center loghost source(?:\s|\z)/)
        source = effective_configured_value(/\Ainfo-center loghost source\s+(.+)\z/, entries: source_entries,
          family: /\A/, fact: "syslog.source", reset: /\Aundo info-center loghost source(?:\s+[a-zA-Z][\w.:\/-]*(?:\s+\d[\d.:\/-]*)?)?\z/)
        record_source_interface("syslog.source", source, source_entries.last(1))
      end

      # 保留地址族与 VPN 前缀，独立日志控制命令不属于目标地址。
      def loghost_pattern
        /\Ainfo-center loghost\s+(?:vpn-instance\s+\S+\s+)?(?:ipv6\s+)?((?!(?:vpn-instance|ipv6|domain)(?:\s|\z))\S+)/
      end

      # 在同一次目标提取中保留作用域及选项，未知尾部不可产生可执行资源。
      def record_loghost_resource(text, match, negative, entry)
        options = parse_server_options(match.post_match, integers: { "port" => 1..65_535, "dscp" => 0..63 },
          names: %w[vpn-instance facility channel filter])
        scope = { "vrf" => text[/\bvpn-instance\s+(\S+)/, 1] || "default" }
        attributes = (options || {}).reject { |key, _| key == "vpn-instance" }
        complete = !options.nil? && [ *scope.values, *attributes.values.grep(String) ].all? { |value| ResourceSchema.token?(value) }
        complete &&= !(text.start_with?("info-center loghost vpn-instance ") && options.key?("vpn-instance"))
        if text[/\bvpn-instance\s+(\S+)/, 1] == "default"
          complete = false
          record_unknown_fact("syslog.destinations", [ entry ], code: :ambiguous_routing_scope)
        end
        complete &&= !attributes.key?("facility") || /\Alocal[0-7]\z/.match?(attributes["facility"])
        attributes["port"] = 514 if complete && !attributes.key?("port")
        attributes["protocol"] = "udp" if complete
        attributes = {} unless complete
        return unless ResourceSchema.token?(scope["vrf"])

        resource = ConfigurationResource.new(kind: "syslog.destination", identity: { "address" => match[1] },
          scope: scope, attributes: attributes, lines: [ entry.line ], complete: complete)
        @fact_builder.record_resource(resource, remove: negative)
      end

      # 接口类型和编号可分写；非法尾部不能回落到旧接口或截取首个词元。
      def record_source_interface(fact, value, entries)
        return unless value

        match = /\A([a-zA-Z][\w.:\/-]*)(?:\s+(\d[\d.:\/-]*))?\z/.match(value)
        if match && (!match[2] || !/\d/.match?(match[1]))
          record_fact(fact, match[1] + match[2].to_s, entries)
        else
          record_unknown_fact(fact, entries)
        end
      end

      # VRP 的版本命令单独归约，避免套用 Comware 撤销语法。
      def snmp_versions
        versions = last_configured_value(/\Asnmp-agent sys-info version\s+(.+)\z/)&.split
        versions == [ "all" ] ? %w[v1 v2c v3] : versions
      end

      # 提取轮询权限、用户安全属性及来源限制。
      def parse_snmp
        enabling_entries = []
        record_fact("snmp.versions", snmp_versions)
        communities = matching_blocks(/\Asnmp-agent community\b/).filter_map do |entry|
          match = /\Asnmp-agent community (read|write)\s+(?:(simple|cipher)\s+)?(\S+)(.*)\z/.match(entry.text)
          unless match && !(match[2].nil? && %w[simple cipher].include?(match[3]))
            record_unknown_snmp_access([ entry ])
            next
          end
          access = SnmpOptions.community(match[4])
          enabling_entries << entry if access[:complete]
          record_unknown_fact("snmp.acl", [ entry ], code: :unsupported_snmp_access_options) unless access[:complete]
          record_credential("snmp-community", "snmp", match[2] || "plain", match[3], entry)
          { write: match[1] == "write", acl: access[:acl], acl_ipv6: access[:acl_ipv6], read_view: access[:read_view], line: entry.line }
        end
        group_entries = matching_blocks(/\Asnmp-agent group\b/).select do |entry|
          next true if /\Asnmp-agent group v3\s+\S+(?:\s|\z)/.match?(entry.text)

          record_unknown_snmp_access([ entry ], code: :unsupported_snmp_group)
          false
        end
        definitions = []
        groups = configured_snmp_groups(group_entries) do |entry|
          settings = entry.text.sub(/\Asnmp-agent group v3\s+\S+\s*/, "")
          access = SnmpOptions.group(settings)
          enabling_entries << entry if access[:complete]
          definitions << access.merge(name: entry.text.split[3], version: "v3", line: entry.line)
          record_unknown_fact("snmp.acl", [ entry ], code: :unsupported_snmp_access_options) unless access[:complete]
          [ entry.text.split[3], { acl: access[:acl], line: entry.line, write: snmp_group_write_state(settings) } ]
        end
        record_fact("snmp.groups", groups)
        record_fact("snmp.group_definitions", definitions)
        users, security_records = {}, {}
        matching_blocks(/\Asnmp-agent usm-user\b/).each do |entry|
          match = /\Asnmp-agent usm-user v3\s+(\S+)(?:\s+(.*))?\z/.match(entry.text)
          unless match
            record_unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
            next
          end
          settings = match[2].to_s
          initial = { name: match[1], auth: false, priv: false, line: entry.line }
          user = snmp_user_definitions_replace? ? users[match[1]] = initial : users[match[1]] ||= initial
          access = SnmpOptions.user(settings, group_required: snmp_user_definitions_replace?)
          record_unknown_fact("snmp.acl", [ entry ], code: :unsupported_snmp_access_options) unless access[:complete]
          user[:group] = access[:group] if access[:group]
          modes = { auth: parse_snmp_secret(settings, "authentication-mode", algorithms: %w[md5 sha sha224 sha256 sha384 sha512 sha2-224 sha2-256 sha2-384 sha2-512]),
            priv: parse_snmp_secret(settings, "privacy-mode", algorithms: %w[des des56 3des aes128 aes192 aes256]) }
          modes = { auth: nil, priv: nil } unless access[:complete]
          enabling_entries << entry if access[:complete] && modes.values.none?(&:nil?)
          if snmp_user_definitions_replace?
            security_records[match[1]] = [ modes, entry, access[:key_format] ]
            modes.each { |key, value| user[key] = value ? true : value }
          else
            record_snmp_credentials("snmp:#{match[1]}", modes, entry, format: access[:key_format]).each { |key, value| user[key] ||= value }
          end
          user[:acl] = access[:acl] if access[:acl]
          user[:acl_ipv6] = access[:acl_ipv6] if access[:acl_ipv6]
        end
        security_records.each { |name, (modes, entry, format)| record_snmp_credentials("snmp:#{name}", modes, entry, format: format) }
        withdrawals = matching_blocks(/\Aundo snmp-agent (?:usm-user|group)(?:\s|\z)/)
        record_unknown_snmp_access(withdrawals, code: :unsupported_snmp_withdrawal) unless withdrawals.empty?
        @fact_builder.record_snmp_access(communities: communities, users: users.values, groups: groups,
          port: listener_port(snmp_port_command, default: 161, scope: "snmp.acl"), **snmp_access_options)
        record_snmp_enabled(enabling_entries)
      end

      # 已校验的正向命令才能隐式启用；未知声明不能从默认禁用推导通过。
      def record_snmp_enabled(enabling_entries)
        validated = enabling_entries.to_h { |entry| [ entry.index, true ] }
        entries = matching_blocks(/\A(?:undo )?snmp-agent(?:\s|\z)/)
        state = @fact_builder.complete? ? false : nil
        entries.each do |entry|
          text = entry.text
          if text == "undo snmp-agent"
            state = analyze(entry) { false }
          elsif text == "snmp-agent" || validated[entry.index] || snmp_implicit_enable?(text)
            state = analyze(entry) { true }
          elsif !text.start_with?("undo ") && !snmp_service_utility?(text)
            state = nil unless state == true
          end
        end
        if state.nil? && entries.any?
          record_unknown_fact("snmp.enabled", entries, code: :snmp_service_unresolved)
        else
          record_fact("snmp.enabled", state, entries)
        end
      end

      # 只识别已支持的完整声明；未知命令族保持未知，不按前缀视为有效配置。
      def snmp_implicit_enable?(text)
        return true if /\Asnmp-agent sys-info version (?:all|(?:v1|v2c|v3)(?: (?:v1|v2c|v3))*)\z/.match?(text)
        return true if /\Asnmp-agent sys-info (?:contact|location)\s+\S.*\z/.match?(text)
        return true if /\Asnmp-agent local-engineid [0-9A-Fa-f]{10,64}\z/.match?(text) && text.split.last.size.even?

        match = /\A#{Regexp.escape(snmp_port_command)}\s+([0-9]+)\z/.match(text)
        !match.nil? && match[1].to_i.between?(1, 65_535)
      end

      # 工具命令例外必须由厂商适配器声明，不能跨平台假设。
      def snmp_service_utility?(_text) = false

      # 只有明确支持串联 ACL 的适配器才改变组、用户与全局过滤的归约。
      def snmp_access_options = {}

      # VRP 可能分行配置用户；不能套用 Comware 完整 VACM 定义的覆盖语义。
      def snmp_user_definitions_replace? = false

      # Comware、VRP 必须明确授予写视图；引号或未知语法保持未解析。
      def snmp_group_write_state(settings)
        syntax = /\A(?:(?:authentication|privacy|noauthentication)(?:\s+|\z))?(?:(?:read-view|(?<write>write-view)|notify-view)\s+[^\s"]+\s*|acl(?:\s+ipv6)?(?:\s+name)?\s+[^\s"]+\s*|acl-ipv[46]\s+[^\s"]+\s*)*\z/
        match = syntax.match(settings)
        return unless match

        !match[:write].nil?
      end

      # 解析实际生效的认证方法及外部服务器引用。
      def parse_authentication
        schemes = matching_blocks(tacacs_section_pattern).to_h do |section|
          server_types = matching_blocks(tacacs_server_family_pattern, section.children).group_by { |entry| entry.text.delete_prefix("undo ").split[1] }
            .transform_values do |entries|
              configured_server_addresses("tacacs", tacacs_server_pattern, entries, negate: "undo") do |text, match, negative, entry|
                record_tacacs_endpoint(section, text, match, negative, entry)
                match[1]
              end
            end
          servers = server_types.values.flatten.uniq
          keys = section.children.filter_map do |entry|
            match = tacacs_key_pattern.match(entry.text)
            next unless match
            kind, format, secret = match.captures
            record_credential("tacacs:#{section.text.split.last}", "tacacs", format, secret, entry)
            kind
          end
          [ section.text.split.last, { servers: servers, server_types: server_types, key_types: keys.uniq, line: section.line } ]
        end
        record_fact("tacacs.schemes", schemes)
        record_fact("tacacs.servers", schemes.values.flat_map { |entry| entry[:servers] }.uniq)
        domains = authentication_domains
        methods = domains.flat_map { |entry| entry.children }
        %w[authentication authorization accounting].each do |kind|
          relevant = matching_blocks(/\A(?:undo )?#{kind}\s+login\b/, methods)
          relevant = matching_blocks(/\A(?:undo )?#{kind}\s+default\b/, methods) if relevant.empty?
          relevant = relevant.last(1)
          if relevant.any? && !/\A#{kind}\s+(?:login|default)\s+(?:(?:hwtacacs-scheme|radius-scheme)\s+\S+(?:\s+(?:local|none))?|local|none)\z/.match?(relevant.first.text)
            record_unknown_fact("tacacs.#{kind == 'authentication' ? 'login' : kind}", relevant)
            next
          end
          refs = relevant.filter_map { |entry| entry.text[/\A#{kind}\s+(?:login|default)\s+hwtacacs-scheme\s+(\S+)/, 1] }
          refs.concat(domain_tacacs_references(kind, domains))
          key = kind == "authentication" ? "login" : kind
          if refs.any? && refs.any? { |name| !schemes.key?(name) || schemes[name][:server_types].fetch(kind, []).empty? }
            record_unknown_fact("tacacs.#{key}", relevant, code: :tacacs_scheme_unresolved)
          else
            used = refs.any?
            if used && key == "login"
              record_unknown_fact("tacacs.login", code: :vty_authentication_unknown) if @fact_builder.vtys.empty? || @fact_builder.vtys.any? { |vty| vty[:authentication].nil? }
              used &&= @fact_builder.vtys.any? && @fact_builder.vtys.all? { |vty| %w[scheme aaa].include?(vty[:authentication]) }
            end
            record_fact("tacacs.#{key}", used, relevant) if @fact_builder.complete? || used
          end
        end
        record_fact("tacacs.keys_present", schemes.values.all? { |entry| tacacs_keys_complete?(entry[:key_types]) }) unless schemes.empty?
        parse_local_accounts
        matching_blocks(/\A(?:line|user-interface)\b/).each do |section|
          matching_blocks(/\A(?:set authentication )?password\b/, section.children).each do |entry|
            match = /\A(?:set authentication )?password\s+(simple|cipher|hash|irreversible-cipher)\s+(.+)\z/.match(entry.text)
            record_credential(section.text, "line", match ? match[1] : "unknown", match&.[](2), entry)
          end
        end
        matching_blocks(/\Asuper password\b/).each do |entry|
          match = /\Asuper password(?: level \d+)?\s+(simple|cipher|hash)\s+(.+)\z/.match(entry.text)
          record_credential("super", "enable", match ? match[1] : "unknown", match&.[](2), entry)
        end
      end

      # 服务器职责和主备属于身份，不能把相同地址的不同职责合并。
      def record_tacacs_endpoint(section, text, match, negative, entry)
        tail = match.post_match.strip
        port = tail[/\A(\d+)(?:\s|\z)/, 1]
        tail = tail.sub(/\A\d+(?:\s|\z)/, "") if port
        options = parse_server_options(tail, flags: [ "secondary" ], names: %w[vpn-instance source-ip])
        priority = %w[primary secondary].include?(text.split.first) ? text.split.first : options&.fetch("secondary", false) ? "secondary" : "primary"
        attributes = {}
        attributes["port"] = port.to_i if port && port.to_i.between?(1, 65_535)
        attributes["source"] = options["source-ip"] if options && options["source-ip"]
        complete = !options.nil? && (!port || attributes.key?("port"))
        if options && options["vpn-instance"] == "default"
          complete = false
          record_unknown_fact("tacacs.endpoints", [ entry ], code: :ambiguous_routing_scope)
        end
        record_tacacs_resource(identity: { "address" => match[1], "role" => text.split[1], "priority" => priority },
          scope: { "group" => section.text.split.last, "vrf" => options&.fetch("vpn-instance", "default") || "default" },
          attributes: complete ? attributes : {}, entry: entry, negative: negative, complete: complete)
      end

      # 解析认证域引用及其服务器组。
      def authentication_domains
        name = last_configured_value(/\Adomain default enable\s+(\S+)\z/)
        unless name
          %w[login authorization accounting].each { |kind| record_unknown_fact("tacacs.#{kind}", code: :authentication_domain_unknown) }
          return []
        end
        matching_blocks(/\Adomain #{Regexp.escape(name)}\z/)
      end
      # 解析 VRP 认证域引用，避免将 VRP 语法应用到 Comware。
      def domain_tacacs_references(_kind, _domains) = []
      # 返回当前平台修改 SNMP 监听端口的命令模式。
      def snmp_port_command = "snmp-agent port"

      # 提取本地账号角色及凭据存储属性。
      def parse_local_accounts
        matching_blocks(/\Alocal-user\s+/).each do |section|
          next if section.text.start_with?("local-user password-")
          name = section.text.split[1]
          passwords = matching_blocks(/\Apassword\s+/, section.children)
          passwords.each do |entry|
            match = /\Apassword\s+(simple|cipher|hash|irreversible-cipher)\s+(.+)\z/.match(entry.text)
            record_credential(name, "local_user", match ? match[1] : "unknown", match ? match[2] : nil, entry)
          end
          record_credential(name, "local_user", "unknown", nil, section) if passwords.empty? && @fact_builder.complete?
        end
      end
    end
  end
end

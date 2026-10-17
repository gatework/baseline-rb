# frozen_string_literal: true

require_relative "../parser"

module Baseline
  module Comware
    # 复用 Comware 与 VRP 结构，由厂商子类选择账号、SSH 和 TACACS 语法。
    class Parser < Baseline::Parser
      private

      # 解析管理访问暴露检查使用的有序 ACL 定义。
      def access_lists
        matching_blocks(/\Aacl\s+/).each do |section|
          # IPv6 ACL 不能误建为名为 ipv6 的 IPv4 ACL，也不能覆盖其别名。
          if /\Aacl\s+ipv6\b/.match?(section.text)
            unknown("ipv6.acls", [ section ], code: :unsupported_acl_family)
            next
          end
          match = /\Aacl\s+(?:number\s+|basic\s+|advanced\s+)?(?:name\s+)?(\S+)(?:\s+name\s+(\S+))?(?:\s+.*)?\z/.match(section.text)
          next unless match
          register_acl(match[2] || match[1], section.children, source: section, aliases: [ match[1] ], supported: !section.text.include?("match-order auto")) do |entry, index|
            comware_rule(entry, index)
          end
        end
      end

      # 解析单条有序 Comware ACL 规则及来源限制。
      def comware_rule(entry, _index)
        match = /\Arule\s+(\d+)\s+(permit|deny)(?:\s+(.*))?\z/.match(entry.text)
        return unless match
        parts = match[3].to_s.split
        protocol = %w[ip tcp udp icmp].include?(parts.first) ? parts.shift : "ip"
        network = if parts.first == "source"
          parts.shift
          acl_source_network(parts)
        else
          "0.0.0.0/0"
        end
        if parts.first == "destination"
          parts.shift
          return unless acl_source_network(parts) == "0.0.0.0/0"
        end
        if parts.first == "destination-port"
          return unless %w[tcp udp].include?(protocol)
          parts.shift
          return unless parts.shift == "eq"
          port = service_port(parts.shift)
          return if port.nil?
        end
        return unless (parts - %w[logging counting]).empty?
        rule = { sequence: match[1].to_i, action: match[2], protocol: protocol, source: network, line: entry.line }
        port.nil? ? rule : rule.merge(destination_port: port)
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      # 根据监听服务、认证方式与 ACL 绑定关系归纳管理访问事实。
      def management
        record("ssh.enabled", configured_state(ssh_enable, ssh_disable), matching_blocks(/\A(?:undo )?(?:ssh|stelnet)/))
        compatible = configured_state(/\Assh server compatible-ssh1x enable\z/, /\A(?:undo ssh server compatible-ssh1x enable|ssh server compatible-ssh1x disable)\z/)
        record("ssh.versions", compatible.nil? ? nil : compatible ? [ "1", "2" ] : [ "2" ])
        ssh_acl = last_configured_value(/\Assh server acl(?: ipv4)?\s+(?:name\s+)?(\S+)\z/)
        defaults = matching_blocks(/\Aline class vty\z/).flat_map(&:children)
        vtys = matching_blocks(/\A(?:line|user-interface) vty\b/).map do |section|
          entries = defaults + section.children
          { name: section.text, protocols: last_configured_value(/\Aprotocol inbound\s+(.+)\z/, entries)&.split,
            authentication: last_configured_value(/\Aauthentication-mode\s+(\S+)\z/, entries),
            acl: last_configured_value(/\Aacl\s+(?:name\s+)?(\S+)(?:\s+inbound)?\z/, entries), line: section.line }
        end
        @facts.management(vtys: vtys, ssh_acl: ssh_acl,
          ssh_port: listener_port("ssh server port", default: 22, scope: "management.acl"),
          telnet_port: listener_port("telnet server port", default: 23, scope: "management.acl"))
        definitions = { "telnet" => "telnet server", "http" => "ip http", "https" => "ip https", "ftp" => "ftp server", "tftp" => "tftp server" }
        record("services", definitions.to_h do |name, command|
          [ name, configured_state(/\A#{command} enable\z/, /\A(?:undo #{command} enable|#{command} disable)\z/) ]
        end)
      end

      # 采集明确启用或禁用的管理服务。
      def services
        record("ntp.servers", configured_values(/\Antp-service unicast-server\s+(\S+)/), matching_blocks(/\Antp-service unicast-server/))
        record_configured_state("ntp.authentication", /\Antp-service authentication enable\z/, /\Aundo ntp-service authentication enable\z/)
        record_configured_value("ntp.source", /\Antp-service source(?:-interface)?\s+(\S+)\z/)
        # 从日志服务器中排除 source 子命令，并保留评估所需的归纳事实。
        hosts = configured_values(/\Ainfo-center loghost\s+(\S+)/) - [ "source" ]
        record("syslog.servers", hosts, matching_blocks(/\Ainfo-center loghost/))
        record_configured_value("syslog.source", /\Ainfo-center loghost source\s+(\S+)\z/)
        enabled = configured_state(/\Asnmp-agent(?:\s|\z)/, /\Aundo snmp-agent\z/)
        record("snmp.enabled", enabled.nil? && @facts.complete? ? false : enabled)
        versions = last_configured_value(/\Asnmp-agent sys-info version\s+(.+)\z/)&.split
        versions = %w[v1 v2c v3] if versions == [ "all" ]
        record("snmp.versions", versions)
        communities = matching_blocks(/\Asnmp-agent community\b/).filter_map do |entry|
          match = /\Asnmp-agent community (read|write)\s+(?:(simple|cipher)\s+)?(\S+)(.*)\z/.match(entry.text)
          unless match
            unknown_snmp_access([ entry ])
            next
          end
          record_credential("snmp-community", "snmp", match[2] || "plain", match[3], entry)
          { write: match[1] == "write", acl: match[4][/\bacl\s+(?:name\s+)?(\S+)/, 1], line: entry.line }
        end
        groups = snmp_groups(matching_blocks(/\Asnmp-agent group v3\s+/)) do |entry|
          settings = entry.text.sub(/\Asnmp-agent group v3\s+\S+\s*/, "")
          [ entry.text.split[3], { acl: entry.text[/\bacl\s+(?:name\s+)?(\S+)/, 1], line: entry.line, write: snmp_group_write(settings) } ]
        end
        record("snmp.groups", groups)
        users = {}
        matching_blocks(/\Asnmp-agent usm-user\b/).each do |entry|
          match = /\Asnmp-agent usm-user v3\s+(\S+)(?:\s+(.*))?\z/.match(entry.text)
          unless match
            unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
            next
          end
          settings = match[2].to_s
          user = users[match[1]] ||= { name: match[1], auth: false, priv: false, line: entry.line }
          group = settings[/\Agroup\s+(\S+)/, 1]
          first = settings.split.first
          group ||= first unless %w[group authentication-mode privacy-mode acl local engineid].include?(first)
          user[:group] = group if group
          modes = { auth: snmp_secret(settings, "authentication-mode", algorithms: %w[md5 sha sha2-224 sha2-256 sha2-384 sha2-512]),
            priv: snmp_secret(settings, "privacy-mode", algorithms: %w[des des56 3des aes128 aes192 aes256]) }
          snmp_credentials("snmp:#{match[1]}", modes, entry).each { |key, value| user[key] ||= value }
          acl = settings[/\bacl\s+(?:name\s+)?(\S+)/, 1]
          user[:acl] = acl if acl
        end
        @facts.snmp(communities: communities, users: users.values, groups: groups,
          port: listener_port(snmp_port_command, default: 161, scope: "snmp.acl"))
      end

      # Comware、VRP 必须明确授予写视图；引号或未知语法保持未解析。
      def snmp_group_write(settings)
        syntax = /\A(?:(?:authentication|privacy|noauthentication)(?:\s+|\z))?(?:(?:read-view|(?<write>write-view)|notify-view)\s+[^\s"]+\s*|acl(?:\s+ipv6)?(?:\s+name)?\s+[^\s"]+\s*|acl-ipv[46]\s+[^\s"]+\s*)*\z/
        match = syntax.match(settings)
        return unless match

        !match[:write].nil?
      end

      # 解析实际生效的认证方法及外部服务器引用。
      def authentication
        schemes = matching_blocks(tacacs_section).to_h do |section|
          server_types = matching_blocks(tacacs_server, section.children).group_by { |entry| entry.text.split[1] }
            .transform_values { |entries| configured_values(tacacs_server, entries) }
          servers = server_types.values.flatten.uniq
          keys = section.children.filter_map do |entry|
            match = tacacs_key.match(entry.text)
            next unless match
            kind, format, secret = match.captures
            record_credential("tacacs:#{section.text.split.last}", "tacacs", format, secret, entry)
            kind
          end
          [ section.text.split.last, { servers: servers, server_types: server_types, key_types: keys.uniq, line: section.line } ]
        end
        record("tacacs.schemes", schemes)
        record("tacacs.servers", schemes.values.flat_map { |entry| entry[:servers] }.uniq)
        domains = authentication_domains
        methods = domains.flat_map { |entry| entry.children }
        %w[authentication authorization accounting].each do |kind|
          relevant = matching_blocks(/\A#{kind}\s+login\b/, methods)
          relevant = matching_blocks(/\A#{kind}\s+default\b/, methods) if relevant.empty?
          refs = relevant.filter_map { |entry| entry.text[/\A#{kind}\s+(?:login|default)\s+hwtacacs-scheme\s+(\S+)/, 1] }
          refs.concat(vrp_tacacs_references(kind, domains))
          key = kind == "authentication" ? "login" : kind
          if refs.any? && refs.any? { |name| !schemes.key?(name) || schemes[name][:server_types].fetch(kind, []).empty? }
            unknown("tacacs.#{key}", relevant, code: :tacacs_scheme_unresolved)
          else
            used = refs.any?
            if used && key == "login"
              unknown("tacacs.login", code: :vty_authentication_unknown) if @facts.vtys.empty? || @facts.vtys.any? { |vty| vty[:authentication].nil? }
              used &&= @facts.vtys.any? && @facts.vtys.all? { |vty| %w[scheme aaa].include?(vty[:authentication]) }
            end
            record("tacacs.#{key}", used, relevant) if @facts.complete? || used
          end
        end
        record("tacacs.keys_present", schemes.values.all? { |entry| tacacs_keys_complete?(entry[:key_types]) }) unless schemes.empty?
        accounts
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

      # 解析认证域引用及其服务器组。
      def authentication_domains
        name = last_configured_value(/\Adomain default enable\s+(\S+)\z/)
        unless name
          %w[login authorization accounting].each { |kind| unknown("tacacs.#{kind}", code: :authentication_domain_unknown) }
          return []
        end
        matching_blocks(/\Adomain #{Regexp.escape(name)}\z/)
      end
      # 解析 VRP 认证域引用，避免将 VRP 语法应用到 Comware。
      def vrp_tacacs_references(_kind, _domains) = []
      # 返回当前平台修改 SNMP 监听端口的命令模式。
      def snmp_port_command = "snmp-agent port"

      # 提取本地账号角色及凭据存储属性。
      def accounts
        matching_blocks(/\Alocal-user\s+/).each do |section|
          next if section.text.start_with?("local-user password-")
          name = section.text.split[1]
          passwords = matching_blocks(/\Apassword\s+/, section.children)
          passwords.each do |entry|
            match = /\Apassword\s+(simple|cipher|hash|irreversible-cipher)\s+(.+)\z/.match(entry.text)
            record_credential(name, "local_user", match ? match[1] : "unknown", match ? match[2] : nil, entry)
          end
          record_credential(name, "local_user", "unknown", nil, section) if passwords.empty? && @facts.complete?
        end
      end
    end
  end
end

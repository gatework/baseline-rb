# frozen_string_literal: true

require_relative "../parser"

module Baseline
  module Cisco
    # 复用 Cisco 管理服务、IPv4 ACL、SNMP 和 AAA 的公共语法。
    class Parser < Baseline::Parser
      SNMP_ROLE_WRITE = { "network-admin" => true, "vdc-admin" => true,
        "network-operator" => false, "vdc-operator" => false }.freeze

      private

      # 解析管理访问暴露检查使用的有序 ACL 定义。
      def access_lists
        matching_blocks(/\Aip access-list\s+/).each do |section|
          name = section.text.split.last
          extended = section.text.start_with?("ip access-list extended ") || nxos?
          register_acl(name, section.children, source: section) { |entry, index| cisco_rule(entry, index, extended: extended) }
        end
        matching_blocks(/\Aaccess-list\s+/).group_by { |entry| entry.text.split[1] }.each do |name, entries|
          extended = name.to_i.between?(100, 199) || name.to_i.between?(2000, 2699)
          register_acl(name, entries) { |entry, index| cisco_rule(entry, index, extended: extended, prefix: /\Aaccess-list\s+\S+\s+/) }
        end
      end

      # 解析 Cisco ACL 条目，保留规则顺序及地址语义。
      def cisco_rule(entry, index, extended:, prefix: /\A/)
        text = entry.text.sub(prefix, "")
        match = /\A(?:(\d+)\s+)?(permit|deny)\s+(.+)\z/.match(text)
        return unless match
        parts = match[3].split
        protocol = extended ? parts.shift : "ip"
        return unless %w[ip tcp udp icmp].include?(protocol)
        network = acl_source_network(parts)
        return if extended && acl_source_network(parts) != "0.0.0.0/0"
        if extended && parts.first == "eq"
          return unless %w[tcp udp].include?(protocol)
          parts.shift
          port = service_port(parts.shift)
          return if port.nil?
        end
        return unless (parts - %w[log log-input]).empty?
        rule = { sequence: match[1]&.to_i || index + 1, action: match[2], protocol: protocol, source: network, line: entry.line }
        port.nil? ? rule : rule.merge(destination_port: port)
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      # 根据监听服务、认证方式与 ACL 绑定关系归纳管理访问事实。
      def management
        version = last_configured_value(/\Aip ssh version\s+([12])\z/)
        record("ssh.versions", [ version ]) if version
        ssh = nxos? ? configured_state(/\Afeature ssh\z/, /\Ano feature ssh\z/) : version ? true : nil
        record("ssh.enabled", ssh, matching_blocks(/\A(?:ip ssh|(?:no )?feature ssh)/))
        default_aaa = nxos? || configured_state(/\Aaaa new-model\z/, /\Ano aaa new-model\z/) == true
        vtys = matching_blocks(/\Aline vty(?:\s|\z)/).map do |section|
          authentication = last_configured_value(/\Alogin authentication\s+(\S+)\z/, section.children)
          local = section.children.any? { |entry| entry.text == "login local" }
          { name: section.text, protocols: last_configured_value(/\Atransport input\s+(.+)\z/, section.children)&.split,
            authentication: local ? "local" : (default_aaa ? "aaa" : nil),
            authentication_list: authentication || (default_aaa ? "default" : nil),
            acl: last_configured_value(/\Aaccess-class\s+(\S+)\s+in(?:\s+vrf-also)?\z/, section.children), line: section.line }
        end
        rotary = matching_blocks(/\A(?:no )?ip ssh port(?:\s|\z)/)
        rotary.concat(matching_blocks(/\Aline vty(?:\s|\z)/).flat_map { |section| matching_blocks(/\A(?:no )?rotary(?:\s|\z)/, section.children) })
        unknown_listener_port("management.acl", rotary) unless rotary.empty?
        telnet_ports = matching_blocks(/\A(?:no )?(?:ip )?telnet(?: server)? port(?:\s|\z)/)
        unknown_listener_port("management.acl", telnet_ports) unless telnet_ports.empty?
        @facts.management(vtys: vtys,
          ssh_port: rotary.empty? ? listener_port("ssh port", default: 22, scope: "management.acl", negate: "no") : nil,
          telnet_port: telnet_ports.empty? ? 23 : nil)
        telnet = if nxos?
          configured_state(/\Afeature telnet\z/, /\Ano feature telnet\z/)
        elsif vtys.any? && vtys.all? { |entry| entry[:protocols] }
          vtys.any? { |entry| (entry[:protocols] & %w[all telnet]).any? }
        end
        record("services", { "telnet" => telnet, "http" => configured_state(/\Aip http server\z/, /\Ano ip http server\z/),
          "https" => configured_state(/\Aip http secure-server\z/, /\Ano ip http secure-server\z/),
          "ftp" => configured_state(/\A(?:feature ftp-server|ftp-server enable)\z/, /\Ano (?:feature ftp-server|ftp-server enable)\z/),
          "tftp" => configured_state(/\A(?:feature tftp-server|tftp-server\s+.+)\z/, /\Ano (?:feature tftp-server|tftp-server\s+.+)\z/),
          "finger" => configured_state(/\A(?:ip finger|service finger)\z/, /\Ano (?:ip finger|service finger)\z/) })
      end

      # 采集明确启用或禁用的管理服务。
      def services
        record("ntp.servers", configured_values(/\Antp server(?: vrf \S+)?\s+(\S+)/), matching_blocks(/\Antp server/))
        record("ntp.authentication", configured_state(/\Antp authenticate\z/, /\Ano ntp authenticate\z/))
        record("ntp.source", last_configured_value(/\Antp source(?:-interface)?\s+(\S+)\z/))
        hosts = configured_values(nxos? ? /\Alogging server\s+(\S+)/ : /\Alogging host(?: ipv6)?\s+(\S+)/)
        hosts |= configured_values(/\Alogging\s+(\d+(?:\.\d+){3})\z/) unless nxos?
        record("syslog.servers", hosts, matching_blocks(/\Alogging (?:host|server)/))
        record("syslog.source", last_configured_value(/\Alogging source-interface\s+(\S+)\z/))
        snmp = matching_blocks(/\Asnmp-server\b/)
        enabled = nxos? ? configured_state(/\Asnmp-server protocol enable\z/, /\Ano snmp-server protocol enable\z/) : nil
        enabled = nxos? || snmp.any? if enabled.nil? && (@facts.complete? || snmp.any?)
        record("snmp.enabled", enabled)
        communities = {}
        matching_blocks(/\Asnmp-server community\b/).each do |entry|
          match = /\Asnmp-server community\s+(\S+)(?:\s+(.*))?\z/.match(entry.text)
          unless match
            unknown_snmp_access([ entry ])
            next
          end
          settings = match[2].to_s
          community = communities[match[1]] ||= { line: entry.line }
          permission = settings[/\A(ro|rw)\b/i, 1]&.downcase
          role = settings[/\bgroup\s+(\S+)/, 1]
          community[:write] = permission == "rw" if permission
          community[:write] = SNMP_ROLE_WRITE[role] if role
          acl = nxos? ? settings[/\buse-ipv4acl\s+(\S+)/, 1] : settings[/\A(?:ro|rw)\s+(\S+)\z/i, 1]
          community[:acl] = acl if acl
          record_credential("snmp-community", "snmp", "plain", match[1], entry) unless @facts.credential_recorded?(community[:line])
        end
        versions = communities.any? ? %w[v1 v2c] : []
        groups = snmp_groups(matching_blocks(/\Asnmp-server group\s+.+?\s+v3\b/)) do |entry|
          name, settings = entry.text.match(/\Asnmp-server group\s+(.+?)\s+v3(?:\s+(.*))?\z/).captures
          write = name.include?('"') ? nil : snmp_group_write(settings.to_s)
          [ name, { acl: entry.text[/\baccess\s+(\S+)/, 1], line: entry.line, write: write } ]
        end
        record("snmp.groups", groups)
        users = {}
        matching_blocks(/\Asnmp-server user\b/).each do |entry|
          match = /\Asnmp-server user\s+(\S+)\s+(\S+)(.*)\z/.match(entry.text)
          unless match
            unknown_snmp_access([ entry ])
            next
          end
          if nxos? && match[2] == "use-ipv4acl"
            user = users[match[1]] ||= { name: match[1], line: entry.line }
            user[:acl] = match[3].strip
            next
          end
          settings = match[3]
          if /\bv[12]c?\b/.match?(settings)
            unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
            next
          end
          unless nxos? || /\bv3\b/.match?(settings)
            unknown_snmp_access([ entry ])
            next
          end
          versions |= [ "v3" ]
          user = users[match[1]] ||= { name: match[1], line: entry.line }
          if nxos?
            (user[:roles] ||= []) << match[2]
            user[:roles].uniq!
            user[:write] = Facts.write_permission(user[:roles].map { |role| SNMP_ROLE_WRITE[role] })
            next if settings.strip.empty?
          end
          modes = { auth: snmp_secret(settings, "auth", algorithms: %w[md5 sha sha-224 sha-256 sha-384 sha-512]),
            priv: snmp_secret(settings, "priv", algorithms: %w[des 3des aes aes-128 aes-192 aes-256], optional_algorithm: nxos?, aes_size: !nxos?) }
          security = snmp_credentials("snmp:#{match[1]}", modes, entry, format: /\bencrypted\b/.match?(settings) ? "cipher" : "unknown")
          user.merge!(security).merge!(group: match[2])
          acl = settings[/\b(?:access|use-ipv4acl)\s+(\S+)/, 1]
          user[:acl] = acl if acl
        end
        port_overrides = matching_blocks(/\A(?:no )?snmp-server (?:listen-port|udp-port|port)(?:\s|\z)/)
        unknown_listener_port("snmp.acl", port_overrides) unless port_overrides.empty?
        @facts.snmp(communities: communities.values, users: users.values, groups: nxos? ? nil : groups,
          port: port_overrides.empty? ? 161 : nil)
        nxos_snmp_coverage(users, enabled: enabled) if nxos?
        unknown("snmp.v3_auth_priv", code: :snmp_user_unresolved) if users.values.any? { |user| !user.key?(:auth) }
        versions |= configured_values(/\Asnmp-server group\s+\S+\s+(v1|v2c|v3)\b/)
        legacy_groups = matching_blocks(/\Asnmp-server group\s+\S+\s+v(?:1|2c)\b/)
        if legacy_groups.any?
          @facts.unknown_snmp_permission(lines: legacy_groups.map(&:line), code: :unsupported_snmp_group)
          unknown("snmp.acl", legacy_groups, code: :unsupported_snmp_group)
        end
        record("snmp.versions", versions) unless versions.empty?
      end

      # NX-OS 通常会同步 CLI 与 SNMP 账号；缺少证据时不能构造虚拟用户。
      def nxos_snmp_coverage(users, enabled:)
        return if enabled == false
        sync_disabled = configured_state(/\Asnmp-server disable snmp-aaa sync\z/, /\Ano snmp-server disable snmp-aaa sync\z/)
        return if sync_disabled == true

        matching_blocks(/\Ausername\s+/).group_by { |entry| entry.text.split[1] }.each do |name, entries|
          roles = entries.filter_map { |entry| entry.text[/\brole\s+(\S+)\s*\z/, 1] }.uniq
          covered = users[name]&.fetch(:roles, []) || []
          next if roles.any? && (roles - covered).empty?

          @facts.unknown_snmp_permission(lines: entries.map(&:line), code: :snmp_user_sync_unconfirmed)
        end
      end

      # IOS 默认不授予写视图；不熟悉的组配置项不能证明只读权限。
      def snmp_group_write(settings)
        syntax = /\A(?:auth|noauth|priv)(?:\s+(?:read|(?<write>write)|notify|context)\s+[^\s"]+|\s+match\s+(?:exact|prefix)|\s+access(?:\s+ipv6)?\s+[^\s"]+)*\z/
        match = syntax.match(settings)
        return unless match

        !match[:write].nil?
      end

      # 解析实际生效的认证方法及外部服务器引用。
      def authentication
        servers, aliases, keyed = [], {}, []
        global_key = matching_blocks(/\Atacacs-server key\s+/)
        global_key.each { |entry| parse_key("tacacs", entry.text.sub(/\Atacacs-server key\s+/, ""), entry) }
        matching_blocks(/\Atacacs-server host\s+/).each do |entry|
          host = entry.text.split[2]
          servers << host
          key = entry.text[/\bkey\s+(.+)\z/, 1]
          if key
            parse_key("tacacs:#{host}", key, entry)
            keyed << host
          end
        end
        matching_blocks(/\Atacacs server\s+/).each do |section|
          hosts = configured_values(/\Aaddress ipv[46]\s+(\S+)/, section.children)
          aliases[section.text.split.last] = hosts
          servers |= hosts
          matching_blocks(/\Akey\s+/, section.children).each do |entry|
            parse_key("tacacs:#{section.text.split.last}", entry.text.delete_prefix("key "), entry)
            keyed |= hosts
          end
        end
        groups = matching_blocks(/\Aaaa group server tacacs\+\s+/).to_h do |section|
          members = configured_values(/\Aserver(?: name)?\s+(\S+)/, section.children)
          [ section.text.split.last, members.flat_map { |member| aliases.fetch(member, [ member ]) } ]
        end
        record("tacacs.servers", servers.uniq)
        record("tacacs.groups", groups)
        tacacs_login(servers, groups)
        patterns = { "authorization" => /\Aaaa authorization (?:exec|commands(?: \d+)?) default\s+(.+)\z/,
          "accounting" => /\Aaaa accounting (?:(?:exec|commands(?: \d+)?) )?default\s+(.+)\z/ }
        patterns.each do |kind, pattern|
          references = configured_values(pattern).flat_map { |methods| methods.scan(/\bgroup\s+(\S+)/).flatten }
          selected = references.flat_map { |name| name == "tacacs+" ? servers : groups.fetch(name, []) }.uniq
          unresolved = references.any? { |name| name != "radius" && name != "tacacs+" && !groups.key?(name) } || (selected - servers).any?
          if unresolved
            unknown("tacacs.#{kind}", matching_blocks(pattern), code: :tacacs_group_unresolved)
          else
            used = selected.any?
            record("tacacs.#{kind}", used, matching_blocks(pattern)) if @facts.complete? || used
          end
        end
        record("tacacs.keys_present", global_key.any? || (servers - keyed).empty?) unless servers.empty?
        accounts
      end

      # 解析各 VTY 实际选用的登录列表，包括命名列表。
      def tacacs_login(servers, groups)
        pattern = /\Aaaa authentication login\s+(\S+)\s+(.+)\z/
        lists = matching_blocks(pattern).each_with_object({}) do |entry, result|
          name, methods = analyze(entry) { entry.text.match(pattern).captures }
          result[name] = { methods: methods, entry: entry }
        end
        entries = @facts.vtys.filter_map { |vty| lists[vty[:authentication_list]]&.fetch(:entry) }.uniq
        results = @facts.vtys.map do |vty|
          if vty[:authentication].nil?
            :vty_authentication_unknown
          elsif vty[:authentication] != "aaa"
            false
          elsif (list = lists[vty[:authentication_list]])
            tacacs_login_method(list[:methods], servers, groups)
          else
            :authentication_list_unresolved
          end
        end
        results << :vty_authentication_unknown if results.empty?
        if results.include?(false)
          record("tacacs.login", false, entries) if @facts.complete?
        elsif (reason = results.find { |value| value.is_a?(Symbol) })
          unknown("tacacs.login", entries, code: reason)
        else
          record("tacacs.login", true, entries)
        end
      end

      # 仅当首选认证方法引用可解析的 TACACS 组时，才确认使用 TACACS。
      def tacacs_login_method(methods, servers, groups)
        tokens = methods.split
        outcomes = []
        until tokens.empty?
          case tokens.shift
          when "group"
            name = tokens.shift
            if name == "radius"
              outcomes << false
              next
            end
            return :tacacs_group_unresolved unless name == "tacacs+" || groups.key?(name)
            selected = name == "tacacs+" ? servers : groups.fetch(name)
            return :tacacs_group_unresolved unless (selected - servers).empty?
            outcomes << selected.any?
          when "local", "local-case", "none", "enable", "line"
            outcomes << false
          else
            return :unsupported_authentication_method
          end
        end
        outcomes.first
      end

      # 提取已配置的凭据编码方式，不保留秘密值。
      def parse_key(owner, text, entry)
        match = /\A(?:(\d+)\s+)?(\S+)/.match(text)
        record_credential(owner, "tacacs", match&.[](1) || "plain", match&.[](2), entry)
      end

      # 提取本地账号角色及凭据存储属性。
      def accounts
        matching_blocks(/\Ausername\s+/).group_by { |entry| entry.text.split[1] }.each do |name, entries|
          passwords = entries.filter_map do |entry|
            match = /\b(?:password|secret)\s+(?:(\d+)\s+)?(\S+)/.match(entry.text)
            record_credential(name, "local_user", match[1] || "plain", match[2], entry) if match
          end
          record_credential(name, "local_user", "unknown", nil, entries.first) if passwords.empty?
        end
        matching_blocks(/\Aenable (?:password|secret)\s+/).each do |entry|
          match = /\Aenable (?:password|secret)(?: level \d+)?\s+(?:(\d+)\s+)?(\S+)/.match(entry.text)
          record_credential("enable", "enable", match ? match[1] || "plain" : "unknown", match&.[](2), entry)
        end
        matching_blocks(/\Aline\b/).each do |section|
          matching_blocks(/\Apassword\b/, section.children).each do |entry|
            match = /\Apassword\s+(?:(\d+)\s+)?(\S+)/.match(entry.text)
            record_credential(section.text, "line", match ? match[1] || "plain" : "unknown", match&.[](2), entry)
          end
        end
      end
    end
  end
end

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
      def parse_access_lists
        matching_blocks(/\Aip access-list\s+/).each do |section|
          name = section.text.split.last
          extended = section.text.start_with?("ip access-list extended ") || nxos?
          register_acl(name, section.children, source: section) { |entry, index| parse_acl_rule(entry, index, extended: extended) }
        end
        matching_blocks(/\Aaccess-list\s+/).group_by { |entry| entry.text.split[1] }.each do |name, entries|
          extended = name.to_i.between?(100, 199) || name.to_i.between?(2000, 2699)
          register_acl(name, entries) { |entry, index| parse_acl_rule(entry, index, extended: extended, prefix: /\Aaccess-list\s+\S+\s+/) }
        end
      end

      # 解析 Cisco ACL 条目，保留规则顺序及地址语义。
      def parse_acl_rule(entry, index, extended:, prefix: /\A/)
        text = entry.text.sub(prefix, "")
        match = /\A(?:(\d+)\s+)?(permit|deny)\s+(.+)\z/.match(text)
        return unless match
        parts = match[3].split
        protocol = extended ? parts.shift : "ip"
        return unless %w[ip tcp udp icmp].include?(protocol)
        network = parse_acl_source_network(parts)
        return if extended && parse_acl_source_network(parts) != "0.0.0.0/0"
        if extended && parts.first == "eq"
          return unless %w[tcp udp].include?(protocol)
          parts.shift
          port = parse_service_port(parts.shift)
          return if port.nil?
        end
        return unless (parts - %w[log log-input]).empty?
        rule = { sequence: match[1]&.to_i || index + 1, action: match[2], protocol: protocol, source: network, line: entry.line }
        port.nil? ? rule : rule.merge(destination_port: port)
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      # 根据监听服务、认证方式与 ACL 绑定关系归纳管理访问事实。
      def parse_management
        version = effective_configured_value(/\Aip ssh version\s+([12])\z/,
          family: /\A(?:no )?ip ssh version\b/, fact: "ssh.versions", reset: /\Ano ip ssh version(?: [12])?\z/)
        record_fact("ssh.versions", [ version ]) if version
        ssh = nxos? ? configured_state(/\Afeature ssh\z/, /\Ano feature ssh\z/) : version ? true : nil
        record_fact("ssh.enabled", ssh, matching_blocks(/\A(?:ip ssh|(?:no )?feature ssh)/))
        default_aaa = nxos? || configured_state(/\Aaaa new-model\z/, /\Ano aaa new-model\z/) == true
        vtys = matching_blocks(/\Aline vty(?:\s|\z)/).map do |section|
          login = configured_vty_login(section, default_aaa: default_aaa)
          acl_entries = section.children.reject { |entry| /\A(?:no )?access-class\s+\S+\s+out(?:\s|\z)/.match?(entry.text) }
          { name: section.text, protocols: effective_configured_value(/\Atransport input\s+((?:all|none|ssh|telnet)(?:\s+(?:ssh|telnet))*)\z/, entries: section.children,
              family: /\A(?:no )?transport input\b/, fact: "ssh.vty_ssh_only", reset: /\Ano transport input(?:\s+\S+)*\z/)&.split,
            authentication: login[:authentication], authentication_list: login[:authentication_list],
            acl: effective_configured_value(/\Aaccess-class\s+(\S+)\s+in(?:\s+vrf-also)?\z/, entries: acl_entries,
              family: /\A(?:no )?access-class\b/, fact: "management.acl",
              reset: /\Ano access-class(?:\s+\S+\s+in(?:\s+vrf-also)?)?\z/), line: section.line }
        end
        rotary = matching_blocks(/\A(?:no )?ip ssh port(?:\s|\z)/)
        rotary.concat(matching_blocks(/\Aline vty(?:\s|\z)/).flat_map { |section| matching_blocks(/\A(?:no )?rotary(?:\s|\z)/, section.children) })
        record_unknown_listener_port("management.acl", rotary) unless rotary.empty?
        telnet_ports = matching_blocks(/\A(?:no )?(?:ip )?telnet(?: server)? port(?:\s|\z)/)
        record_unknown_listener_port("management.acl", telnet_ports) unless telnet_ports.empty?
        @fact_builder.record_management_access(vtys: vtys,
          ssh_port: rotary.empty? ? listener_port("ssh port", default: 22, scope: "management.acl", negate: "no") : nil,
          telnet_port: telnet_ports.empty? ? 23 : nil)
        telnet = if nxos?
          configured_state(/\Afeature telnet\z/, /\Ano feature telnet\z/)
        elsif vtys.any? && vtys.all? { |entry| entry[:protocols] }
          vtys.any? { |entry| (entry[:protocols] & %w[all telnet]).any? }
        end
        record_fact("services", { "telnet" => telnet, "http" => configured_state(/\Aip http server\z/, /\Ano ip http server\z/),
          "https" => configured_state(/\Aip http secure-server\z/, /\Ano ip http secure-server\z/),
          "ftp" => configured_state(/\A(?:feature ftp-server|ftp-server enable)\z/, /\Ano (?:feature ftp-server|ftp-server enable)\z/),
          "tftp" => configured_state(/\A(?:feature tftp-server|tftp-server\s+.+)\z/, /\Ano (?:feature tftp-server|tftp-server\s+.+)\z/),
          "finger" => configured_state(/\A(?:ip finger|service finger)\z/, /\Ano (?:ip finger|service finger)\z/) })
      end

      # VTY 登录方式属于同一声明族，不能让先前的本地登录覆盖后续列表或撤销。
      def configured_vty_login(section, default_aaa:)
        entry = matching_blocks(/\A(?:no )?login\b/, section.children).last
        fallback = { authentication: default_aaa ? "aaa" : nil, authentication_list: default_aaa ? "default" : nil }
        return fallback unless entry

        case entry.text
        when "login local"
          analyze(entry) { { authentication: "local", authentication_list: nil } }
        when "login", "no login"
          analyze(entry) { { authentication: "none", authentication_list: nil } }
        when /\Alogin authentication\s+(\S+)\z/
          analyze(entry) { fallback.merge(authentication_list: entry.text.split.last) }
        else
          record_unknown_fact("ssh.vty_aaa", [ entry ])
          record_unknown_fact("tacacs.login", [ entry ])
          { authentication: nil, authentication_list: nil }
        end
      end

      # 提取时间服务器、认证要求与源接口。
      def parse_ntp
        ntp_entries = matching_blocks(/\A(?:no )?ntp server(?:\s|\z)/)
        ntp_pattern = /\Antp server\s+(?:vrf\s+\S+\s+)?(?:(?:ip|ipv6)\s+)?((?!(?:vrf|ip|ipv6)(?:\s|\z))\S+)/
        servers = configured_server_addresses("ntp.servers", ntp_pattern, ntp_entries, negate: "no") do |text, match|
          options = parse_server_options(match.post_match, flags: %w[prefer normal-sync burst iburst],
            integers: { "version" => 1..4, "key" => 1..65_535, "minpoll" => 4..17, "maxpoll" => 4..17 },
            names: [ "use-vrf" ], interfaces: [ "source" ])
          vrf = text[/\Antp server\s+vrf\s+(\S+)/, 1]
          [ match[1], vrf || options["use-vrf"] ] if options && !(vrf && options.key?("use-vrf"))
        end
        record_fact("ntp.servers", servers, ntp_entries)
        record_configured_state("ntp.authentication", /\Antp authenticate\z/, /\Ano ntp authenticate\z/)
        source_entries = matching_blocks(/\A(?:no )?ntp source(?:-interface)?\b/)
        source = effective_configured_value(/\Antp source(?:-interface)?\s+(\S+)\z/, entries: source_entries,
          family: /\A/, fact: "ntp.source", reset: /\Ano ntp source(?:-interface)?(?:\s+\S+)?\z/)
        record_fact("ntp.source", source, source_entries.last(1))
      end

      # 提取日志目标与源接口，厂商命令不进入事实归约层。
      def parse_syslog
        log_entries = matching_blocks(nxos? ? /\A(?:no )?logging server(?:\s|\z)/ : /\A(?:no )?logging host(?:\s|\z)/)
        log_pattern = nxos? ? /\Alogging server\s+(\S+)/ : /\Alogging host\s+(?:ipv6\s+)?((?!ipv6(?:\s|\z))\S+)/
        unless nxos?
          log_entries += matching_blocks(/\A(?:no )?logging\s+\d+(?:\.\d+){3}\z/)
          log_entries.sort_by!(&:index)
          log_pattern = /\Alogging\s+(?:host\s+(?:ipv6\s+)?)?((?!(?:host|ipv6)(?:\s|\z))\S+)/
        end
        hosts = configured_server_addresses("syslog.servers", log_pattern, log_entries, negate: "no") do |text, match, negative, entry|
          record_loghost_resource(match, negative, entry)
          [ match[1], text[/\b(?:use-vrf|vrf)\s+(\S+)/, 1] ]
        end
        record_fact("syslog.servers", hosts, log_entries)
        source_entries = matching_blocks(/\A(?:no )?logging source-interface\b/)
        source = effective_configured_value(/\Alogging source-interface\s+(\S+)\z/, entries: source_entries,
          family: /\A/, fact: "syslog.source", reset: /\Ano logging source-interface(?:\s+\S+)?\z/)
        record_fact("syslog.source", source, source_entries.last(1))
      end

      # NX-OS 的级别、VRF 与 IOS 的传输选项分别解释，不从尾部盲拼命令。
      def record_loghost_resource(match, negative, entry)
        tail = match.post_match.strip
        severity = tail[/\A([0-7])(?:\s|\z)/, 1] if nxos?
        tail = tail.sub(/\A[0-7](?:\s|\z)/, "") if severity
        names = nxos? ? %w[use-vrf facility] : %w[vrf transport]
        options = parse_server_options(tail, integers: { "port" => 1..65_535 }, names: names)
        scope = { "vrf" => entry.text[/\b(?:use-vrf|vrf)\s+(\S+)/, 1] || "default" }
        attributes = (options || {}).reject { |key, _| %w[use-vrf vrf].include?(key) }
        attributes["protocol"] = attributes.delete("transport") if attributes.key?("transport")
        attributes["severity"] = severity.to_i if severity
        complete = !options.nil? && [ *scope.values, *attributes.values.grep(String) ].all? { |value| ResourceSchema.token?(value) }
        complete &&= !attributes.key?("protocol") || %w[udp tcp].include?(attributes["protocol"])
        complete &&= !attributes.key?("facility") || /\A(?:local[0-7]|auth|authpriv|cron|daemon|ftp|kernel|lpr|mail|news|syslog|user|uucp)\z/.match?(attributes["facility"])
        return unless ResourceSchema.token?(scope["vrf"])

        resource = ConfigurationResource.new(kind: "syslog.destination", identity: { "address" => match[1] },
          scope: scope, attributes: complete ? attributes : {}, lines: [ entry.line ], complete: complete)
        @fact_builder.record_resource(resource, remove: negative)
      end

      # 提取轮询权限、用户安全属性及来源限制。
      def parse_snmp
        snmp_entries = matching_blocks(/\Asnmp-server\b/)
        enabled = nxos? ? configured_state(/\Asnmp-server protocol enable\z/, /\Ano snmp-server protocol enable\z/) : nil
        enabled = nxos? || snmp_entries.any? if enabled.nil? && (@fact_builder.complete? || snmp_entries.any?)
        record_fact("snmp.enabled", enabled)
        communities, community_acls = {}, {}
        configured_community_entries.each do |entry|
          match = /\Asnmp-server community\s+(\S+)(?:\s+(.*))?\z/.match(entry.text)
          unless match
            record_unknown_snmp_access([ entry ])
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
          unless nxos?
            access = (community_acls[match[1]] ||= { value: acl, conflicted: false })
            access[:conflicted] ||= access[:value] != acl
            if access[:conflicted]
              community.delete(:acl)
              record_unknown_fact("snmp.acl", [ entry ], code: :conflicting_community_acl)
            end
          end
          record_credential("snmp-community", "snmp", "plain", match[1], entry) unless @fact_builder.credential_recorded?(community[:line])
        end
        versions = communities.any? ? %w[v1 v2c] : []
        unsupported_groups = matching_blocks(/\Asnmp-server group\b/).reject do |entry|
          /\Asnmp-server group\s+\S+\s+v(?:1|2c|3)(?:\s|\z)/.match?(entry.text)
        end
        record_unknown_snmp_access(unsupported_groups, code: :unsupported_snmp_group) unless unsupported_groups.empty?
        groups = configured_snmp_groups(matching_blocks(/\Asnmp-server group\s+\S+\s+v3(?:\s|\z)/)) do |entry|
          name, settings = entry.text.match(/\Asnmp-server group\s+(.+?)\s+v3(?:\s+(.*))?\z/).captures
          write = name.include?('"') ? nil : snmp_group_write_state(settings.to_s)
          [ name, { acl: entry.text[/\baccess\s+(\S+)/, 1], line: entry.line, write: write } ]
        end
        record_fact("snmp.groups", groups)
        users = {}
        matching_blocks(/\Asnmp-server user\b/).each do |entry|
          match = /\Asnmp-server user\s+(\S+)\s+(\S+)(.*)\z/.match(entry.text)
          unless match
            record_unknown_snmp_access([ entry ])
            next
          end
          if nxos? && match[2] == "use-ipv4acl"
            user = users[match[1]] ||= { name: match[1], line: entry.line }
            user[:acl] = match[3].strip
            next
          end
          settings = match[3]
          if /\bv[12]c?\b/.match?(settings)
            record_unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
            next
          end
          unless nxos? || /\bv3\b/.match?(settings)
            record_unknown_snmp_access([ entry ])
            next
          end
          versions |= [ "v3" ]
          user = users[match[1]] ||= { name: match[1], line: entry.line }
          if nxos?
            (user[:roles] ||= []) << match[2]
            user[:roles].uniq!
            user[:write] = FactBuilder.write_permission_state(user[:roles].map { |role| SNMP_ROLE_WRITE[role] })
            next if settings.strip.empty?
          end
          modes = { auth: parse_snmp_secret(settings, "auth", algorithms: %w[md5 sha sha-224 sha-256 sha-384 sha-512]),
            priv: parse_snmp_secret(settings, "priv", algorithms: %w[des 3des aes aes-128 aes-192 aes-256], optional_algorithm: nxos?, aes_size: !nxos?) }
          security = record_snmp_credentials("snmp:#{match[1]}", modes, entry, format: /\bencrypted\b/.match?(settings) ? "cipher" : "unknown")
          user.merge!(security).merge!(group: match[2])
          acl = settings[/\b(?:access|use-ipv4acl)\s+(\S+)/, 1]
          user[:acl] = acl if acl
        end
        port_overrides = matching_blocks(/\A(?:no )?snmp-server (?:listen-port|udp-port|port)(?:\s|\z)/)
        record_unknown_listener_port("snmp.acl", port_overrides) unless port_overrides.empty?
        @fact_builder.record_snmp_access(communities: communities.values, users: users.values, groups: nxos? ? nil : groups,
          port: port_overrides.empty? ? 161 : nil)
        record_unverified_snmp_user_sync(users, enabled: enabled) if nxos?
        record_unknown_fact("snmp.v3_auth_priv", code: :snmp_user_unresolved) if users.values.any? { |user| !user.key?(:auth) }
        versions |= configured_values(/\Asnmp-server group\s+\S+\s+(v1|v2c|v3)\b/)
        legacy_groups = matching_blocks(/\Asnmp-server group\s+\S+\s+v(?:1|2c)\b/)
        if legacy_groups.any?
          @fact_builder.record_unknown_snmp_permission(lines: legacy_groups.map(&:line), code: :unsupported_snmp_group)
          record_unknown_fact("snmp.acl", legacy_groups, code: :unsupported_snmp_group)
        end
        record_fact("snmp.versions", versions) unless versions.empty?
      end

      # IOS 的 no 声明撤销整项团体字；先归约有效来源，避免留下访问或凭据事实。
      def configured_community_entries
        return matching_blocks(/\Asnmp-server community\b/) if nxos?

        active = {}
        matching_blocks(/\A(?:no )?snmp-server community\b/).each do |entry|
          if (match = /\Ano snmp-server community\s+(\S+)\z/.match(entry.text))
            analyze(entry) { active.delete(match[1]) }
          elsif entry.text.start_with?("no ")
            record_unknown_snmp_access([ entry ])
          else
            name = entry.text.split[2]
            (active[name] ||= []) << entry
          end
        end
        active.values.flatten.sort_by(&:line)
      end

      # NX-OS 通常会同步 CLI 与 SNMP 账号；缺少证据时不能构造虚拟用户。
      def record_unverified_snmp_user_sync(users, enabled:)
        return if enabled == false
        sync_disabled = configured_state(/\Asnmp-server disable snmp-aaa sync\z/, /\Ano snmp-server disable snmp-aaa sync\z/)
        return if sync_disabled == true

        matching_blocks(/\Ausername\s+/).group_by { |entry| entry.text.split[1] }.each do |name, entries|
          roles = entries.filter_map { |entry| entry.text[/\brole\s+(\S+)\s*\z/, 1] }.uniq
          covered = users[name]&.fetch(:roles, []) || []
          next if roles.any? && (roles - covered).empty?

          @fact_builder.record_unknown_snmp_permission(lines: entries.map(&:line), code: :snmp_user_sync_unconfirmed)
        end
      end

      # IOS 默认不授予写视图；不熟悉的组配置项不能证明只读权限。
      def snmp_group_write_state(settings)
        syntax = /\A(?:auth|noauth|priv)(?:\s+(?:read|(?<write>write)|notify|context)\s+[^\s"]+|\s+match\s+(?:exact|prefix)|\s+access(?:\s+ipv6)?\s+[^\s"]+)*\z/
        match = syntax.match(settings)
        return unless match

        !match[:write].nil?
      end

      # 解析实际生效的认证方法及外部服务器引用。
      def parse_authentication
        servers, aliases, keyed = [], {}, []
        global_key = matching_blocks(/\Atacacs-server key\s+/)
        global_key.each { |entry| record_tacacs_key("tacacs", entry.text.sub(/\Atacacs-server key\s+/, ""), entry) }
        legacy_hosts = matching_blocks(/\A(?:no )?tacacs-server host(?:\s|\z)/)
        hosts = configured_server_addresses("tacacs", /\Atacacs-server host\s+(\S+)/, legacy_hosts, negate: "no")
        servers |= hosts
        active_hosts = {}
        legacy_hosts.each do |entry|
          host = entry.text[/\A(?:no )?tacacs-server host\s+(\S+)/, 1]
          next unless server_address?(host)
          entry.text.start_with?("no ") ? active_hosts.delete(host) : active_hosts[host] = entry
        end
        active_hosts.each do |host, entry|
          key = entry.text[/\bkey\s+(.+)\z/, 1]
          if key
            record_tacacs_key("tacacs:#{host}", key, entry)
            keyed << host
          end
        end
        matching_blocks(/\Atacacs server\s+/).each do |section|
          hosts = configured_server_addresses("tacacs", /\Aaddress ipv[46]\s+(\S+)/, matching_blocks(/\A(?:no )?address ipv[46](?:\s|\z)/, section.children), negate: "no")
          aliases[section.text.split.last] = hosts
          servers |= hosts
          matching_blocks(/\Akey\s+/, section.children).each do |entry|
            record_tacacs_key("tacacs:#{section.text.split.last}", entry.text.delete_prefix("key "), entry)
            keyed |= hosts
          end
        end
        groups = matching_blocks(/\Aaaa group server tacacs\+\s+/).to_h do |section|
          members = configured_values(/\Aserver(?: name)?\s+(\S+)/, section.children)
          [ section.text.split.last, members.flat_map { |member| aliases.fetch(member, [ member ]) } ]
        end
        record_fact("tacacs.servers", servers.uniq)
        record_fact("tacacs.groups", groups)
        record_tacacs_login_usage(servers, groups)
        %w[authorization accounting].each { |kind| record_tacacs_action_usage(kind, servers, groups) }
        record_fact("tacacs.keys_present", global_key.any? || (servers - keyed).empty?) unless servers.empty?
        parse_local_accounts
      end

      # 授权和计费按动作及命令级别分别覆盖，只有全部最终声明都首选 TACACS 才确认使用。
      def record_tacacs_action_usage(kind, servers, groups)
        pattern = /\A(?:no )?aaa #{kind} (?:(exec|commands(?: \d+)?) )?default(?:\s|\z)/
        entries = matching_blocks(pattern).group_by { |entry| entry.text[pattern, 1] }.values.map(&:last)
        results = entries.map do |entry|
          match = /\Aaaa #{kind} (?:(?:exec|commands(?: \d+)?) )?default\s+(.+)\z/.match(entry.text)
          next :unsupported_authentication_method unless match

          methods = match[1]
          if kind == "accounting"
            next analyze(entry) { false } if methods == "none"
            methods = methods.sub(/\A(?:start-stop|stop-only)\s+/, "")
          end
          analyze(entry) { tacacs_login_method_state(methods, servers, groups) }
        end
        if (reason = results.find { |value| value.is_a?(Symbol) })
          record_unknown_fact("tacacs.#{kind}", entries, code: reason)
        else
          used = results.any? && results.all?(true)
          record_fact("tacacs.#{kind}", used, entries) if @fact_builder.complete? || used
        end
      end

      # 解析各 VTY 实际选用的登录列表，包括命名列表。
      def record_tacacs_login_usage(servers, groups)
        pattern = /\Aaaa authentication login\s+(\S+)\s+(.+)\z/
        family = /\A(?:no )?aaa authentication login\s+(\S+)(?:\s|\z)/
        lists = matching_blocks(family).each_with_object({}) do |entry, result|
          name = entry.text[family, 1]
          match = pattern.match(entry.text)
          # 最后同名声明决定列表证据；撤销或损坏不能复用先前的方法。
          methods = match ? analyze(entry) { match[2] } : nil
          result[name] = { methods: methods, entry: entry }
        end
        entries = @fact_builder.vtys.filter_map { |vty| lists[vty[:authentication_list]]&.fetch(:entry) }.uniq
        results = @fact_builder.vtys.map do |vty|
          if vty[:authentication].nil?
            :vty_authentication_unknown
          elsif vty[:authentication] != "aaa"
            false
          elsif (list = lists[vty[:authentication_list]])
            list[:methods] ? tacacs_login_method_state(list[:methods], servers, groups) : :authentication_list_unresolved
          else
            :authentication_list_unresolved
          end
        end
        results << :vty_authentication_unknown if results.empty?
        if results.include?(false)
          record_fact("tacacs.login", false, entries) if @fact_builder.complete?
        elsif (reason = results.find { |value| value.is_a?(Symbol) })
          record_unknown_fact("tacacs.login", entries, code: reason)
        else
          record_fact("tacacs.login", true, entries)
        end
      end

      # 仅当首选认证方法引用可解析的 TACACS 组时，才确认使用 TACACS。
      def tacacs_login_method_state(methods, servers, groups)
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
      def record_tacacs_key(owner, text, entry)
        match = /\A(?:(\d+)\s+)?(\S+)/.match(text)
        record_credential(owner, "tacacs", match&.[](1) || "plain", match&.[](2), entry)
      end

      # 提取本地账号角色及凭据存储属性。
      def parse_local_accounts
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

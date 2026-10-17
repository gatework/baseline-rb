# frozen_string_literal: true

require_relative "../parser"

require "shellwords"
require_relative "document"

module Baseline
  module PaloAlto
    # 将 PAN-OS set 语法归纳为与配置块平台一致的事实。
    class Parser < Baseline::Parser
      MANAGEMENT_SERVICES = %w[ssh telnet http https].freeze
      RELEVANT = /\Aset (?:deviceconfig system |network (?:profiles interface-management-profile |interface )|shared (?:server-profile tacplus |authentication-profile |authentication-sequence |log-settings syslog )|mgt-config users )/

      private

      # 选择适合当前平台语法的文档词法解析器。
      def document_class = Document
      # 匹配当前平台显式声明的主机名。
      def hostname_pattern = /\Aset deviceconfig system hostname\s+(\S+)\z/

      # 仅对管理配置子集分词一次，不处理无关的安全规则。
      def prepare_configuration
        @statements = roots.filter_map do |entry|
          next unless RELEVANT.match?(entry.text)
          { entry: entry, tokens: Shellwords.shellsplit(entry.text).drop(1) }
        rescue ArgumentError
          @facts.incomplete!(code: :invalid_set_statement, lines: [ entry.line ])
          nil
        end
        @interface_profiles = rows("network", "profiles", "interface-management-profile").group_by { |row| row[:tokens][3] }
        @unresolved_profile_bindings = false
        @profile_bindings = rows("network", "interface").select do |row|
          index = row[:tokens].index("interface-management-profile")
          next false unless index
          valid = row[:tokens].size == index + 2 && !row[:tokens].last.empty?
          unless valid
            @unresolved_profile_bindings = true
            @facts.incomplete!(code: :invalid_management_profile_binding, lines: [ row[:entry].line ])
          end
          valid
        end
        @active_profiles = @profile_bindings.map { |row| row[:tokens].last }.uniq
      end

      # 覆盖所有已配置的管理端点，包括数据接口。
      def management
        services = (MANAGEMENT_SERVICES + [ "snmp" ]).to_h { |name| [ name, service_state(name) ] }
        record("ssh.enabled", services["ssh"], service_entries([ "ssh" ]))
        record("services", services.slice("telnet", "http", "https"), service_entries(%w[telnet http https]))
        record("snmp.enabled", services["snmp"], service_entries([ "snmp" ]))
        permitted_sources("management.acl", MANAGEMENT_SERVICES)
        permitted_sources("snmp.acl", [ "snmp" ])
      end

      # MGT 服务标志缺失时保持未知；明确启用的端点可证明服务已启用。
      def service_state(name)
        disabled = boolean(%w[deviceconfig system service] + [ "disable-#{name}" ])
        global = disabled.nil? ? nil : !disabled
        values = @active_profiles.map { |profile| profile_service(profile, name) }
        return true if global == true || values.include?(true)
        return false if global == false && values.all?(false)

        nil
      end

      # 保留参与跨端点服务事实归纳的显式声明。
      def service_entries(names)
        names.flat_map do |name|
          rows(*(%w[deviceconfig system service] + [ "disable-#{name}" ])) + @active_profiles.flat_map do |profile|
            rows("network", "profiles", "interface-management-profile", profile, name)
          end
        end.map { |row| row[:entry] }
      end

      # 仅解释命名接口配置文件中显式声明的服务。
      def profile_service(profile, name)
        return unless @interface_profiles.key?(profile)
        prefix = [ "network", "profiles", "interface-management-profile", profile, name ]
        value = boolean(prefix)
        return value unless value.nil?
        return if rows(*prefix).any?
        return false if value.nil? && @facts.complete?

        nil
      end

      # 端点的原生允许列表适用于该端点所有已启用服务。
      def permitted_sources(fact, services)
        global = services.map { |name| boolean(%w[deviceconfig system service] + [ "disable-#{name}" ]) }
        prefixes = global.all?(true) ? [] : [ %w[deviceconfig system permitted-ip] ]
        unresolved = @unresolved_profile_bindings
        @active_profiles.each do |profile|
          enabled = services.map { |name| profile_service(profile, name) }
          unresolved ||= enabled.include?(nil)
          prefixes << [ "network", "profiles", "interface-management-profile", profile, "permitted-ip" ] if enabled.include?(true)
        end
        entries = []
        sources = prefixes.flat_map do |prefix|
          matches = rows(*prefix)
          entries.concat(matches.map { |row| row[:entry] })
          matches.empty? ? [ "0.0.0.0/0" ] : matches.map do |row|
            tokens = row[:tokens].drop(prefix.size)
            unless tokens.size == 1 || tokens.size == 3 && tokens[1] == "description"
              unresolved = true
              next
            end
            network = IPAddr.new(tokens.first)
            unless network.ipv4?
              unresolved = true
              next
            end
            analyze(row[:entry]) { "#{network}/#{network.prefix}" }
          rescue IPAddr::Error, ArgumentError
            unresolved = true
            nil
          end
        end.compact
        bound = !sources.include?("0.0.0.0/0")
        @facts.direct_acl(fact: fact, sources: unresolved ? nil : sources, bound: bound, lines: entries.map(&:line))
        unknown("#{fact}.bound", code: :management_profile_unresolved) if unresolved
        cursor.capture_many(entries.select { |entry| cursor.parsed?(entry.index) }, data: sources, path: [ "facts", "#{fact}.sources" ]) unless unresolved
      end

      # 采集明确启用或禁用的管理服务。
      def services
        ntp
        syslog
        snmp
      end

      # 认证要求必须覆盖全部已配置服务器，不能由任意一台满足来证明。
      def ntp
        entries = rows("deviceconfig", "system", "ntp-servers")
        servers = entries.group_by { |row| row[:tokens][3] }.filter_map do |name, definitions|
          prefix = [ "deviceconfig", "system", "ntp-servers", name ]
          address = endpoint(prefix + [ "ntp-server-address" ])
          unless address && %w[primary-ntp-server secondary-ntp-server].include?(name)
            unknown("ntp.servers", definitions.map { |row| row[:entry] }, code: :ntp_server_unresolved)
            unknown("ntp.authentication", definitions.map { |row| row[:entry] }, code: :ntp_server_unresolved)
            next
          end
          { address: address, authenticated: ntp_authentication(prefix) }
        end
        record("ntp.servers", servers.map { |server| server[:address] }.uniq, entries.map { |row| row[:entry] })
        if servers.any? && servers.none? { |server| server[:authenticated].nil? }
          record("ntp.authentication", servers.all? { |server| server[:authenticated] }, entries.map { |row| row[:entry] })
        end
        record_scalar("ntp.source", %w[deviceconfig system route service ntp source interface])
      end

      # 仅完整的认证声明才能证明所有服务器均满足认证要求。
      def ntp_authentication(prefix)
        entries = rows(*(prefix + [ "authentication-type" ]))
        options = entries.map { |row| row[:tokens].drop(prefix.size + 1) }.uniq
        return if options.empty?
        return false if options == [ [ "none" ] ]
        return true if options == [ [ "autokey" ] ]
        key = options.find { |parts| parts.take(2) == %w[symmetric-key algorithm] }
        id = options.find { |parts| parts.take(2) == %w[symmetric-key key-id] }
        if options.size == 2 && key && id && key.size == 5 && %w[md5 sha1 sha256 sha512].include?(key[2]) &&
            key[3] == "authentication-key" && !key[4].empty? && id.size == 3 && /\A\d+\z/.match?(id[2]) && id[2].to_i.between?(1, 65_534)
          return true
        end
        unknown("ntp.authentication", entries.map { |row| row[:entry] }, code: :unsupported_ntp_authentication)
        nil
      end

      # 配置的采集端地址与运行时日志转发成功是两类事实。
      def syslog
        entries = rows("shared", "log-settings", "syslog").select { |row| row[:tokens][4] == "server" }
        servers = entries.group_by { |row| [ row[:tokens][3], row[:tokens][5] ] }.values.filter_map do |definitions|
          address = definitions.reverse.find { |row| row[:tokens][6] == "server" }
          value = address && endpoint(address[:tokens].take(7))
          unknown("syslog.servers", definitions.map { |row| row[:entry] }, code: :syslog_server_unresolved) unless value
          value
        end
        record("syslog.servers", servers.uniq, entries.map { |row| row[:entry] })
        record_scalar("syslog.source", %w[deviceconfig system route service syslog source interface])
      end

      # 轮询用户、团体字与出站 SNMP Trap 配置相互独立。
      def snmp
        prefix = %w[deviceconfig system snmp-setting access-setting version]
        versions = rows(*prefix).map { |row| row[:tokens][prefix.size] }.compact.uniq
        record("snmp.versions", versions)
        communities = rows(*(prefix + %w[v2c snmp-community-string])).filter_map do |row|
          unless row[:tokens].size == prefix.size + 3 && !row[:tokens].last.empty?
            @facts.incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
            next
          end
          record_credential("snmp-community", "snmp", secret_format(row[:tokens].last), row[:tokens].last, row[:entry])
          { write: false, line: row[:entry].line }
        end
        users_prefix = prefix + %w[v3 users]
        users = rows(*users_prefix).group_by { |row| row[:tokens][users_prefix.size] }.filter_map do |name, entries|
          next unless name
          user = { name: name, auth: false, priv: false, write: false, line: entries.first[:entry].line }
          { "authpwd" => :auth, "privpwd" => :priv }.each do |field, key|
            row = entries.reverse.find { |entry| entry[:tokens][users_prefix.size + 1] == field }
            next unless row
            unless row[:tokens].size == users_prefix.size + 3 && !row[:tokens].last.empty?
              @facts.incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
              next
            end
            user[key] = !row[:tokens].last.empty?
            record_credential("snmp:#{name}", "snmp_user", secret_format(row[:tokens].last), row[:tokens].last, row[:entry])
          end
          user
        end
        @facts.snmp(communities: communities, users: users)
        if (versions - %w[v2c v3]).any? || versions.size > 1
          unknown_snmp_access(rows(*prefix).map { |row| row[:entry] }, code: :unsupported_snmp_version)
        end
      end

      # 将选中的登录配置或有序认证序列解析为 TACACS 服务器。
      def authentication
        server_rows = rows("shared", "server-profile", "tacplus")
        schemes = server_rows.group_by { |row| row[:tokens][3] }.to_h do |name, entries|
          servers = entries.select { |row| row[:tokens][4] == "server" }.group_by { |row| row[:tokens][5] }
          addresses = servers.values.filter_map do |server|
            address = server.reverse.find { |row| row[:tokens][6] == "address" }
            value = address && endpoint(address[:tokens].take(7))
            unknown("tacacs.servers", server.map { |row| row[:entry] }, code: :tacacs_server_unresolved) unless value
            value
          end
          unknown("tacacs.servers", entries.map { |row| row[:entry] }, code: :tacacs_server_unresolved) if servers.empty?
          keys = servers.values.map do |server|
            secret = server.reverse.find { |row| row[:tokens][6] == "secret" }
            value = secret && scalar(secret[:tokens].take(7))
            record_credential("tacacs:#{name}", "tacacs", secret_format(value), value, secret[:entry]) if value
            !value.to_s.empty?
          end
          [ name, { servers: addresses, keys_present: keys.any? && keys.all?, line: entries.first[:entry].line } ]
        end
        record("tacacs.schemes", schemes)
        record("tacacs.servers", schemes.values.flat_map { |scheme| scheme[:servers] }.uniq)
        record("tacacs.keys_present", schemes.values.all? { |scheme| scheme[:keys_present] }) if schemes.any?
        selected = scalar(%w[deviceconfig system authentication-profile])
        login = selected ? tacacs_profile(selected, schemes) : false
        login.nil? ? unknown("tacacs.login", code: :tacacs_scheme_unresolved) : record("tacacs.login", login)
        # PAN-OS 角色映射与命令计费不能套用路由器式 AAA 开关语义。
        %w[authorization accounting].each { |kind| unknown("tacacs.#{kind}", code: :platform_semantics_unresolved) }
        accounts
      end

      # 认证序列具有顺序；后备 TACACS 不能视为首选 TACACS 登录。
      def tacacs_profile(name, schemes)
        prefix = [ "shared", "authentication-profile", name, "method" ]
        methods = rows(*prefix)
        if methods.empty?
          sequence = rows("shared", "authentication-sequence", name, "authentication-profiles").last
          return unless sequence
          names = sequence[:tokens].drop(4).reject { |token| %w[[ ]].include?(token) }
          return if names.empty? || names.first == name
          return tacacs_profile_definition(names.first, schemes)
        end
        tacacs_profile_definition(name, schemes)
      end

      # 选中的 TACACS 配置必须至少解析出一台具有地址的服务器。
      def tacacs_profile_definition(name, schemes)
        prefix = [ "shared", "authentication-profile", name, "method" ]
        methods = rows(*prefix)
        return if methods.empty?
        kinds = methods.map { |row| row[:tokens][4] }.uniq
        return unless kinds.one?
        return false if %w[none local-database radius ldap kerberos saml-idp cloud].include?(kinds.first)
        return unless kinds.first == "tacplus"
        target = scalar(prefix + %w[tacplus server-profile])
        return unless target && schemes[target] && schemes[target][:servers].any?

        true
      end

      # 仅存储凭据元数据，导出的加密值不进入报告。
      def accounts
        rows("mgt-config", "users").group_by { |row| row[:tokens][2] }.each do |name, entries|
          row = entries.reverse.find { |entry| entry[:tokens][3] == "phash" }
          unless row
            external_profile = scalar([ "mgt-config", "users", name, "authentication-profile" ])
            record_credential(name, "local_user", "unknown", nil, entries.first[:entry]) unless external_profile && !external_profile.empty?
            next
          end
          secret = scalar(row[:tokens].take(4))
          format = if /\A\$(?:1|5|6)\$[^$]+\$[^$]+\z/.match?(secret.to_s)
            secret.start_with?("$1$") ? "5" : "hash"
          else
            "unknown"
          end
          record_credential(name, "local_user", format, secret, row[:entry])
        end
      end

      # 识别 PAN-OS 带标记的加密 set 值；其余情况保留明文风险。
      def secret_format(value) = value.start_with?("-AQ", "-AR") ? "cipher" : "plain"

      # 按词元前缀选择归一化后的 PAN-OS set 命令行。
      def rows(*prefix)
        @statements.select { |row| row[:tokens].take(prefix.size) == prefix }
      end

      # 地址仅接受 IP 或 DNS 名称，不接受不完整转义或任意文本。
      def endpoint(prefix)
        value = scalar(prefix)
        return if value.nil?
        return value if server_address?(value)

        @facts.incomplete!(code: :invalid_server_address, lines: rows(*prefix).map { |row| row[:entry].line })
        nil
      end

      # 显式标志格式错误时，不能用平台默认值替代。
      def boolean(prefix)
        value = scalar(prefix)
        return if value.nil?
        return value == "yes" if %w[yes no].include?(value)

        @facts.incomplete!(code: :invalid_set_statement, lines: rows(*prefix).map { |row| row[:entry].line })
        nil
      end

      # 标量语法与事实来源共享同一条最终声明。
      def record_scalar(path, prefix)
        row = rows(*prefix).last
        record(path, scalar(prefix), row ? [ row[:entry] ] : [])
      end

      # 严格校验词元数量，避免尾随内容使错误配置被误判为已知事实。
      def scalar(prefix)
        row = rows(*prefix).last
        return unless row
        unless row[:tokens].size == prefix.size + 1
          @facts.incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
          return
        end

        analyze(row[:entry]) { row[:tokens].last }
      end
    end
  end
end

# frozen_string_literal: true

require_relative "../parser"

require "shellwords"
require_relative "document"
require_relative "command_index"

module Baseline
  module PaloAlto
    # 将 PAN-OS set 语法归纳为与配置块平台一致的事实。
    class Parser < Baseline::Parser
      # 原生管理端点没有 VTY 模型；未建模能力保留未知，不改变规则适用范围。
      UNSUPPORTED_FACTS = {
        "ssh.versions" => :ssh_version_unmodeled,
        "ssh.vty_ssh_only" => :native_management_endpoint,
        "ssh.vty_aaa" => :native_management_endpoint,
        "tacacs.authorization" => :platform_semantics_unresolved,
        "tacacs.accounting" => :platform_semantics_unresolved
      }.freeze
      PARTIAL_FACTS = { "services" => :service_states_partially_modeled }.freeze

      MANAGEMENT_SERVICES = %w[ssh telnet http https].freeze
      RELEVANT = /\Aset (?:deviceconfig system |network (?:profiles interface-management-profile |interface )|shared (?:server-profile tacplus |authentication-profile |authentication-sequence |log-settings syslog )|mgt-config users )/

      private

      # 选择适合当前平台语法的文档词法解析器。
      def document_class = Document
      # 匹配当前平台显式声明的主机名。
      def hostname_pattern = /\Aset deviceconfig system hostname\s+(\S+)\z/
      # set 语法使用独立的设备身份命令族。
      def hostname_family_pattern = /\Aset deviceconfig system hostname(?:\s|\z)/

      # 仅对管理配置子集分词一次，不处理无关的安全规则。
      def prepare_configuration
        statements = roots.filter_map do |entry|
          next unless RELEVANT.match?(entry.text)
          { entry: entry, tokens: Shellwords.shellsplit(entry.text).drop(1) }
        rescue ArgumentError
          @fact_builder.mark_incomplete!(code: :invalid_set_statement, lines: [ entry.line ])
          nil
        end
        @command_index = CommandIndex.new(statements)
        @interface_profiles = statements_with_prefix("network", "profiles", "interface-management-profile").group_by { |row| row[:tokens][3] }
        @unresolved_profile_bindings = false
        # 同一接口作用域只保留最后绑定，其他接口继续独立参与管理端点归约。
        bindings = statements_with_prefix("network", "interface").select { |row| row[:tokens].include?("interface-management-profile") }
          .group_by { |row| row[:tokens].take(row[:tokens].index("interface-management-profile")) }.values.map(&:last)
        @profile_bindings = bindings.select do |row|
          index = row[:tokens].index("interface-management-profile")
          next false unless index
          valid = row[:tokens].size == index + 2 && !row[:tokens].last.empty?
          unless valid
            @unresolved_profile_bindings = true
            @fact_builder.mark_incomplete!(code: :invalid_management_profile_binding, lines: [ row[:entry].line ])
          end
          valid
        end
        @active_profiles = @profile_bindings.map { |row| row[:tokens].last }.uniq
      end

      # 覆盖所有已配置的管理端点，包括数据接口。
      def parse_management
        service_states = (MANAGEMENT_SERVICES + [ "snmp" ]).to_h { |name| [ name, service_state(name) ] }
        record_fact("ssh.enabled", service_states["ssh"], service_entries([ "ssh" ]))
        record_fact("services", service_states.slice("telnet", "http", "https"), service_entries(%w[telnet http https]))
        record_fact("snmp.enabled", service_states["snmp"], service_entries([ "snmp" ]))
        record_permitted_sources("management.acl", MANAGEMENT_SERVICES)
        record_permitted_sources("snmp.acl", [ "snmp" ])
      end

      # MGT 服务标志缺失时保持未知；明确启用的端点可证明服务已启用。
      def service_state(name)
        disabled = configured_boolean(%w[deviceconfig system service] + [ "disable-#{name}" ])
        global = disabled.nil? ? nil : !disabled
        values = @active_profiles.map { |profile| profile_service_state(profile, name) }
        return true if global == true || values.include?(true)
        return false if global == false && values.all?(false)

        nil
      end

      # 保留参与跨端点服务事实归纳的显式声明。
      def service_entries(names)
        names.flat_map do |name|
          statements_with_prefix(*(%w[deviceconfig system service] + [ "disable-#{name}" ])) + @active_profiles.flat_map do |profile|
            statements_with_prefix("network", "profiles", "interface-management-profile", profile, name)
          end
        end.map { |row| row[:entry] }
      end

      # 仅解释命名接口配置文件中显式声明的服务。
      def profile_service_state(profile, name)
        return unless @interface_profiles.key?(profile)
        prefix = [ "network", "profiles", "interface-management-profile", profile, name ]
        value = configured_boolean(prefix)
        return value unless value.nil?
        return if statements_with_prefix(*prefix).any?
        return false if value.nil? && @fact_builder.complete?

        nil
      end

      # 端点的原生允许列表适用于该端点所有已启用服务。
      def record_permitted_sources(fact, service_names)
        global = service_names.map { |name| configured_boolean(%w[deviceconfig system service] + [ "disable-#{name}" ]) }
        prefixes = global.all?(true) ? [] : [ %w[deviceconfig system permitted-ip] ]
        unresolved = @unresolved_profile_bindings
        @active_profiles.each do |profile|
          enabled = service_names.map { |name| profile_service_state(profile, name) }
          unresolved ||= enabled.include?(nil)
          prefixes << [ "network", "profiles", "interface-management-profile", profile, "permitted-ip" ] if enabled.include?(true)
        end
        entries = []
        sources = prefixes.flat_map do |prefix|
          matches = statements_with_prefix(*prefix)
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
        @fact_builder.record_source_restriction(fact: fact, sources: unresolved ? nil : sources, bound: bound, lines: entries.map(&:line))
        record_unknown_fact("#{fact}.bound", code: :management_profile_unresolved) if unresolved
        cursor.capture_many(entries.select { |entry| cursor.parsed?(entry.index) }, data: sources, path: [ "facts", "#{fact}.sources" ]) unless unresolved
      end

      # 认证要求必须覆盖全部已配置服务器，不能由任意一台满足来证明。
      def parse_ntp
        entries = statements_with_prefix("deviceconfig", "system", "ntp-servers")
        servers = entries.group_by { |row| row[:tokens][3] }.filter_map do |name, definitions|
          prefix = [ "deviceconfig", "system", "ntp-servers", name ]
          address = configured_server_address(prefix + [ "ntp-server-address" ])
          unless address && %w[primary-ntp-server secondary-ntp-server].include?(name)
            record_unknown_fact("ntp.servers", definitions.map { |row| row[:entry] }, code: :ntp_server_unresolved)
            record_unknown_fact("ntp.authentication", definitions.map { |row| row[:entry] }, code: :ntp_server_unresolved)
            next
          end
          authenticated = ntp_authentication_state(prefix)
          attributes = { "address" => address }
          attributes["authenticated"] = authenticated unless authenticated.nil?
          resource = ConfigurationResource.new(kind: "ntp.association", identity: { "name" => name }, attributes: attributes,
            lines: definitions.map { |row| row[:entry].line }, complete: !authenticated.nil?)
          @fact_builder.record_resource(resource)
          { address: address, authenticated: authenticated }
        end
        record_fact("ntp.servers", servers.map { |server| server[:address] }.uniq, entries.map { |row| row[:entry] })
        if servers.any? && servers.none? { |server| server[:authenticated].nil? }
          record_fact("ntp.authentication", servers.all? { |server| server[:authenticated] }, entries.map { |row| row[:entry] })
        end
        record_configured_scalar("ntp.source", %w[deviceconfig system route service ntp source interface])
        record_route_source_address_presence("ntp")
      end

      # 仅完整的认证声明才能证明所有服务器均满足认证要求。
      def ntp_authentication_state(prefix)
        entries = statements_with_prefix(*(prefix + [ "authentication-type" ]))
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
        record_unknown_fact("ntp.authentication", entries.map { |row| row[:entry] }, code: :unsupported_ntp_authentication)
        nil
      end

      # 配置的采集端地址与运行时日志转发成功是两类事实。
      def parse_syslog
        entries = statements_with_prefix("shared", "log-settings", "syslog").select { |row| row[:tokens][4] == "server" }
        servers = entries.group_by { |row| [ row[:tokens][3], row[:tokens][5] ] }.values.filter_map do |definitions|
          address = definitions.reverse.find { |row| row[:tokens][6] == "server" }
          value = address && configured_server_address(address[:tokens].take(7))
          record_unknown_fact("syslog.servers", definitions.map { |row| row[:entry] }, code: :syslog_server_unresolved) unless value
          record_syslog_resource(definitions, value) if value
          value
        end
        record_fact("syslog.servers", servers.uniq, entries.map { |row| row[:entry] })
        record_configured_scalar("syslog.source", %w[deviceconfig system route service syslog source interface])
        record_route_source_address_presence("syslog")
      end

      # 切换服务路由接口时，已有显式源地址必须单独核对，不能静默保留错误绑定。
      def record_route_source_address_presence(service)
        rows = statements_with_prefix("deviceconfig", "system", "route", "service", service, "source", "address")
        record_fact("#{service}.source_address_present", rows.any?, rows.map { |row| row[:entry] }) if @fact_builder.complete? || rows.any?
      end

      # 命名配置对象按叶子最后值归约，未知字段不进入公开资源数据。
      def record_syslog_resource(definitions, address)
        profile, name = definitions.first[:tokens].values_at(3, 5)
        unless [ profile, name ].all? { |value| ResourceSchema.token?(value) }
          record_unknown_fact("syslog.destinations", definitions.map { |row| row[:entry] }, code: :unsupported_resource_identity)
          return
        end
        attributes = { "address" => address }
        complete = true
        definitions.group_by { |row| row[:tokens][6] }.each do |field, rows|
          row = rows.last
          value = row[:tokens][7]
          valid = row[:tokens].size == 8
          valid &&= case field
          when "server" then ResourceSchema.address?(value)
          when "port" then /\A\d+\z/.match?(value.to_s) && value.to_i.between?(1, 65_535)
          when "transport" then %w[UDP TCP SSL].include?(value)
          when "facility" then /\ALOG_(?:USER|LOCAL[0-7])\z/.match?(value.to_s)
          when "format" then %w[BSD IETF].include?(value)
          else false
          end
          complete &&= valid
          next unless valid && field != "server"
          key = field == "transport" ? "protocol" : field
          attributes[key] = field == "port" ? value.to_i : field == "transport" ? value.downcase : value
        end
        resource = ConfigurationResource.new(kind: "syslog.destination", identity: { "name" => name }, scope: { "profile" => profile },
          attributes: attributes, lines: definitions.map { |row| row[:entry].line }, complete: complete)
        @fact_builder.record_resource(resource)
      end

      # 轮询用户、团体字与出站 SNMP Trap 配置相互独立。
      def parse_snmp
        prefix = %w[deviceconfig system snmp-setting access-setting version]
        versions = statements_with_prefix(*prefix).map { |row| row[:tokens][prefix.size] }.compact.uniq
        record_fact("snmp.versions", versions)
        communities = statements_with_prefix(*(prefix + %w[v2c snmp-community-string])).filter_map do |row|
          unless row[:tokens].size == prefix.size + 3 && !row[:tokens].last.empty?
            @fact_builder.mark_incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
            next
          end
          record_credential("snmp-community", "snmp", credential_storage_format(row[:tokens].last), row[:tokens].last, row[:entry])
          { write: false, line: row[:entry].line }
        end
        users_prefix = prefix + %w[v3 users]
        users = statements_with_prefix(*users_prefix).group_by { |row| row[:tokens][users_prefix.size] }.filter_map do |name, entries|
          next unless name
          user = { name: name, auth: false, priv: false, write: false, line: entries.first[:entry].line }
          { "authpwd" => :auth, "privpwd" => :priv }.each do |field, key|
            row = entries.reverse.find { |entry| entry[:tokens][users_prefix.size + 1] == field }
            next unless row
            unless row[:tokens].size == users_prefix.size + 3 && !row[:tokens].last.empty?
              @fact_builder.mark_incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
              next
            end
            user[key] = !row[:tokens].last.empty?
            record_credential("snmp:#{name}", "snmp_user", credential_storage_format(row[:tokens].last), row[:tokens].last, row[:entry],
              purpose: key == :auth ? "authentication" : "privacy")
          end
          user
        end
        @fact_builder.record_snmp_access(communities: communities, users: users)
        if (versions - %w[v2c v3]).any? || versions.size > 1
          record_unknown_snmp_access(statements_with_prefix(*prefix).map { |row| row[:entry] }, code: :unsupported_snmp_version)
        end
      end

      # 将选中的登录配置或有序认证序列解析为 TACACS 服务器。
      def parse_authentication
        server_rows = statements_with_prefix("shared", "server-profile", "tacplus")
        schemes = server_rows.group_by { |row| row[:tokens][3] }.to_h do |name, entries|
          servers = entries.select { |row| row[:tokens][4] == "server" }.group_by { |row| row[:tokens][5] }
          addresses = servers.values.filter_map do |server|
            address = server.reverse.find { |row| row[:tokens][6] == "address" }
            value = address && configured_server_address(address[:tokens].take(7))
            record_unknown_fact("tacacs.servers", server.map { |row| row[:entry] }, code: :tacacs_server_unresolved) unless value
            record_tacacs_endpoint(name, server, value) if value
            value
          end
          record_unknown_fact("tacacs.servers", entries.map { |row| row[:entry] }, code: :tacacs_server_unresolved) if servers.empty?
          keys = servers.values.map do |server|
            secret = server.reverse.find { |row| row[:tokens][6] == "secret" }
            value = secret && configured_scalar(secret[:tokens].take(7))
            record_credential("tacacs:#{name}", "tacacs", credential_storage_format(value), value, secret[:entry]) if value
            !value.to_s.empty?
          end
          [ name, { servers: addresses, keys_present: keys.any? && keys.all?, line: entries.first[:entry].line } ]
        end
        record_fact("tacacs.schemes", schemes)
        record_fact("tacacs.servers", schemes.values.flat_map { |scheme| scheme[:servers] }.uniq)
        record_fact("tacacs.keys_present", schemes.values.all? { |scheme| scheme[:keys_present] }) if schemes.any?
        selected = configured_scalar(%w[deviceconfig system authentication-profile])
        login = selected ? tacacs_login_state(selected, schemes) : false
        login.nil? ? record_unknown_fact("tacacs.login", code: :tacacs_scheme_unresolved) : record_fact("tacacs.login", login)
        parse_local_accounts
      end

      # 命名服务器地址可独立修改；秘密叶子仅贡献配置存在性。
      def record_tacacs_endpoint(profile, rows, address)
        attributes = { "address" => address }
        complete = true
        rows.group_by { |row| row[:tokens][6] }.each do |field, definitions|
          row = definitions.last
          value = row[:tokens][7]
          case field
          when "address"
            complete &&= row[:tokens].size == 8 && ResourceSchema.address?(value)
          when "port"
            valid = row[:tokens].size == 8 && /\A\d+\z/.match?(value.to_s) && value.to_i.between?(1, 65_535)
            complete &&= valid
            attributes["port"] = value.to_i if valid
          when "secret"
            valid = row[:tokens].size == 8 && value.is_a?(String) && !value.empty?
            attributes["key_present"] = valid
            complete &&= valid
          else
            complete = false
          end
        end
        record_tacacs_resource(identity: { "name" => rows.first[:tokens][5] }, scope: { "profile" => profile },
          attributes: attributes, entry: rows.first[:entry], complete: complete)
      end

      # 认证序列具有顺序；后备 TACACS 不能视为首选 TACACS 登录。
      def tacacs_login_state(name, schemes)
        prefix = [ "shared", "authentication-profile", name, "method" ]
        methods = statements_with_prefix(*prefix)
        if methods.empty?
          sequence = statements_with_prefix("shared", "authentication-sequence", name, "authentication-profiles").last
          return unless sequence
          names = sequence[:tokens].drop(4).reject { |token| %w[[ ]].include?(token) }
          return if names.empty? || names.first == name
          return authentication_profile_tacacs_state(names.first, schemes)
        end
        authentication_profile_tacacs_state(name, schemes)
      end

      # 选中的 TACACS 配置必须至少解析出一台具有地址的服务器。
      def authentication_profile_tacacs_state(name, schemes)
        prefix = [ "shared", "authentication-profile", name, "method" ]
        methods = statements_with_prefix(*prefix)
        return if methods.empty?
        kinds = methods.map { |row| row[:tokens][4] }.uniq
        return unless kinds.one?
        return false if %w[none local-database radius ldap kerberos saml-idp cloud].include?(kinds.first)
        return unless kinds.first == "tacplus"
        target = configured_scalar(prefix + %w[tacplus server-profile])
        return unless target && schemes[target] && schemes[target][:servers].any?

        true
      end

      # 仅存储凭据元数据，导出的加密值不进入报告。
      def parse_local_accounts
        statements_with_prefix("mgt-config", "users").group_by { |row| row[:tokens][2] }.each do |name, entries|
          row = entries.reverse.find { |entry| entry[:tokens][3] == "phash" }
          unless row
            external_profile = configured_scalar([ "mgt-config", "users", name, "authentication-profile" ])
            record_credential(name, "local_user", "unknown", nil, entries.first[:entry]) unless external_profile && !external_profile.empty?
            next
          end
          secret = configured_scalar(row[:tokens].take(4))
          format = if /\A\$(?:1|5|6)\$[^$]+\$[^$]+\z/.match?(secret.to_s)
            secret.start_with?("$1$") ? "5" : "hash"
          else
            "unknown"
          end
          record_credential(name, "local_user", format, secret, row[:entry])
        end
      end

      # 识别 PAN-OS 带标记的加密 set 值；其余情况保留明文风险。
      def credential_storage_format(value) = value.start_with?("-AQ", "-AR") ? "cipher" : "plain"

      # 按词元前缀选择归一化后的 PAN-OS set 命令行。
      def statements_with_prefix(*prefix)
        @command_index.matching_prefix(prefix)
      end

      # 地址仅接受 IP 或 DNS 名称，不接受不完整转义或任意文本。
      def configured_server_address(prefix)
        value = configured_scalar(prefix)
        return if value.nil?
        return value if server_address?(value)

        @fact_builder.mark_incomplete!(code: :invalid_server_address, lines: statements_with_prefix(*prefix).map { |row| row[:entry].line })
        nil
      end

      # 显式标志格式错误时，不能用平台默认值替代。
      def configured_boolean(prefix)
        value = configured_scalar(prefix)
        return if value.nil?
        return value == "yes" if %w[yes no].include?(value)

        @fact_builder.mark_incomplete!(code: :invalid_set_statement, lines: statements_with_prefix(*prefix).map { |row| row[:entry].line })
        nil
      end

      # 标量语法与事实来源共享同一条最终声明。
      def record_configured_scalar(path, prefix)
        row = statements_with_prefix(*prefix).last
        record_fact(path, configured_scalar(prefix), row ? [ row[:entry] ] : [])
      end

      # 严格校验词元数量，避免尾随内容使错误配置被误判为已知事实。
      def configured_scalar(prefix)
        row = statements_with_prefix(*prefix).last
        return unless row
        unless row[:tokens].size == prefix.size + 1
          @fact_builder.mark_incomplete!(code: :invalid_set_statement, lines: [ row[:entry].line ])
          return
        end

        analyze(row[:entry]) { row[:tokens].last }
      end
    end
  end
end

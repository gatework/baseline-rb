# frozen_string_literal: true

require_relative "../parser"

require "shellwords"
require_relative "document"

module Baseline
  module Hillstone
    # StoneOS 管理端点与原生主机允许列表不同于路由器 VTY。
    class Parser < Baseline::Parser
      # 原生管理端点没有 VTY 模型；未建模能力保留未知，不改变规则适用范围。
      UNSUPPORTED_FACTS = {
        "ssh.versions" => :ssh_version_unmodeled,
        "ssh.vty_ssh_only" => :native_management_endpoint,
        "ssh.vty_aaa" => :native_management_endpoint,
        "tacacs.accounting" => :platform_semantics_unresolved
      }.freeze
      PARTIAL_FACTS = { "services" => :service_states_partially_modeled }.freeze

      MANAGEMENT_SERVICES = %w[ssh telnet http https ftp snmp].freeze
      HOST_PROTOCOLS = %w[ssh telnet http https netconf any].freeze

      private

      # 选择适合当前平台语法的文档词法解析器。
      def document_class = Document

      # 初始化当前配置的词元缓存，供各领域解析阶段共享。
      def prepare_configuration
        @tokens = {}
      end

      # 已配置主机 ACL 本身不能证明管理监听服务已启用。
      def parse_management
        interfaces = matching_blocks(/\Ainterface\s+/)
        states = interfaces.map do |section|
          matching_blocks(/\A(?:no )?manage\s+/, section.children).each_with_object({}) do |entry, values|
            parts = command_tokens(entry)
            negative = parts.first == "no"
            parts = parts.drop(1) if negative
            next unless MANAGEMENT_SERVICES.include?(parts[1])
            if parts.size == 2
              values[parts[1]] = analyze(entry) { !negative }
            else
              values[parts[1]] = nil
            end
          end
        end
        service_states = MANAGEMENT_SERVICES.to_h do |name|
          values = states.map { |state| state[name] }
          enabled = values.include?(true) ? true : values.any? && values.all?(false) ? false : nil
          [ name, enabled ]
        end
        record_fact("ssh.enabled", service_states["ssh"])
        record_fact("services", service_states.slice("telnet", "http", "https", "ftp"))
        record_management_sources
      end

      # 信任主机可使用 CIDR、掩码、区间或 any；跨协议按保守并集处理。
      def record_management_sources
        entries = matching_blocks(/\A(?:no )?admin host\b/)
        sources = entries.flat_map do |entry|
          parts = command_tokens(entry)
          raise ArgumentError unless parts.take(2) == %w[admin host] && HOST_PROTOCOLS.include?(parts.last)
          analyze(entry) { parse_host_networks(parts[2...-1]) }
        rescue ArgumentError, IPAddr::Error
          record_unknown_fact("management.acl", [ entry ], code: :unsupported_trusted_host)
          nil
        end
        if entries.empty?
          return unless @fact_builder.complete?
          # 未显式配置受信任主机时，不能据此证明来源访问受限。
          @fact_builder.record_source_restriction(fact: "management.acl", sources: nil, bound: false)
        else
          @fact_builder.record_source_restriction(fact: "management.acl", sources: sources.include?(nil) ? nil : sources,
            bound: true, lines: entries.map(&:line))
        end
      end

      # 提取时间同步服务器及相关认证配置。
      def parse_ntp
        entries = matching_blocks(/\Antp server\b/)
        sources = []
        servers = entries.filter_map do |entry|
          parts = command_tokens(entry)
          unless server_address?(parts[2])
            record_unknown_fact("ntp", [ entry ])
            next
          end
          options = parse_keyword_options(parts.drop(3), flags: [ "prefer" ], keys: %w[key source vrouter])
          unless options && (!options["key"] || /\A[1-9]\d*\z/.match?(options["key"]))
            record_unknown_fact("ntp", [ entry ])
            next
          end
          sources << options["source"]
          analyze(entry) { parts[2] }
        end
        record_fact("ntp.servers", servers.uniq, entries)
        record_configured_state("ntp.authentication", /\Antp authentication\z/, /\Ano ntp authentication\z/)
        record_fact("ntp.source", sources.first, entries) if sources.any? && sources.first && sources.uniq.one?
        record_unknown_fact("ntp", matching_blocks(/\Ano ntp server\b/)) if matching_blocks(/\Ano ntp server\b/).any?
      end

      # 同一目标可供多个日志类别使用，统计时只计一次。
      def parse_syslog
        entries = matching_blocks(/\Alogging syslog\b/)
        sources = []
        servers = entries.filter_map do |entry|
          parts = command_tokens(entry)
          options = parts.drop(3)
          source = nil
          if %w[vrouter source-interface].include?(options.first)
            source = options[1] if options.first == "source-interface"
            options = options.drop(2)
          end
          valid = server_address?(parts[2]) && %w[tcp udp secure-tcp].include?(options[0]) && parse_service_port(options[1])&.positive?
          tail = options.drop(2)
          tail = tail.drop(1) if options[0] == "secure-tcp" && tail.first == "server-cert-check-disable"
          valid &&= tail.empty? || tail.first == "type" && tail.size >= 2
          unless valid
            record_unknown_fact("syslog", [ entry ])
            next
          end
          sources << source
          analyze(entry) { parts[2] }
        end
        record_fact("syslog.servers", servers.uniq, entries)
        record_fact("syslog.source", sources.first, entries) if sources.any? && sources.first && sources.uniq.one?
        record_unknown_fact("syslog", matching_blocks(/\Ano logging syslog\b/)) if matching_blocks(/\Ano logging syslog\b/).any?
      end

      # 轮询主机权限独立于出站 Trap 接收端。
      def parse_snmp
        record_configured_state("snmp.enabled", /\Asnmp-server manager\z/, /\Ano snmp-server manager\z/)
        entries = matching_blocks(/\Asnmp-server host\b/)
        versions, sources, communities = [], [], []
        entries.each do |entry|
          parts = command_tokens(entry)
          offset = parts.index("version")
          raise ArgumentError unless offset && offset > 2
          networks = parse_host_networks(parts[2...offset])
          settings = parts.drop(offset + 1)
          if %w[1 2c].include?(settings.first) && settings[1] == "community" && !settings[2].to_s.empty? &&
              (settings.size == 3 || settings.size == 4 && %w[ro rw].include?(settings[3]))
            record_credential("snmp-community", "snmp", credential_storage_format(settings[2]), settings[2], entry)
            versions << (settings.first == "1" ? "v1" : "v2c")
            communities << { write: settings[3] == "rw", line: entry.line }
            sources.concat(networks)
          elsif settings == [ "3" ]
            versions << "v3"
            sources.concat(networks)
            analyze(entry) { true }
          else
            raise ArgumentError
          end
        rescue ArgumentError, IPAddr::Error
          record_unknown_snmp_access([ entry ], code: :unsupported_snmp_host)
        end
        groups = parse_snmp_access_groups
        users = parse_snmp_access_users
        versions |= [ "v3" ] if users.any? || groups.any?
        record_fact("snmp.groups", groups)
        record_fact("snmp.versions", versions.uniq, entries)
        unsupported = matching_blocks(/\Ano snmp-server (?:host|user|group)\b/)
        record_unknown_snmp_access(unsupported, code: :unsupported_snmp_security) if unsupported.any?
        if versions.include?("v3") && users.empty?
          record_unknown_snmp_access(entries, code: :snmp_user_unresolved)
        end
        @fact_builder.record_snmp_access(communities: communities, users: users, groups: groups)
        @fact_builder.record_source_restriction(fact: "snmp.acl", sources: sources, bound: true, lines: entries.map(&:line)) if entries.any?
      end

      # 组只声明访问权限；认证级别要求不能替代用户的实际密钥证据。
      def parse_snmp_access_groups
        entries = matching_blocks(/\Asnmp-server group\b/).select do |entry|
          parts = command_tokens(entry)
          options = parse_keyword_options(parts.drop(5), flags: [], keys: %w[read-view write-view])
          valid = parts.size >= 5 && parts[3] == "v3" && %w[noauth auth auth-enc].include?(parts[4]) &&
            !parts[2].to_s.empty? && options && options.values.none?(&:empty?)
          record_unknown_snmp_access([ entry ], code: :unsupported_snmp_group) unless valid
          valid
        end
        configured_snmp_groups(entries) do |entry|
          parts = command_tokens(entry)
          options = parse_keyword_options(parts.drop(5), flags: [], keys: %w[read-view write-view])
          analyze(entry) { true }
          [ parts[2], { write: options.key?("write-view"), line: entry.line, acl: nil } ]
        end
      end

      # StoneOS 用户显式引用组及远端地址，秘密值仅用于提取安全属性。
      def parse_snmp_access_users
        matching_blocks(/\Asnmp-server user\b/).filter_map do |entry|
          parts = command_tokens(entry)
          valid = parts.size >= 8 && !parts[2].to_s.empty? && parts[3] == "group" && !parts[4].to_s.empty? &&
            parts[5] == "v3" && parts[6] == "remote"
          address = IPAddr.new(parts[7]) if valid
          valid &&= address.ipv4? && !parts[7].include?("/")
          security = parts.drop(8)
          valid &&= security.empty? || [ 3, 6 ].include?(security.size) && security[0] == "auth-protocol" &&
            %w[md5 sha].include?(security[1]) && !security[2].to_s.empty? &&
            (security.size == 3 || security[3] == "enc-protocol" && %w[des aes].include?(security[4]) && !security[5].to_s.empty?)
          unless valid
            record_unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
            next
          end
          security.each_slice(3) do |mode|
            record_credential("snmp:#{parts[2]}", "snmp_user", credential_storage_format(mode[2]), mode[2], entry)
          end
          analyze(entry) { { name: parts[2], group: parts[4], auth: security.any?, priv: security.size == 6, line: entry.line } }
        rescue ArgumentError, IPAddr::Error
          record_unknown_snmp_access([ entry ], code: :unsupported_snmp_user)
          nil
        end
      end

      # 分别记录 TACACS 定义与管理认证引用。
      def parse_authentication
        definitions = matching_blocks(/\Aaaa-server\s+/).filter_map do |section|
          parts = command_tokens(section)
          unless parts.size == 4 && parts[2..] == %w[type tacacs+]
            record_unknown_fact("tacacs", [ section ]) if parts.include?("tacacs+")
            next
          end
          endpoints = matching_blocks(/\A(?:host|backup[12])\b/, section.children)
          servers = endpoints.filter_map do |entry|
            values = command_tokens(entry)
            if server_address?(values[1]) && (values.size == 2 || values.size == 4 && values[2] == "vrouter")
              analyze(entry) { values[1] }
            else
              record_unknown_fact("tacacs", [ entry ])
              nil
            end
          end
          secrets = matching_blocks(/\Asecret\b/, section.children)
          keys = secrets.map { |entry| record_stored_credential("tacacs:#{parts[1]}", "tacacs", entry) }
          [ parts[1], { servers: servers.uniq, keys_present: keys.any? && keys.all?, line: section.line,
            declaration: section.children.empty? } ]
        end
        schemes = definitions.group_by(&:first).to_h do |name, entries|
          # StoneOS 会先导出空的前向声明，再导出包含内容的服务器块。
          populated = entries.map(&:last).reject { |entry| entry[:declaration] }
          selected = populated.last || entries.last.last
          @fact_builder.record_unknown_fact("tacacs", lines: populated.map { |entry| entry[:line] }, code: :duplicate_tacacs_scheme) if populated.size > 1
          if selected[:servers].empty?
            @fact_builder.record_unknown_fact("tacacs.servers", lines: [ selected[:line] ], code: :tacacs_server_unresolved)
          end
          [ name, selected.except(:declaration) ]
        end
        record_fact("tacacs.schemes", schemes)
        record_fact("tacacs.servers", schemes.values.flat_map { |scheme| scheme[:servers] }.uniq)
        record_fact("tacacs.keys_present", schemes.values.all? { |scheme| scheme[:keys_present] }) if schemes.any?
        { "authentication-server" => "login", "authorization-mode" => "authorization" }.each do |command, fact|
          entries = matching_blocks(/\Aadmin #{command}\b/)
          next if entries.empty?
          parts = command_tokens(entries.last)
          name = parts[3] if parts.size == 4 && parts[2] == "aaa-server"
          if name && schemes[name] && schemes[name][:servers].any?
            record_fact("tacacs.#{fact}", true, entries)
          else
            record_unknown_fact("tacacs.#{fact}", entries, code: :tacacs_scheme_unresolved)
          end
        end
        matching_blocks(/\Aadmin user\s+/).each do |section|
          owner = command_tokens(section)[2]
          passwords = matching_blocks(/\Apassword\b/, section.children)
          record_credential(owner, "local_user", "unknown", nil, section) if passwords.empty?
          passwords.each { |entry| record_stored_credential(owner, "local_user", entry) }
        end
      end

      # 编码格式的存储语义未经确认时保持未知，不能猜测为明文。
      def credential_storage_format(value) = value.start_with?("$") ? "unknown" : "plain"

      # 仅记录已配置秘密值的存储属性。
      def record_stored_credential(owner, kind, entry)
        parts = command_tokens(entry).drop(1)
        valid = parts.size == 1 && !%w[cipher hash plain].include?(parts.first) || parts.size == 2 && %w[cipher hash plain].include?(parts.first)
        unless valid && !parts.last.to_s.empty?
          @fact_builder.mark_incomplete!(code: :invalid_credential_statement, lines: [ entry.line ])
          record_credential(owner, kind, "unknown", nil, entry)
          return false
        end
        format, secret = parts.size == 2 && %w[cipher hash plain].include?(parts.first) ? parts : [ credential_storage_format(parts.first.to_s), parts.first ]
        record_credential(owner, kind, format, secret, entry)
        true
      end

      # 切分含引号的命令值，不将其作为 Ruby 代码解释。
      def command_tokens(entry)
        @tokens[entry.index] ||= Shellwords.shellsplit(entry.text)
      rescue ArgumentError
        @fact_builder.mark_incomplete!(code: :invalid_quoted_statement, lines: [ entry.line ])
        cursor.mark(entry.index, state: :unsupported)
        @tokens[entry.index] = []
      end

      # 校验可选参数，避免接受任意尾随命令片段。
      def parse_keyword_options(parts, flags:, keys:)
        values = {}
        until parts.empty?
          key = parts.shift
          return if values.key?(key)
          if flags.include?(key)
            values[key] = true
          elsif keys.include?(key) && parts.any?
            values[key] = parts.shift
          else
            return
          end
        end
        values
      end

      # 将命名主机或网络对象归一化为地址区间。
      def parse_host_networks(parts)
        return [ "0.0.0.0/0" ] if parts == [ "any" ]
        if parts.size == 3 && parts.first == "range"
          first, last = parts.drop(1).map { |value| IPAddr.new(value) }
          raise ArgumentError unless first.ipv4? && last.ipv4? && first.prefix == 32 && last.prefix == 32 && first.to_i <= last.to_i
          Acl.cidrs_from_ranges([ [ first.to_i, last.to_i ] ])
        elsif parts.size == 1 || parts.size == 2
          value = IPAddr.new(parts.join("/"))
          raise ArgumentError unless value.ipv4?
          [ "#{value}/#{value.prefix}" ]
        else
          raise ArgumentError
        end
      end
    end
  end
end

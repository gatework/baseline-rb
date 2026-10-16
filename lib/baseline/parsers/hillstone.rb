# frozen_string_literal: true

require "shellwords"
require_relative "../hillstone_document"

module Baseline
  module Parsers
    # StoneOS 管理端点与原生主机允许列表不同于路由器 VTY。
    class Hillstone < Base
      MANAGEMENT_SERVICES = %w[ssh telnet http https ftp snmp].freeze
      HOST_PROTOCOLS = %w[ssh telnet http https netconf any].freeze

      private

      # 选择适合当前平台语法的文档词法解析器。
      def configuration_document_class = HillstoneDocument

      # 解析管理访问暴露检查使用的有序 ACL 定义。
      def access_lists
        @tokens = {}
      end

      # 已配置主机 ACL 本身不能证明管理监听服务已启用。
      def management
        interfaces = sections(/\Ainterface\s+/)
        states = interfaces.map do |section|
          matching(/\A(?:no )?manage\s+/, section.children).each_with_object({}) do |entry, values|
            parts = tokens(entry)
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
        services = MANAGEMENT_SERVICES.to_h do |name|
          values = states.map { |state| state[name] }
          enabled = values.include?(true) ? true : values.any? && values.all?(false) ? false : nil
          [ name, enabled ]
        end
        record("ssh.enabled", services["ssh"])
        record("services", services.slice("telnet", "http", "https", "ftp"))
        management_sources
      end

      # 信任主机可使用 CIDR、掩码、区间或 any；跨协议按保守并集处理。
      def management_sources
        entries = matching(/\A(?:no )?admin host\b/)
        sources = entries.flat_map do |entry|
          parts = tokens(entry)
          raise ArgumentError unless parts.take(2) == %w[admin host] && HOST_PROTOCOLS.include?(parts.last)
          analyze(entry) { host_networks(parts[2...-1]) }
        rescue ArgumentError, IPAddr::Error
          unknown("management.acl", [ entry ], code: :unsupported_trusted_host)
          nil
        end
        if entries.empty?
          return unless @facts.complete?
          # 未显式配置受信任主机时，不能据此证明来源访问受限。
          @facts.direct_acl(fact: "management.acl", sources: nil, bound: false)
        else
          @facts.direct_acl(fact: "management.acl", sources: sources.include?(nil) ? nil : sources,
            bound: true, lines: entries.map(&:line))
        end
      end

      # 采集明确启用或禁用的管理服务。
      def services
        ntp
        syslog
        snmp
      end

      # 提取时间同步服务器及相关认证配置。
      def ntp
        entries = matching(/\Antp server\b/)
        sources = []
        servers = entries.filter_map do |entry|
          parts = tokens(entry)
          unless server_address?(parts[2])
            unknown("ntp", [ entry ])
            next
          end
          options = pairs(parts.drop(3), flags: [ "prefer" ], keys: %w[key source vrouter])
          unless options && (!options["key"] || /\A[1-9]\d*\z/.match?(options["key"]))
            unknown("ntp", [ entry ])
            next
          end
          sources << options["source"]
          analyze(entry) { parts[2] }
        end
        record("ntp.servers", servers.uniq, entries)
        record("ntp.authentication", state(/\Antp authentication\z/, /\Ano ntp authentication\z/))
        record("ntp.source", sources.first) if sources.any? && sources.first && sources.uniq.one?
        unknown("ntp", matching(/\Ano ntp server\b/)) if matching(/\Ano ntp server\b/).any?
      end

      # 同一目标可供多个日志类别使用，统计时只计一次。
      def syslog
        entries = matching(/\Alogging syslog\b/)
        sources = []
        servers = entries.filter_map do |entry|
          parts = tokens(entry)
          options = parts.drop(3)
          source = nil
          if %w[vrouter source-interface].include?(options.first)
            source = options[1] if options.first == "source-interface"
            options = options.drop(2)
          end
          valid = server_address?(parts[2]) && %w[tcp udp secure-tcp].include?(options[0]) && service_port(options[1])&.positive?
          tail = options.drop(2)
          tail = tail.drop(1) if options[0] == "secure-tcp" && tail.first == "server-cert-check-disable"
          valid &&= tail.empty? || tail.first == "type" && tail.size >= 2
          unless valid
            unknown("syslog", [ entry ])
            next
          end
          sources << source
          analyze(entry) { parts[2] }
        end
        record("syslog.servers", servers.uniq, entries)
        record("syslog.source", sources.first) if sources.any? && sources.first && sources.uniq.one?
        unknown("syslog", matching(/\Ano logging syslog\b/)) if matching(/\Ano logging syslog\b/).any?
      end

      # 轮询主机权限独立于出站 Trap 接收端。
      def snmp
        record("snmp.enabled", state(/\Asnmp-server manager\z/, /\Ano snmp-server manager\z/))
        entries = matching(/\Asnmp-server host\b/)
        versions, sources, communities = [], [], []
        entries.each do |entry|
          parts = tokens(entry)
          offset = parts.index("version")
          raise ArgumentError unless offset && offset > 2
          networks = host_networks(parts[2...offset])
          settings = parts.drop(offset + 1)
          if %w[1 2c].include?(settings.first) && settings[1] == "community" && !settings[2].to_s.empty? &&
              (settings.size == 3 || settings.size == 4 && %w[ro rw].include?(settings[3]))
            credential("snmp-community", "snmp", secret_format(settings[2]), settings[2], entry)
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
          unknown_snmp_access([ entry ], code: :unsupported_snmp_host)
        end
        record("snmp.versions", versions.uniq, entries)
        unsupported = matching(/\A(?:snmp-server (?:user|group)\b|no snmp-server (?:host|user|group)\b)/)
        unknown_snmp_access(unsupported, code: :unsupported_snmp_security) if unsupported.any? || versions.include?("v3")
        @facts.snmp(communities: communities, users: [])
        @facts.direct_acl(fact: "snmp.acl", sources: sources, bound: true, lines: entries.map(&:line)) if entries.any?
      end

      # 分别记录 TACACS 定义与管理认证引用。
      def authentication
        definitions = sections(/\Aaaa-server\s+/).filter_map do |section|
          parts = tokens(section)
          unless parts.size == 4 && parts[2..] == %w[type tacacs+]
            unknown("tacacs", [ section ]) if parts.include?("tacacs+")
            next
          end
          endpoints = matching(/\A(?:host|backup[12])\b/, section.children)
          servers = endpoints.filter_map do |entry|
            values = tokens(entry)
            if server_address?(values[1]) && (values.size == 2 || values.size == 4 && values[2] == "vrouter")
              analyze(entry) { values[1] }
            else
              unknown("tacacs", [ entry ])
              nil
            end
          end
          secrets = matching(/\Asecret\b/, section.children)
          keys = secrets.map { |entry| stored_secret("tacacs:#{parts[1]}", "tacacs", entry) }
          [ parts[1], { servers: servers.uniq, keys_present: keys.any? && keys.all?, line: section.line,
            declaration: section.children.empty? } ]
        end
        schemes = definitions.group_by(&:first).to_h do |name, entries|
          # StoneOS 会先导出空的前向声明，再导出包含内容的服务器块。
          populated = entries.map(&:last).reject { |entry| entry[:declaration] }
          selected = populated.last || entries.last.last
          @facts.unknown("tacacs", lines: populated.map { |entry| entry[:line] }, code: :duplicate_tacacs_scheme) if populated.size > 1
          if selected[:servers].empty?
            @facts.unknown("tacacs.servers", lines: [ selected[:line] ], code: :tacacs_server_unresolved)
          end
          [ name, selected.except(:declaration) ]
        end
        record("tacacs.schemes", schemes)
        record("tacacs.servers", schemes.values.flat_map { |scheme| scheme[:servers] }.uniq)
        record("tacacs.keys_present", schemes.values.all? { |scheme| scheme[:keys_present] }) if schemes.any?
        { "authentication-server" => "login", "authorization-mode" => "authorization" }.each do |command, fact|
          entries = matching(/\Aadmin #{command}\b/)
          next if entries.empty?
          parts = tokens(entries.last)
          name = parts[3] if parts.size == 4 && parts[2] == "aaa-server"
          if name && schemes[name] && schemes[name][:servers].any?
            record("tacacs.#{fact}", true, entries)
          else
            unknown("tacacs.#{fact}", entries, code: :tacacs_scheme_unresolved)
          end
        end
        sections(/\Aadmin user\s+/).each do |section|
          owner = tokens(section)[2]
          passwords = matching(/\Apassword\b/, section.children)
          credential(owner, "local_user", "unknown", nil, section) if passwords.empty?
          passwords.each { |entry| stored_secret(owner, "local_user", entry) }
        end
      end

      # 编码格式的存储语义未经确认时保持未知，不能猜测为明文。
      def secret_format(value) = value.start_with?("$") ? "unknown" : "plain"

      # 仅记录已配置秘密值的存储属性。
      def stored_secret(owner, kind, entry)
        parts = tokens(entry).drop(1)
        valid = parts.size == 1 && !%w[cipher hash plain].include?(parts.first) || parts.size == 2 && %w[cipher hash plain].include?(parts.first)
        unless valid && !parts.last.to_s.empty?
          @facts.incomplete!(code: :invalid_credential_statement, lines: [ entry.line ])
          credential(owner, kind, "unknown", nil, entry)
          return false
        end
        format, secret = parts.size == 2 && %w[cipher hash plain].include?(parts.first) ? parts : [ secret_format(parts.first.to_s), parts.first ]
        credential(owner, kind, format, secret, entry)
        true
      end

      # 切分含引号的命令值，不将其作为 Ruby 代码解释。
      def tokens(entry)
        @tokens[entry.index] ||= Shellwords.shellsplit(entry.text)
      rescue ArgumentError
        @facts.incomplete!(code: :invalid_quoted_statement, lines: [ entry.line ])
        cursor.mark(entry.index, state: :unsupported)
        @tokens[entry.index] = []
      end

      # 校验可选参数，避免接受任意尾随命令片段。
      def pairs(parts, flags:, keys:)
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
      def host_networks(parts)
        return [ "0.0.0.0/0" ] if parts == [ "any" ]
        if parts.size == 3 && parts.first == "range"
          first, last = parts.drop(1).map { |value| IPAddr.new(value) }
          raise ArgumentError unless first.ipv4? && last.ipv4? && first.prefix == 32 && last.prefix == 32 && first.to_i <= last.to_i
          Acl.networks([ [ first.to_i, last.to_i ] ])
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

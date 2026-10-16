# frozen_string_literal: true

require "ctx_parser/configuration_parser"
require "ctx_parser/input"
require_relative "../document"

module Baseline
  module Parsers
    # 共享输入与提取边界；CtxParser 跟踪来源，Facts 归纳领域证据。
    class Base < CtxParser::ConfigurationParser
      SERVICE_PORTS = { "ssh" => 22, "telnet" => 23, "snmp" => 161, "snmptrap" => 162 }.freeze
      SNMP_OPTIONS = %w[auth priv authentication-mode privacy-mode acl access use-ipv4acl group local engineid engineID
        encrypted localizedkey localizedV2key remote udp-port].freeze

      private

      # 解释当前命令回显，保留不支持或格式错误的证据。
      def parse_output(text, complete:)
        begin
          text = CtxParser::Input.text(text, encoding: :utf8, max_bytes: 16 * 1024 * 1024)
        rescue ArgumentError, EncodingError
          return CtxParser::Result.new(status: :failed, issues: [ { code: :invalid_configuration } ])
        end
        read_configuration(text, document_class: configuration_document_class)
        issues = document.issues.dup
        if (!complete || issues.any?) && exclude_incomplete_final_line
          issues << { code: :incomplete_final_line, line: cursor.lines.last.number }
        end
        @source_issues = issues
        @facts = Facts.new(complete: complete, issues: issues)
        if roots.empty?
          return CtxParser::Result.new(status: :failed, issues: issues + [ { code: :empty_configuration } ])
        end
        if (hostname = matching(hostname_pattern).last)
          name = analyze(hostname) { hostname.text[hostname_pattern, 1] }
          record("hostname", name)
          capture(hostname, name, [ "facts", "hostname" ])
        end
        access_lists
        management
        services
        authentication
        @facts.result
      end

      # 返回本次解析的根配置块。
      def roots = @blocks
      # 选择适合当前平台语法的文档词法解析器。
      def configuration_document_class = Document
      # 匹配当前平台显式声明的主机名。
      def hostname_pattern = /\A(?:hostname|sysname)\s+(\S+)\z/
      # 选择符合目标命令语法的根配置块。
      def sections(pattern) = roots.select { |entry| pattern.match?(entry.text) }

      # 保留原始文本，但不将可能截断的词元纳入事实构建树。
      def exclude_incomplete_final_line
        line = cursor.lines.last
        return false unless line && !line.raw.end_with?("\n", "\r") && cursor.state(line.index) != :ignored

        entries, ancestors = roots, []
        while (entry = entries.last)
          if entry.index == line.index
            retained = entries[0...-1].freeze
            ancestors.reverse_each do |siblings, parent|
              block = CtxParser::Block.new(cursor: cursor, header: parent.header, children: retained, last_index: parent.last_index)
              retained = (siblings[0...-1] + [ block ]).freeze
            end
            @blocks = retained
            cursor.mark(line.index, state: :unsupported)
            return true
          end
          ancestors << [ entries, entry ]
          entries = entry.children
        end
        false
      end

      # 筛选匹配已支持命令模式的来源条目。
      def matching(pattern, entries = roots) = entries.select { |entry| pattern.match?(entry.text) }
      # 提取匹配值，并关联对应的来源条目。
      def values(pattern, entries = roots)
        entries.filter_map do |entry|
          value = entry.text[pattern, 1]
          analyze(entry) { value } unless value.nil?
        end.uniq
      end

      # 按配置顺序选取最后一条匹配声明。
      def last(pattern, entries = roots)
        entry = entries.reverse.find { |candidate| !candidate.text[pattern, 1].nil? }
        return unless entry

        analyze(entry) { entry.text[pattern, 1] }
      end

      # 保存归一化事实及其来源证据。
      def record(path, value, entries = [])
        return unless @facts.record(path, value, lines: entries.map(&:line))

        # 来源块中尚未解释的命令不能标记为解析成功。
        cursor.capture_many(entries.select { |entry| cursor.parsed?(entry.index) }, data: value, path: [ "facts", path ])
      end

      # 记录事实不可用的原因，并保留对应的来源行。
      def unknown(path, entries = [], code: :unsupported_syntax)
        @facts.unknown(path, lines: entries.map(&:line), code: code)
        entries.each { |entry| cursor.mark(entry.index, state: :unsupported) }
      end

      # 未解析的访问声明不能抹除其他已确认的写权限。
      def unknown_snmp_access(entries, code: :unsupported_syntax)
        @facts.unknown_snmp_permission(lines: entries.map(&:line), code: code)
        %w[snmp.communities snmp.community_present snmp.users snmp.versions snmp.v3_auth_priv snmp.acl].each do |path|
          unknown(path, entries, code: code)
        end
      end

      # 按来源顺序确定最终生效的显式启用或禁用声明。
      def state(on, off, entries = roots)
        entries.reduce(nil) do |value, entry|
          if off.match?(entry.text)
            analyze(entry) { false }
          elsif on.match?(entry.text)
            analyze(entry) { true }
          else
            value
          end
        end
      end

      # 记录凭据属性，不保留凭据秘密值。
      def credential(owner, kind, format, secret, entry)
        value = analyze(entry) { Credential.new(owner: owner, kind: kind, format: format, secret: secret, line: entry.line) }
        index = @facts.credential(value)
        capture(entry, value.to_h, [ "facts", "credentials.records", index ])
      end

      # 注册有序 ACL 规则与别名，同时保留不支持的语法。
      def register_acl(name, entries, aliases: [], supported: true, source: nil, &block)
        commands = entries.reject { |entry| /\A(?:\d+\s+)?(?:description|remark|step|statistics|hardware-count)\b/.match?(entry.text) }
        parsed = commands.map.with_index do |entry, index|
          value = analyze(entry) { block.call(entry, index) }
          cursor.mark(entry.index, state: :unsupported) unless value
          value
        end
        damaged = @source_issues.any? do |issue|
          line = issue[:line]
          next false unless line

          source ? source.line_range.cover?(line) : damaged_numbered_acl?(cursor.lines.fetch(line - 1).text, name)
        end
        acl = Acl.new(name: name, line: entries.first&.line, rules: parsed.compact,
          supported: supported && !damaged && parsed.none?(&:nil?))
        if @facts.register_acl(acl, aliases: aliases, lines: entries.map(&:line)).any?
          entries.each { |entry| cursor.mark(entry.index, state: :unsupported) }
        end
      end

      # 名称被分页截断时，所有匹配其前缀的编号 ACL 都不能声明完整。
      def damaged_numbered_acl?(text, name)
        prefix = text.split(/--\s*More\s*--|\e\[/i, 2).first
        match = /\Aaccess-list(?:\s+(\S*))?(.*)\z/.match(prefix)
        return false unless match

        identity, suffix = match.captures
        identity.to_s.empty? || (suffix.empty? ? name.start_with?(identity) : name == identity)
      end

      # 归一化 ACL 来源地址；不推测不支持语法的含义。
      def source(parts)
        token = parts.shift
        return "0.0.0.0/0" if token == "any"
        token = parts.shift if token == "host"
        wildcard = parts.shift if parts.first&.match?(/\A(?:\d+(?:\.\d+){3}|0)\z/)
        Acl.source(token, wildcard)
      end

      # 显式端口名称仅属于配置语法，不代表组织批准值。
      def service_port(token)
        return SERVICE_PORTS[token] unless token&.match?(/\A\d+\z/)
        value = token.to_i
        value if value.between?(0, 65_535)
      end

      # 服务器目标只接受 IP 地址或 DNS 名称，不接受网段或空词元。
      def server_address?(value)
        return false unless value.is_a?(String) && !value.empty?
        IPAddr.new(value)
        !value.include?("/")
      rescue IPAddr::Error
        value.bytesize <= 253 && !/\A[\d.]+\z/.match?(value) && value.delete_suffix(".").split(".", -1).all? do |label|
          /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i.match?(label)
        end
      end

      # 配置的监听端口仅替代当前服务的默认端口。
      def listener_port(command, default:, scope:, negate: "undo")
        prefix = Regexp.escape(command)
        entries = matching(/\A(?:#{negate} )?#{prefix}(?:\s|\z)/)
        return default if entries.empty?
        entry = entries.last
        return analyze(entry) { default } if entry.text == "#{negate} #{command}"
        token = entry.text[/\A#{prefix}\s+(\d+)\z/, 1]
        port = service_port(token)
        return analyze(entry) { port } if port && port.positive?
        unknown_listener_port(scope, entries)
        nil
      end

      # 监听端口无法解析时，将依赖该端口的事实保留为未知。
      def unknown_listener_port(scope, entries)
        %w[sources restricted].each { |field| unknown("#{scope}.#{field}", entries, code: :unsupported_service_port) }
      end

      # 区分模式未声明、格式无效及包含完整算法与秘密值的声明。
      def snmp_secret(settings, keyword, algorithms:, optional_algorithm: false, aes_size: false)
        tokens = settings.split
        index = tokens.index(keyword)
        return false unless index
        return if tokens.count(keyword) > 1
        parameters = tokens.drop(index + 1).take_while { |token| !SNMP_OPTIONS.include?(token) }
        if algorithms.include?(parameters.first)
          algorithm = parameters.shift
        elsif !optional_algorithm || parameters.size != 1 || %w[aes des md5 sha].include?(parameters.first)
          return
        end
        return if algorithm == "aes" && aes_size && !%w[128 192 256].include?(parameters.shift)
        format = parameters.shift if %w[cipher simple].include?(parameters.first)
        return unless parameters.size == 1
        [ format, parameters.first ]
      end

      # 提取 SNMP 凭据属性，不持久化秘密值。
      def snmp_credentials(owner, modes, entry, format: nil)
        modes.each_value do |value|
          next if value == false
          stored_format, secret = value || [ "unknown", nil ]
          credential(owner, "snmp_user", stored_format || format || "unknown", secret, entry)
        end
        unknown("snmp.v3_auth_priv", [ entry ], code: :invalid_snmp_security) if modes.value?(nil)
        modes.transform_values { |value| value ? true : value }
      end

      # 同名组可出现在不同安全级别；后续只读声明不能消除已有写权限。
      def snmp_groups(entries)
        entries.map { |entry| yield(entry) }.group_by(&:first).transform_values do |definitions|
          records = definitions.map(&:last)
          acls = records.map { |record| record[:acl] }.uniq
          { acl: acls.one? ? acls.first : nil, acl_ambiguous: acls.size > 1,
            write: Facts.write_permission(records.map { |record| record[:write] }),
            line: records.first[:line], lines: records.map { |record| record[:line] } }
        end
      end
    end
  end
end

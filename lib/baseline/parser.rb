# frozen_string_literal: true

require "ctx_parser/configuration"
require "ctx_parser/input"
require_relative "document"
require_relative "fact_builder"
require_relative "credential"

module Baseline
  # 共享输入与提取边界；CtxParser 跟踪来源，FactBuilder 归纳领域证据。
  class Parser < CtxParser::Configuration
    # 只有明确声明的事实才属于适配器契约；新增规则不能默认获得实现能力。
    SUPPORTED_FACTS = %w[
      snmp.enabled snmp.versions snmp.write_enabled snmp.v3_auth_priv snmp.acl.bound snmp.acl.restricted snmp.acl.sources
      ntp.servers ntp.authentication ntp.source syslog.servers syslog.source
      ssh.enabled ssh.versions ssh.vty_ssh_only ssh.vty_aaa management.acl.bound management.acl.restricted management.acl.sources
      services credentials.storage_safe credentials.records tacacs.servers tacacs.login tacacs.authorization tacacs.accounting tacacs.keys_present
    ].freeze

    # 声明尚未建模的事实；未知能力不能通过空值或默认值伪装成已支持。
    UNSUPPORTED_FACTS = {}.freeze
    PARTIAL_FACTS = {}.freeze

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
      read_configuration(text, document_class: document_class)
      issues = document.issues.dup
      if (!complete || issues.any?) && exclude_incomplete_final_line
        issues << { code: :incomplete_final_line, line: cursor.lines.last.number }
      end
      @source_issues = issues
      @fact_builder = FactBuilder.new(complete: complete, issues: issues)
      if roots.empty?
        return CtxParser::Result.new(status: :failed, issues: issues + [ { code: :empty_configuration } ])
      end
      prepare_configuration
      if (hostname = matching_blocks(hostname_family_pattern).last)
        name = effective_configured_value(hostname_pattern, entries: [ hostname ], family: hostname_family_pattern, fact: "hostname")
        if name
          record_fact("hostname", name)
          capture(hostname, name, [ "facts", "hostname" ])
        end
      end
      parse_access_lists
      parse_management
      parse_services
      parse_authentication
      self.class::UNSUPPORTED_FACTS.each_key { |path| record_unknown_fact(path, code: :unsupported_capability) }
      @fact_builder.build
    end

    # 以相同顺序编排各厂商的原子领域能力，语法提取由适配器实现。
    def parse_services
      parse_ntp
      parse_syslog
      parse_snmp
    end

    # 在领域解析前准备当前配置的词元和引用索引。
    def prepare_configuration; end

    # 不使用命名 ACL 的平台由原生管理来源声明提供事实。
    def parse_access_lists; end

    # 返回本次解析的根配置块。
    def roots = @blocks
    # 选择适合当前平台语法的文档词法解析器。
    def document_class = Document
    # 匹配当前平台显式声明的主机名。
    def hostname_pattern = /\A(?:hostname|sysname)\s+(\S+)\z/
    # 损坏的最终身份声明也属于同族，不能继续使用旧身份选择设备策略。
    def hostname_family_pattern = /\A(?:hostname|sysname)(?:\s|\z)/
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
    def matching_blocks(pattern, entries = roots) = entries.select { |entry| pattern.match?(entry.text) }
    # 提取匹配值，并关联对应的来源条目。
    def configured_values(pattern, entries = roots)
      entries.filter_map do |entry|
        value = entry.text[pattern, 1]
        analyze(entry) { value } unless value.nil?
      end.uniq
    end

    # 地址语法在输入边界校验；损坏的服务器声明不能变成已知的空集或数量。
    def configured_server_addresses(scope, pattern, entries, negate: nil)
      values = {}
      entries.each do |entry|
        negative = negate && entry.text.start_with?("#{negate} ")
        text = negative ? entry.text.delete_prefix("#{negate} ") : entry.text
        match = pattern.match(text)
        address = match && match[1]
        unless server_address?(address)
          record_unknown_fact(scope, [ entry ], code: :invalid_server_address)
          next
        end
        identity = block_given? ? yield(text, match, negative, entry) : address
        unless identity
          record_unknown_fact(scope, [ entry ], code: :unsupported_server_options)
          next
        end
        analyze(entry) { address }
        negative ? values.delete(identity) : values[identity] = address
      end
      values.values.uniq
    end

    # 服务器可选项必须完整消费；未知参数、重复项及缺失值不能作为有效配置。
    def parse_server_options(text, flags: [], integers: {}, names: [], interfaces: [])
      parts, values = text.split, {}
      keywords = flags + integers.keys + names + interfaces
      until parts.empty?
        key = parts.shift
        return if values.key?(key) || !keywords.include?(key)
        if flags.include?(key)
          values[key] = true
          next
        end
        value = parts.shift
        return if value.nil? || keywords.include?(value)
        if integers.key?(key)
          return unless /\A\d+\z/.match?(value) && integers.fetch(key).cover?(value.to_i)
          value = value.to_i
        elsif interfaces.include?(key)
          return unless /\A[a-zA-Z][\w.:\/-]*\z/.match?(value)
          value += parts.shift if !/\d/.match?(value) && /\A\d[\d.:\/-]*\z/.match?(parts.first.to_s)
          return unless /\d/.match?(value)
        end
        values[key] = value
      end
      return if values.key?("minpoll") && values.key?("maxpoll") && values["minpoll"] > values["maxpoll"]

      values
    end

    # 按配置顺序选取最后一条匹配声明。
    def last_configured_value(pattern, entries = roots)
      entry = entries.reverse.find { |candidate| !candidate.text[pattern, 1].nil? }
      return unless entry

      analyze(entry) { entry.text[pattern, 1] }
    end

    # 先选取最后一条同族声明，再校验语法，避免回落到已被撤销或损坏的旧值。
    def effective_configured_value(pattern, entries: roots, family:, fact:, reset: nil)
      entry = entries.reverse.find { |candidate| family.match?(candidate.text) }
      return unless entry
      return analyze(entry) { nil } if reset&.match?(entry.text)
      match = pattern.match(entry.text)
      return analyze(entry) { match[1] } if match

      record_unknown_fact(fact, [ entry ])
      nil
    end

    # 保存最后生效的标量声明及对应来源，不将被覆盖的声明作为当前证据。
    def record_configured_value(path, pattern, entries = roots)
      entry = entries.reverse.find { |candidate| !candidate.text[pattern, 1].nil? }
      return unless entry

      record_fact(path, analyze(entry) { entry.text[pattern, 1] }, [ entry ])
    end

    # 启用状态可能由正向或撤销声明决定，保留所有参与归约的来源。
    def record_configured_state(path, on, off)
      entries = roots.select { |entry| on.match?(entry.text) || off.match?(entry.text) }
      record_fact(path, configured_state(on, off, entries), entries)
    end

    # 保存归一化事实及其来源证据。
    def record_fact(path, value, entries = [])
      return unless @fact_builder.record_fact(path, value, lines: entries.map(&:line))

      # 来源块中尚未解释的命令不能标记为解析成功。
      cursor.capture_many(entries.select { |entry| cursor.parsed?(entry.index) }, data: value, path: [ "facts", path ])
    end

    # 记录事实不可用的原因，并保留对应的来源行。
    def record_unknown_fact(path, entries = [], code: :unsupported_syntax)
      @fact_builder.record_unknown_fact(path, lines: entries.map(&:line), code: code)
      entries.each { |entry| cursor.mark(entry.index, state: :unsupported) }
    end

    # 未解析的访问声明不能抹除其他已确认的写权限。
    def record_unknown_snmp_access(entries, code: :unsupported_syntax)
      @fact_builder.record_unknown_snmp_permission(lines: entries.map(&:line), code: code)
      %w[snmp.communities snmp.community_present snmp.users snmp.versions snmp.v3_auth_priv snmp.acl].each do |path|
        record_unknown_fact(path, entries, code: code)
      end
    end

    # 按来源顺序确定最终生效的显式启用或禁用声明。
    def configured_state(on, off, entries = roots)
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
    def record_credential(owner, kind, format, secret, entry)
      value = analyze(entry) { Credential.new(owner: owner, kind: kind, format: format, secret: secret, line: entry.line) }
      index = @fact_builder.record_credential(value)
      capture(entry, value.to_h, [ "facts", "credentials.records", index ])
    end

    # 注册有序 ACL 规则与别名，同时保留不支持的语法。
    def register_acl(name, entries, aliases: [], supported: true, source: nil, &block)
      commands = entries.reject { |entry| /\A(?:\d+\s+)?(?:description|remark|step|statistics|hardware-count)\b/.match?(entry.text) }
      # 厂商显式序号是规则身份；重复身份不能靠来源先后消解。无序号规则保留原有顺序语义。
      sequences = commands.filter_map do |entry|
        match = /\A(?:access-list\s+\S+\s+)?(?:rule\s+)?(\d+)\s+(?:permit|deny)\b/.match(entry.text)
        Integer(match[1], 10) if match
      end
      duplicate_sequences = sequences.uniq.size != sequences.size
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
        supported: supported && !damaged && !duplicate_sequences && parsed.none?(&:nil?))
      conflicts = @fact_builder.register_acl(acl, aliases: aliases, lines: entries.map(&:line))
      if duplicate_sequences || conflicts.any?
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
    def parse_acl_source_network(parts)
      token = parts.shift
      return "0.0.0.0/0" if token == "any"
      if token == "host"
        address = parts.shift
        raise ArgumentError, "A host requires one IPv4 address" unless address&.match?(/\A\d+(?:\.\d+){3}\z/)
        return Acl.source_network(address)
      end
      wildcard = parts.shift if parts.first&.match?(/\A(?:\d+(?:\.\d+){3}|0)\z/)
      Acl.source_network(token, wildcard)
    end

    # 显式端口名称仅属于配置语法，不代表组织批准值。
    def parse_service_port(token)
      return SERVICE_PORTS[token] unless token&.match?(/\A\d+\z/)
      value = token.to_i
      value if value.between?(0, 65_535)
    end

    # 服务器目标只接受 IP 地址或 DNS 名称，不接受网段或空词元。
    def server_address?(value)
      ResourceSchema.address?(value)
    end

    # 各厂商的时间关联参数归一化到同一资源，不保存任何认证密钥值。
    def record_ntp_resource(address:, role:, vrf:, options:, entry:, negative: false)
      scope = { "vrf" => vrf || "default" }
      mapping = { "key" => "key_id", "authkey" => "key_id", "authentication-keyid" => "key_id",
        "priority" => "prefer", "source-interface" => "source", "normal-sync" => "normal_sync" }
      attributes = options.reject { |key, _| %w[vpn-instance use-vrf vrouter].include?(key) }.to_h do |key, value|
        [ mapping.fetch(key, key), key == "key" && value.is_a?(String) ? value.to_i : value ]
      end
      complete = scope.values.all? { |value| ResourceSchema.token?(value) } &&
        attributes.values.grep(String).all? { |value| ResourceSchema.token?(value) }
      unless complete
        record_unknown_fact("ntp.associations", [ entry ], code: :unsupported_resource_identity)
        return
      end
      resource = ConfigurationResource.new(kind: "ntp.association", identity: { "address" => address, "role" => role }, scope: scope,
        attributes: attributes, lines: [ entry.line ])
      @fact_builder.record_resource(resource, remove: negative)
    end

    # 配置的监听端口仅替代当前服务的默认端口。
    def listener_port(command, default:, scope:, negate: "undo")
      prefix = Regexp.escape(command)
      entries = matching_blocks(/\A(?:#{negate} )?#{prefix}(?:\s|\z)/)
      return default if entries.empty?
      entry = entries.last
      return analyze(entry) { default } if entry.text == "#{negate} #{command}"
      token = entry.text[/\A#{prefix}\s+(\d+)\z/, 1]
      port = parse_service_port(token)
      return analyze(entry) { port } if port && port.positive?
      record_unknown_listener_port(scope, entries)
      nil
    end

    # 监听端口无法解析时，将依赖该端口的事实保留为未知。
    def record_unknown_listener_port(scope, entries)
      %w[sources restricted].each { |field| record_unknown_fact("#{scope}.#{field}", entries, code: :unsupported_service_port) }
    end

    # 区分模式未声明、格式无效及包含完整算法与秘密值的声明。
    def parse_snmp_secret(settings, keyword, algorithms:, optional_algorithm: false, aes_size: false)
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
    def record_snmp_credentials(owner, modes, entry, format: nil)
      modes.each_value do |value|
        next if value == false
        stored_format, secret = value || [ "unknown", nil ]
        record_credential(owner, "snmp_user", stored_format || format || "unknown", secret, entry)
      end
      record_unknown_fact("snmp.v3_auth_priv", [ entry ], code: :invalid_snmp_security) if modes.value?(nil)
      modes.transform_values { |value| value ? true : value }
    end

    # 同名组可出现在不同安全级别；后续只读声明不能消除已有写权限。
    def configured_snmp_groups(entries)
      entries.map { |entry| yield(entry) }.group_by(&:first).transform_values do |definitions|
        records = definitions.map(&:last)
        acls = records.map { |record| record[:acl] }.uniq
        { acl: acls.one? ? acls.first : nil, acl_ambiguous: acls.size > 1,
          write: FactBuilder.write_permission_state(records.map { |record| record[:write] }),
          line: records.first[:line], lines: records.map { |record| record[:line] } }
      end
    end
  end
end

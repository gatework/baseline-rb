# frozen_string_literal: true

require_relative "acl"
require_relative "credential"
require_relative "configuration_resource"

require "ctx_parser/result"

module Baseline
  # 归并跨命令引用及未知状态，不依赖厂商语法或解析游标。
  class FactBuilder
    attr_reader :vtys

    # 初始化带来源信息的事实存储，并显式记录证据完整性。
    def initialize(complete:, issues: [])
      @confirmed_complete = complete
      @complete = complete && issues.empty?
      @values, @sources, @issues, @acls = {}, {}, issues.dup, {}
      @resources = {}
      @vtys, @communities, @snmp_users, @credentials = [], [], [], []
      @credential_lines = {}
      @snmp_groups = {}
      @snmp_group_issues = []
      @snmp_permission_issues = []
      @ssh_acl = nil
      @management_ports = { "ssh" => 22, "stelnet" => 22, "telnet" => 23 }
      @snmp_port = 161
      @direct_acls = {}
    end

    # 判断所有已选事实是否都有完整证据支持。
    def complete? = @complete

    # 相关配置语句格式错误时，不能继续依据配置缺失推导结论。
    def mark_incomplete!(code:, lines: [])
      @complete = false
      @issues << { code: code, lines: lines.uniq }
    end

    # 防火墙可直接声明来源网段，不要求一定引用路由器式命名 ACL。
    def record_source_restriction(fact:, sources:, bound:, lines: [])
      unless %w[management.acl snmp.acl].include?(fact) && [ true, false ].include?(bound) &&
          (sources.nil? || sources.is_a?(Array))
        raise ArgumentError, "Direct access requires a known scope, binding state and source networks"
      end
      networks = sources && Acl.cidrs_from_ranges(sources.map { |source| Acl.ipv4_range(source) })
      @direct_acls[fact] = true
      record_fact("#{fact}.bound", bound, lines: lines)
      if networks
        record_fact("#{fact}.sources", networks, lines: lines)
        record_fact("#{fact}.restricted", !networks.include?("0.0.0.0/0"), lines: lines)
      else
        %w[sources restricted].each { |key| record_unknown_fact("#{fact}.#{key}", lines: lines, code: :acl_unresolved) }
      end
    end

    # 将 false 保留为已知事实；输入不完整时，不接受 nil 或空集作为确定值。
    def record_fact(path, value, lines: [])
      return false if value.nil? || (!complete? && value.respond_to?(:empty?) && value.empty?)

      @values[path] = CtxParser::Immutable.copy(value)
      if lines.empty?
        @sources.delete(path)
      else
        @sources[path] = lines.uniq
      end
      true
    end

    # 记录事实不可用的原因，并保留对应的来源行。
    def record_unknown_fact(path, lines: [], code: :unsupported_syntax)
      @issues << { code: code, fact: path, lines: lines.uniq }
    end

    # 同一作用域对象按最终声明覆盖，跨作用域对象彼此独立。
    def record_resource(resource, remove: false)
      raise ArgumentError, "A configuration resource is required" unless resource.is_a?(ConfigurationResource)
      raise ArgumentError, "Resource removal must be boolean" unless [ true, false ].include?(remove)

      if remove && resource.complete?
        @resources.delete(resource.key)
      else
        @resources[resource.key] = resource.to_h
      end
      true
    end

    # 将别名关联到同一 ACL；保留定义冲突，避免后续定义静默覆盖。
    def register_acl(acl, aliases: [], lines: [])
      keys = ([ acl.name ] + aliases).uniq
      duplicates = keys.select { |key| @acls.key?(key) }
      duplicates.each { |key| record_unknown_fact("acls.#{key}", lines: lines, code: :duplicate_acl) }
      keys.each { |key| @acls[key] = acl }
      duplicates
    end

    # 根据监听服务、认证方式与 ACL 绑定关系归纳管理访问事实。
    def record_management_access(vtys:, ssh_acl: nil, ssh_port: 22, telnet_port: 23)
      @vtys, @ssh_acl = CtxParser::Immutable.copy(vtys), CtxParser::Immutable.copy(ssh_acl)
      @management_ports = { "ssh" => ssh_port, "stelnet" => ssh_port, "telnet" => telnet_port }
    end

    # 根据用户、组和团体字归纳 SNMP 暴露面及凭据事实。
    def record_snmp_access(communities:, users:, groups: nil, port: 161)
      @snmp_port = port
      @communities = CtxParser::Immutable.copy(communities)
      @snmp_groups = CtxParser::Immutable.copy(groups || {})
      @snmp_group_issues = []
      @snmp_users = users.map do |user|
        if groups && user[:group]
          if groups.key?(user[:group])
            group = groups.fetch(user[:group])
            user = user.merge(write: group[:write])
            unless user[:acl]
              user = user.merge(acl: group[:acl])
              @snmp_group_issues << { code: :snmp_group_ambiguous, fact: "snmp.acl", lines: [] } if group[:acl_ambiguous]
            end
          elsif !user[:acl]
            @snmp_group_issues << { code: :snmp_group_unresolved, fact: "snmp.acl", lines: [] }
          end
        end
        CtxParser::Immutable.copy(user)
      end
    end

    # 即使其他权限尚未解析，已确认的写权限仍属于违规证据。
    def self.write_permission_state(permissions)
      return true if permissions.include?(true)
      return false if permissions.all?(false)

      nil
    end

    # 暂存不完整的访问证据，优先保留已确认的权限授予事实。
    def record_unknown_snmp_permission(lines: [], code: :snmp_permission_unresolved)
      @snmp_permission_issues << { code: code, fact: "snmp.write_enabled", lines: lines.uniq }
    end

    # 检查此来源行是否已经产生凭据事实。
    def credential_recorded?(line) = @credential_lines.key?(line)

    # 记录凭据属性，不保留凭据秘密值。
    def record_credential(credential)
      index = @credentials.size
      attributes = credential.to_h
      @credentials << attributes
      @credential_lines[attributes[:line]] = true
      index
    end

    # 汇总事实与诊断，并保留证据完整性状态。
    def build
      dup.build_snapshot
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} complete=#{complete?} facts=#{@values.size}>"

    protected

    # 归约仅写入当前副本，后续快照始终从解析器提供的原始证据重新生成。
    def build_snapshot
      record_fact("acls", @acls.values.uniq.map(&:to_h))
      record_management_facts
      record_snmp_facts
      record_credential_facts
      @issues << { code: :hostname_missing } unless @values.key?("hostname")
      @issues << { code: :input_not_confirmed_complete } unless @confirmed_complete
      status = complete? && @values.key?("hostname") ? :complete : :partial
      CtxParser::Result.new(status: status,
        records: [ { "facts" => @values, "sources" => @sources, "resources" => @resources.values } ], issues: @issues.uniq)
    end

    private

    # 已记录的值不可变；复制归约会更新的容器即可隔离派生事实与诊断。
    def initialize_copy(original)
      super
      @values = @values.dup
      @sources = @sources.dup
      @issues = @issues.dup
    end

    # 归纳管理服务监听端点及其实际生效的访问限制。
    def record_management_facts
      record_fact("ssh.vty", vtys)
      if vtys.any? && vtys.all? { |entry| entry[:protocols] }
        protocols = vtys.flat_map { |entry| entry[:protocols] }.uniq
        record_fact("ssh.vty_ssh_only", protocols.any? && (protocols - %w[ssh stelnet]).empty?)
      end
      if vtys.any? && vtys.all? { |entry| entry[:authentication] }
        record_fact("ssh.vty_aaa", vtys.all? { |entry| %w[scheme aaa local].include?(entry[:authentication]) })
      end
      # 全局 SSH ACL 仅覆盖明确限制为 SSH 的管理监听端点。
      bindings = if @ssh_acl && @values["ssh.vty_ssh_only"] == true
        [ { name: @ssh_acl, ports: management_ports([ "ssh" ]) } ]
      else
        vtys.map { |entry| { name: entry[:acl], ports: management_ports(entry[:protocols]) } }
      end
      record_acl_sources(bindings, protocol: "tcp", fact: "management.acl") unless @direct_acls["management.acl"]
      if vtys.any?
        %w[ssh.vty_ssh_only ssh.vty_aaa management.acl.bound].each { |path| @sources[path] = vtys.map { |entry| entry[:line] } }
      end
    end

    # 归纳 SNMP 监听、团体字及用户的安全属性。
    def record_snmp_facts
      @issues.concat(@snmp_group_issues)
      record_fact("snmp.communities", @communities)
      record_fact("snmp.community_present", @communities.any?) if complete? || @communities.any?
      access = @communities + @snmp_users + @snmp_groups.values
      permissions = access.map { |entry| entry[:write] }
      permissions << nil unless @snmp_permission_issues.empty?
      writable = self.class.write_permission_state(permissions)
      record_fact("snmp.write_enabled", writable, lines: access.flat_map { |entry| entry[:lines] || [ entry[:line] ] }.compact)
      if writable.nil?
        record_unknown_fact("snmp.write_enabled", code: :snmp_permission_unresolved)
        @issues.concat(@snmp_permission_issues)
      end
      record_fact("snmp.users", @snmp_users)
      if @snmp_users.any?
        record_fact("snmp.v3_auth_priv", @snmp_users.all? { |entry| entry[:auth] && entry[:priv] },
          lines: @snmp_users.map { |entry| entry[:line] }.compact)
      end
      bindings = (@communities + @snmp_users).map { |entry| { name: entry[:acl], ports: @snmp_port ? [ @snmp_port ] : nil } }
      record_acl_sources(bindings, protocol: "udp", fact: "snmp.acl") unless @direct_acls["snmp.acl"]
    end

    # 汇总凭据存储方式及可度量的强度属性。
    def record_credential_facts
      record_fact("credentials.records", @credentials)
      record_fact("credentials.present", @credentials.any?) if complete? || @credentials.any?
      return if @credentials.empty?

      storage = @credentials.map { |entry| entry[:storage] }
      safe = storage.any? { |value| %w[plaintext legacy].include?(value) } ? false : storage.include?("unknown") ? nil : true
      record_fact("credentials.storage_safe", safe)
      %w[credentials.records credentials.storage_safe].each { |path| @sources[path] = @credentials.map { |entry| entry[:line] }.uniq }
    end

    # 确定所选管理协议使用的监听端口。
    def management_ports(protocols)
      return if !protocols || protocols.empty? || (protocols - @management_ports.keys).any?
      ports = protocols.map { |name| @management_ports.fetch(name) }.uniq
      ports unless ports.include?(nil)
    end

    # 解析已绑定 ACL 的来源范围，并保留不支持的证据。
    def record_acl_sources(bindings, protocol:, fact:)
      names = bindings.map { |binding| binding[:name] }
      if names.empty? || names.any? { |name| name.nil? || name.empty? }
        record_fact("#{fact}.bound", false) if complete?
        return
      end
      record_fact("#{fact}.bound", true)
      resolved = bindings.uniq.map do |binding|
        name = binding[:name]
        acl = @acls[name]
        duplicate = @issues.any? { |issue| issue[:fact] == "acls.#{name}" }
        next if !acl || duplicate
        sources = (binding[:ports] || [ nil ]).map { |port| acl.permitted_source_networks(protocol: protocol, port: port) }
        sources.flatten unless sources.any?(&:nil?)
      end
      if resolved.any?(&:nil?)
        record_unknown_fact("#{fact}.sources", code: :acl_unresolved)
        record_unknown_fact("#{fact}.restricted", code: :acl_unresolved)
        return
      end
      sources = Acl.cidrs_from_ranges(resolved.flatten.uniq.map { |cidr| Acl.ipv4_range(cidr) })
      record_fact("#{fact}.sources", sources)
      record_fact("#{fact}.restricted", !sources.include?("0.0.0.0/0"))
      lines = names.uniq.flat_map { |name| @acls.fetch(name).rules.map { |rule| rule[:line] } }.compact.uniq
      %w[sources restricted].each { |field| @sources["#{fact}.#{field}"] = lines }
    end
  end
end

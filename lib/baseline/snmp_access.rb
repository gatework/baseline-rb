# frozen_string_literal: true

require_relative "acl"

module Baseline
  # H3C 的全局、组及用户 ACL 串联；团体字端点使用序号而非秘密作为标识。
  module SnmpAccess
    # 全局过滤单独保留，不能把用户组不明确误写成全局 ACL 不存在。
    def self.global(acl:, supported:, acls:, port:, issues:)
      sources = sources_for(acl, acls, port, issues)
      unresolved = sources.nil? || issues.any? { |issue| issue[:fact] == "snmp.global_access" }
      { acl: acl, sources: unresolved ? nil : sources, supported: supported, complete: !unresolved }
    end

    # 每个主体独立保留许可，最后才能按检查契约合并实际来源。
    def self.endpoints(communities:, users:, global_acl:, acls:, port:, issues:)
      principals = communities.each_with_index.map { |entry, index| [ "community:#{index + 1}", entry ] } +
        users.map { |entry| [ "user:#{entry[:name]}", entry ] }
      allowed_cache = {}
      principals.map do |name, entry|
        chain = [ global_acl, *entry.fetch(:acl_chain, [ entry[:acl] ]) ].compact.uniq
        unresolved = port.nil? || issues.any? do |issue|
          fact = issue[:fact]
          fact && %w[snmp.acl snmp.users snmp.communities snmp.global_access snmp.v3_auth_priv].any? { |scope| fact == scope || fact.start_with?("#{scope}.") }
        end
        sources = [ "0.0.0.0/0" ]
        chain.each do |acl|
          allowed = allowed_cache.fetch(acl) { allowed_cache[acl] = sources_for(acl, acls, port, issues) }
          allowed ? sources = Acl.intersect_networks(sources, allowed) : unresolved = true
        end
        { name: name, protocol: "udp", port: port, acl_chain: chain, sources: unresolved ? nil : sources,
          bound: chain.any?, complete: !unresolved, line: entry[:line] }
      end
    end

    # 缺失、重复及无法解释的 ACL 不从其他层推导成通过。
    def self.sources_for(name, acls, port, issues)
      return [ "0.0.0.0/0" ] unless name
      return if issues.any? { |issue| issue[:fact] == "acls.#{name}" }
      acls[name]&.permitted_source_networks(protocol: "udp", port: port)
    end
    private_class_method :sources_for
  end
end

# frozen_string_literal: true

require_relative "acl"

module Baseline
  # 每个 VTY/传输端点分别归约串联 ACL，避免丢失更严格的许可及端口差异。
  module ManagementAccess
    # 不把未知协议或缺失 ACL 当成无限制；未绑定且协议明确时才记录全网。
    def self.endpoints(vtys:, ssh_acl:, ports:, acls:, issues:)
      vtys.flat_map do |vty|
        protocols = vty[:protocols]
        known = protocols.is_a?(Array) && protocols.any? && (protocols - %w[ssh stelnet telnet]).empty?
        transports = known ? protocols.map { |name| name == "stelnet" ? "ssh" : name }.uniq : [ nil ]
        transports.map do |transport|
          chain = [ vty[:acl], transport == "ssh" ? ssh_acl : nil ].compact.uniq
          port = ports[transport]
          sources = [ "0.0.0.0/0" ]
          unresolved = !known || !port || issues.any? do |issue|
            %w[management.acl ssh.vty ssh.vty_ssh_only].include?(issue[:fact]) || chain.any? { |name| issue[:fact] == "acls.#{name}" }
          end
          chain.each do |name|
            allowed = acls[name]&.permitted_source_networks(protocol: "tcp", port: port)
            if allowed.nil?
              unresolved = true
            else
              sources = Acl.intersect_networks(sources, allowed)
            end
          end
          { name: vty[:name], transport: transport, protocol: "tcp", port: port, acl_chain: chain,
            sources: unresolved ? nil : sources, bound: chain.any?, complete: !unresolved, line: vty[:line] }
        end
      end
    end
  end
end

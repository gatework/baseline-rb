# frozen_string_literal: true

require_relative "tacacs_operation_schema"

module Baseline
  # 已确认的 Comware 7 端点命令；方案密钥和域方法列表均不在这里改写。
  module TacacsCommands
    private

    def render_tacacs(operation)
      TacacsOperationSchema.validate!(kind: operation.kind, identity: operation.identity, scope: operation.scope,
        before: operation.before, after: operation.after, action: operation.action, phase: operation.phase)
      raise CommandRenderer::UnsupportedOperation, "unsupported_tacacs_style" unless self.class::TACACS_STYLE == :h3c
      role = operation.identity.fetch("role")
      primary = operation.kind == "tacacs.primary"
      endpoint = primary ? operation.after || operation.before : operation.identity.except("role").merge(operation.after || operation.before)
      unless endpoint["vrf"] == "default" && (!primary || [ operation.before, operation.after ].compact.all? { |value| value["vrf"] == "default" })
        raise CommandRenderer::UnsupportedOperation, "unsupported_tacacs_routing_context"
      end
      address = IPAddr.new(endpoint.fetch("address"))
      if endpoint["address"].include?("/") || address.to_i.zero? || address.ipv4? && (IPAddr.new("224.0.0.0/4").include?(address) || address.to_i == 4_294_967_295) || address.ipv6? && IPAddr.new("ff00::/8").include?(address)
        raise ArgumentError, "Invalid TACACS unicast address"
      end
      target = "#{address.ipv6? ? 'ipv6 ' : ''}#{endpoint['address']} #{endpoint['port']}"
      reset = operation.action == :replace && operation.before["single_connection"] && !operation.after["single_connection"]
      commands = []
      if operation.action == :remove || reset
        commands << (primary ? "undo primary #{role}" : "undo secondary #{role} #{target}")
      end
      if operation.after
        commands << "#{primary ? 'primary' : 'secondary'} #{role} #{target}#{operation.after['single_connection'] ? ' single-connection' : ''}"
      end
      commands.map { |command| CommandStep.new(view: [ "hwtacacs scheme #{operation.scope.fetch('group')}" ], command: command, phase: operation.phase, operation_id: operation.id) }
    rescue IPAddr::Error
      raise ArgumentError, "Unsupported TACACS address"
    end
  end
end

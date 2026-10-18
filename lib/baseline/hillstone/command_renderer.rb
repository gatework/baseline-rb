# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module Hillstone
    # StoneOS 删除目标也需要传输、端口和日志类别，不允许地址级泛删。
    class CommandRenderer < Baseline::CommandRenderer
      RESOURCE_KINDS = [ "syslog.destination" ].freeze
      ENTER = "configure"
      LEAVE = "exit"

      private

      # 构造相同完整身份的正反命令，其他日志类别保持独立。
      def render_resource(operation)
        identity, scope = operation.identity, operation.scope
        unless operation.kind == "syslog.destination" && (identity.keys - %w[address protocol port types]).empty? &&
            %w[address protocol port].all? { |key| identity.key?(key) } &&
            [ [ "vrf" ], [ "source" ] ].include?(scope.keys) && %w[udp tcp secure-tcp].include?(identity["protocol"]) &&
            (!identity.key?("types") || (identity["types"] - %w[event config]).empty?)
          raise UnsupportedOperation, "incomplete_stoneos_syslog_identity"
        end
        address = identity.fetch("address")
        raise ArgumentError, "Invalid address spelling" if /[\[\]%]/.match?(address)
        route = if scope.key?("source")
          " source-interface #{scope['source']}"
        elsif scope["vrf"] != "default"
          " vrouter #{scope['vrf']}"
        else ""
        end
        base = "logging syslog #{address}#{route} #{identity['protocol']} #{identity['port']}"
        category = identity.key?("types") ? " type #{identity['types'].join(' ')}" : ""
        commands = []
        commands << "no #{base}#{category}" if %i[remove replace].include?(operation.action)
        if operation.after
          unless (operation.after.keys - [ "certificate_check" ]).empty? &&
              (!operation.after.key?("certificate_check") || identity["protocol"] == "secure-tcp")
            raise UnsupportedOperation, "unsupported_stoneos_syslog_options"
          end
          cert = operation.after["certificate_check"] == false ? " server-cert-check-disable" : ""
          commands << "#{base}#{cert}#{category}"
        end
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end
    end
  end
end

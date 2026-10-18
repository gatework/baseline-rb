# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module Cisco
    # 公共对象校验与步骤编排；IOS 和 NX-OS 分别提供增删语法。
    class CommandRenderer < Baseline::CommandRenderer
      RESOURCE_KINDS = [ "syslog.destination" ].freeze

      private

      # 操作整体渲染后才输出，未知属性不能生成只有删除的半个变更。
      def render_resource(operation)
        unless operation.kind == "syslog.destination" && operation.identity.keys == [ "address" ] && operation.scope.keys == [ "vrf" ]
          raise UnsupportedOperation, "unsupported_syslog_identity"
        end
        address = operation.identity.fetch("address")
        if /[\[\]%]/.match?(address) || %w[host server ipv6 vrf use-vrf].include?(address.downcase)
          raise ArgumentError, "Invalid destination spelling"
        end
        vrf = operation.scope.fetch("vrf")
        raise ArgumentError, "Invalid routing scope" unless ResourceSchema.token?(vrf)
        commands = []
        commands << syslog_removal(address, vrf) if %i[remove replace].include?(operation.action)
        commands << syslog_addition(address, vrf, operation.after) if operation.after
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end
    end
  end
end

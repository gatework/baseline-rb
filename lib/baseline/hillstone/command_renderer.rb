# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module Hillstone
    # StoneOS 删除目标也需要传输、端口和日志类别，不允许地址级泛删。
    class CommandRenderer < Baseline::CommandRenderer
      RESOURCE_KINDS = %w[syslog.destination ntp.association].freeze
      ENTER = "configure"
      LEAVE = "exit"

      def source_requires_associations?(id) = id == "ntp.source"

      # 地址级删除和材料前提须绑定完整规划操作，不能在独立呈现调用中默认成立。
      def render(operation, verified_ntp_operation_ids: [], **context)
        if operation.kind == "ntp.server"
          unless verified_ntp_operation_ids.is_a?(Array) && verified_ntp_operation_ids.all? { |id| id.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(id) }
            raise ArgumentError, "Invalid verified NTP operations"
          end
          raise UnsupportedOperation, "ntp_preconditions_unverified" unless verified_ntp_operation_ids.include?(operation.id)
          return render_stoneos_ntp(operation)
        end
        super(operation, **context)
      end

      private

      # 固定语法只接受服务器的已知字段；移除后以完整前后状态重新建立同一个全局地址。
      def render_stoneos_ntp(operation)
        address = operation.identity.fetch("address")
        if address.bytesize > 127 || /[\[\]%]/.match?(address) || %w[key source prefer vrouter].include?(address.downcase)
          raise ArgumentError, "Invalid StoneOS NTP address"
        end
        [ operation.before, operation.after ].compact.each do |fields|
          unless (fields.keys - %w[vrf source prefer key_id vrf_explicit]).empty? && (!fields.key?("key_id") || fields["key_id"] <= 65_535)
            raise UnsupportedOperation, "unsupported_stoneos_ntp_options"
          end
        end
        commands = []
        commands << "no ntp server #{address}" if operation.before
        if (fields = operation.after)
          tail = []
          tail << "key #{fields['key_id']}" if fields.key?("key_id")
          tail << "source #{fields['source']}" if fields.key?("source")
          tail << "prefer" if fields["prefer"] == true
          tail << "vrouter #{fields['vrf']}" if fields["vrf"] != "default" || fields["vrf_explicit"] == true
          commands << [ "ntp server #{address}", *tail ].join(" ")
        end
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end

      def render_ntp(*) = raise UnsupportedOperation, "native_ntp_server_operation_required"

      # 构造相同完整身份的正反命令，其他日志类别保持独立。
      def render_resource(operation)
        identity, scope = operation.identity, operation.scope
        unless operation.kind == "syslog.destination" && (identity.keys - %w[address protocol port types]).empty? &&
            %w[address protocol port].all? { |key| identity.key?(key) } &&
            [ [ "vrf" ], [ "source" ], %w[vrf vrf_mode] ].include?(scope.keys) && %w[udp tcp secure-tcp].include?(identity["protocol"]) &&
            (!identity.key?("types") || (identity["types"] - %w[event config]).empty?)
          raise UnsupportedOperation, "incomplete_stoneos_syslog_identity"
        end
        address = identity.fetch("address")
        raise ArgumentError, "Invalid address spelling" if /[\[\]%]/.match?(address)
        route = if scope.key?("source")
          " source-interface #{scope['source']}"
        elsif scope["vrf"] != "default" || scope["vrf_mode"] == "named"
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

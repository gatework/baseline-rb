# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module H3c
    # Comware 的全局源接口、协议版本和服务开关语法。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "info-center loghost source", "ntp.source" => "ntp-service source" }.freeze
      DISABLE_COMMANDS = { "telnet" => "undo telnet server enable", "http" => "undo ip http enable",
        "https" => "undo ip https enable", "ftp" => "undo ftp server enable", "tftp" => "undo tftp server enable" }.freeze
      SSH_VERSION_TWO = "undo ssh server compatible-ssh1x enable"
      ENTER = "system-view"
      LEAVE = "return"
      EXIT_VIEW = "quit"
      RESOURCE_KINDS = %w[syslog.destination ntp.association].freeze
      NTP_STYLE = :h3c
      VTY_PROTOCOL_COMMAND = "protocol inbound ssh"
      SNMP_VERSION_REMOVAL = "undo snmp-agent sys-info version"
      SSH_DISABLE_COMMAND = "undo ssh server enable"
      PREREQUISITES = CtxParser::Immutable.copy({ "ssh.vty_ssh_only" => { "ssh.enabled" => true },
        "snmp.versions" => { "snmp.enabled" => true, "snmp.v3_auth_priv" => true } })

      private

      # 同身份属性替换先撤销旧对象再重建；独立目标由计划按先增后删编排。
      def render_resource(operation)
        unless operation.kind == "syslog.destination" && operation.identity.keys == [ "address" ] && operation.scope.keys == [ "vrf" ]
          raise UnsupportedOperation, "unsupported_syslog_identity"
        end
        address = operation.identity.fetch("address")
        if /[\[\]%]/.match?(address) || %w[source source-port vpn-instance ipv6 domain].include?(address.downcase)
          raise ArgumentError, "Unsupported address spelling"
        end
        vrf = operation.scope.fetch("vrf")
        target = "#{vrf == 'default' ? '' : "vpn-instance #{vrf} "}#{address.include?(':') ? 'ipv6 ' : ''}#{address}"
        commands = []
        commands << "undo info-center loghost #{target}" if %i[remove replace].include?(operation.action)
        if operation.after
          attributes = operation.after
          unless (attributes.keys - %w[port dscp facility channel filter protocol]).empty? &&
              (!attributes.key?("protocol") || attributes["protocol"] == "udp") &&
              (!attributes.key?("facility") || /\Alocal[0-7]\z/.match?(attributes["facility"])) &&
              (!attributes.key?("filter") || attributes["filter"].bytesize <= 8)
            raise UnsupportedOperation, "unsupported_syslog_options"
          end
          tail = %w[port dscp facility channel filter].filter_map { |key| "#{key} #{attributes[key]}" if attributes.key?(key) }
          commands << [ "info-center loghost #{target}", *tail ].join(" ")
        end
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end
    end
  end
end

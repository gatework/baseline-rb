# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module Huawei
    # VRP 源接口使用自己的声明，不继承 Comware 的命令名称。
    class CommandRenderer < Baseline::CommandRenderer
      NTP_AUTHENTICATION_COMMANDS = { true => "ntp-service authentication enable", false => "undo ntp-service authentication enable" }.freeze
      NTP_AUTHENTICATION_BEFORE_ASSOCIATIONS = true
      SOURCE_COMMANDS = { "syslog.source" => "info-center loghost source", "ntp.source" => "ntp-service source-interface" }.freeze
      DISABLE_COMMANDS = { "telnet" => "undo telnet server enable", "ftp" => "undo ftp server enable" }.freeze
      SSH_VERSION_TWO = "undo ssh server compatible-ssh1x enable"
      ENTER = "system-view"
      LEAVE = "return"
      EXIT_VIEW = "quit"
      RESOURCE_KINDS = %w[syslog.destination ntp.association].freeze
      NTP_STYLE = :vrp
      SNMP_PERMISSION_PROFILES = [ "vrp_v600" ].freeze
      ACCESS_STYLE = :vrp
      VTY_AUTHENTICATION_PROFILE = "vrp_s_series"
      VTY_PROTOCOL_COMMAND = "protocol inbound ssh"
      SSH_DISABLE_COMMAND = "undo stelnet server enable"
      PREREQUISITES = CtxParser::Immutable.copy({ "ssh.vty_ssh_only" => { "ssh.enabled" => true } })

      private

      # VRP 域名使用 domain，VPN 位于目标之后，不套用 Comware 的前置格式。
      def render_resource(operation)
        unless operation.kind == "syslog.destination" && operation.identity.keys == [ "address" ] && operation.scope.keys == [ "vrf" ]
          raise UnsupportedOperation, "unsupported_syslog_identity"
        end
        address = operation.identity.fetch("address")
        raise ArgumentError, "Unsupported address spelling" if /[\[\]%]/.match?(address)
        family = begin
          IPAddr.new(address).ipv6? ? "ipv6 " : ""
        rescue IPAddr::Error
          "domain "
        end
        vrf = operation.scope.fetch("vrf")
        target = "#{family}#{address}#{vrf == 'default' ? '' : " vpn-instance #{vrf}"}"
        commands = []
        commands << "undo info-center loghost #{target}" if %i[remove replace].include?(operation.action)
        if operation.after
          attributes = operation.after
          unless (attributes.keys - %w[port facility channel protocol]).empty? &&
              (!attributes.key?("protocol") || attributes["protocol"] == "udp") &&
              (!attributes.key?("facility") || /\Alocal[0-7]\z/.match?(attributes["facility"]))
            raise UnsupportedOperation, "unsupported_vrp_syslog_options"
          end
          tail = %w[port facility channel].filter_map { |key| "#{key} #{attributes[key]}" if attributes.key?(key) }
          commands << [ "info-center loghost #{target}", *tail ].join(" ")
        end
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end
    end
  end
end

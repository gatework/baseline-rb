# frozen_string_literal: true

require_relative "../cisco/command_renderer"

module Baseline
  module CiscoIos
    # IOS 只生成已建模的全局命令，不以关闭 VTY 代替服务修正。
    class CommandRenderer < Baseline::Cisco::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "logging source-interface", "ntp.source" => "ntp source" }.freeze
      DISABLE_COMMANDS = { "http" => "no ip http server", "https" => "no ip http secure-server", "finger" => "no ip finger" }.freeze
      SSH_VERSION_TWO = "ip ssh version 2"
      ENTER = "configure terminal"
      LEAVE = "end"
      RESOURCE_KINDS = %w[syslog.destination ntp.association].freeze
      NTP_STYLE = :ios
      ACCESS_STYLE = :ios
      VTY_PROTOCOL_COMMAND = "transport input ssh"
      PREREQUISITES = CtxParser::Immutable.copy({ "ssh.vty_ssh_only" => { "ssh.enabled" => true } })

      private

      # IOS 在地址之后指定 VRF，IPv6 地址有独立的地址族关键字。
      def syslog_target(address, vrf)
        "#{address.include?(':') ? 'ipv6 ' : ''}#{address}#{vrf == 'default' ? '' : " vrf #{vrf}"}"
      end

      # no 形式仅撤销指定路由域的目标，不附加传输属性。
      def syslog_removal(address, vrf) = "no logging host #{syslog_target(address, vrf)}"

      # 保留已有显式传输选项；无批准或已知值时不编造协议及端口。
      def syslog_addition(address, vrf, attributes)
        unless (attributes.keys - %w[protocol port]).empty? && (!attributes.key?("protocol") || %w[udp tcp].include?(attributes["protocol"]))
          raise UnsupportedOperation, "unsupported_ios_syslog_options"
        end
        raise UnsupportedOperation, "transport_required_for_port" if attributes.key?("port") && !attributes.key?("protocol")
        tail = []
        tail << "transport #{attributes['protocol']}" if attributes.key?("protocol")
        tail << "port #{attributes['port']}" if attributes.key?("port")
        [ "logging host #{syslog_target(address, vrf)}", *tail ].join(" ")
      end
    end
  end
end

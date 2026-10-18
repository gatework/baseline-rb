# frozen_string_literal: true

require_relative "../cisco/command_renderer"

module Baseline
  module CiscoNxos
    # NX-OS 功能开关与源接口命令，不复用 IOS 的版本设置。
    class CommandRenderer < Baseline::Cisco::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "logging source-interface", "ntp.source" => "ntp source-interface" }.freeze
      DISABLE_COMMANDS = { "telnet" => "no feature telnet", "ftp" => "no feature ftp-server", "tftp" => "no feature tftp-server" }.freeze
      ENTER = "configure terminal"
      LEAVE = "end"
      RESOURCE_KINDS = %w[syslog.destination ntp.association].freeze
      NTP_STYLE = :nxos
      SSH_DISABLE_COMMAND = "no feature ssh"

      private

      # NX-OS 地址族由地址本身决定，路由域使用 use-vrf。
      def syslog_removal(address, vrf)
        "no logging server #{address}#{vrf == 'default' ? '' : " use-vrf #{vrf}"}"
      end

      # 已核验的 NX-OS 命令子集；版本相关 port/transport 扩展保留受阻。
      def syslog_addition(address, vrf, attributes)
        facilities = %w[auth authpriv cron daemon ftp kernel local0 local1 local2 local3 local4 local5 local6 local7 lpr mail news syslog user uucp]
        unless (attributes.keys - %w[severity facility]).empty? && (!attributes.key?("facility") || facilities.include?(attributes["facility"]))
          raise UnsupportedOperation, "unsupported_nxos_syslog_options"
        end
        tail = []
        tail << attributes["severity"].to_s if attributes.key?("severity")
        tail << "use-vrf #{vrf}" unless vrf == "default"
        tail << "facility #{attributes['facility']}" if attributes.key?("facility")
        [ "logging server #{address}", *tail ].join(" ")
      end
    end
  end
end

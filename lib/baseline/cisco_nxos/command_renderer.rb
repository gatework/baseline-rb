# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module CiscoNxos
    # NX-OS 功能开关与源接口命令，不复用 IOS 的版本设置。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "logging source-interface", "ntp.source" => "ntp source-interface" }.freeze
      DISABLE_COMMANDS = { "telnet" => "no feature telnet", "ftp" => "no feature ftp-server", "tftp" => "no feature tftp-server" }.freeze
      ENTER = "configure terminal"
      LEAVE = "end"
    end
  end
end

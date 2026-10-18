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
    end
  end
end

# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module Huawei
    # VRP 源接口使用自己的声明，不继承 Comware 的命令名称。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "info-center loghost source", "ntp.source" => "ntp-service source-interface" }.freeze
      DISABLE_COMMANDS = { "telnet" => "undo telnet server enable", "ftp" => "undo ftp server enable" }.freeze
      SSH_VERSION_TWO = "undo ssh server compatible-ssh1x enable"
      ENTER = "system-view"
      LEAVE = "return"
      EXIT_VIEW = "quit"
    end
  end
end

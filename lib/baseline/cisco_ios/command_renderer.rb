# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module CiscoIos
    # IOS 只生成已建模的全局命令，不以关闭 VTY 代替服务修正。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "logging source-interface", "ntp.source" => "ntp source" }.freeze
      DISABLE_COMMANDS = { "http" => "no ip http server", "https" => "no ip http secure-server", "finger" => "no ip finger" }.freeze
      SSH_VERSION_TWO = "ip ssh version 2"
      ENTER = "configure terminal"
      LEAVE = "end"
    end
  end
end

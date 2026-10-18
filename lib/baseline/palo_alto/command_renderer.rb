# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module PaloAlto
    # 服务路由的叶子修改保留 profile；不自动提交候选配置。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "set deviceconfig system route service syslog source interface",
        "ntp.source" => "set deviceconfig system route service ntp source interface" }.freeze
      ENTER = "configure"
      LEAVE = "exit"
      PREREQUISITES = CtxParser::Immutable.copy({ "ntp.source" => { "ntp.source_address_present" => false },
        "syslog.source" => { "syslog.source_address_present" => false } })

      private

      # PAN-OS 逻辑接口使用点分单元编号，不接受路由器式 Loopback0。
      def source_interface(value)
        name = super
        name if name && /\A(?:management|ethernet\d+\/\d+(?:\.\d+)?|ae\d+(?:\.\d+)?|loopback\.\d+|tunnel\.\d+|vlan(?:\.\d+)?)\z/.match?(name)
      end
    end
  end
end

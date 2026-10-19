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
      RESOURCE_KINDS = [ "ntp.association" ].freeze
      PREREQUISITES = CtxParser::Immutable.copy({ "ntp.source" => { "ntp.source_address_present" => false },
        "syslog.source" => { "syslog.source_address_present" => false } })

      private

      # 固定主备槽位只改批准叶子；既有认证子树保留，不导出或重写其秘密。
      def render_ntp(operation, verified_key_ids: [], verified_slots: [])
        name = operation.identity["name"]
        unless operation.identity.keys == [ "name" ] && operation.scope.empty? &&
            %w[primary-ntp-server secondary-ntp-server].include?(name) &&
            [ operation.before, operation.after ].compact.all? { |fields| (fields.keys - %w[address authenticated]).empty? }
          raise UnsupportedOperation, "unsupported_panos_ntp_slot"
        end
        unless verified_slots.is_a?(Array) && (verified_slots - %w[primary-ntp-server secondary-ntp-server]).empty?
          raise ArgumentError, "Invalid verified NTP slots"
        end
        if operation.action == :replace && operation.before["authenticated"] == true &&
            operation.before["address"] != operation.after["address"] && !verified_slots.include?(name)
          raise UnsupportedOperation, "ntp_peer_key_compatibility_unverified"
        end
        prefix = "deviceconfig system ntp-servers #{name}"
        commands = if operation.action == :remove
          [ "delete #{prefix}" ]
        elsif operation.action == :add && operation.after["authenticated"] == false && operation.after.key?("address")
          [ "set #{prefix} ntp-server-address #{operation.after['address']}", "set #{prefix} authentication-type none" ]
        elsif operation.action == :replace && [ true, false ].include?(operation.before["authenticated"]) &&
            operation.after["authenticated"] == operation.before["authenticated"] && operation.after.key?("address")
          [ "set #{prefix} ntp-server-address #{operation.after['address']}" ]
        else
          raise UnsupportedOperation, "panos_ntp_authentication_material_required"
        end
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end

      # PAN-OS 逻辑接口使用点分单元编号，不接受路由器式 Loopback0。
      def source_interface(value)
        name = super
        name if name && /\A(?:management|ethernet\d+\/\d+(?:\.\d+)?|ae\d+(?:\.\d+)?|loopback\.\d+|tunnel\.\d+|vlan(?:\.\d+)?)\z/.match?(name)
      end
    end
  end
end

# frozen_string_literal: true

require_relative "../command_renderer"

module Baseline
  module PaloAlto
    # 命名目标和服务路由只修改批准叶子，不自动提交候选配置。
    class CommandRenderer < Baseline::CommandRenderer
      SOURCE_COMMANDS = { "syslog.source" => "set deviceconfig system route service syslog source interface",
        "ntp.source" => "set deviceconfig system route service ntp source interface" }.freeze
      ENTER = "configure"
      LEAVE = "exit"
      RESOURCE_KINDS = %w[ntp.association syslog.destination].freeze
      PREREQUISITES = CtxParser::Immutable.copy({ "ntp.source" => { "ntp.source_address_present" => false },
        "syslog.source" => { "syslog.source_address_present" => false } })

      # 完整操作绑定已核验的引用及 SSL 前提，独立调用不能默认这些证据成立。
      def render(operation, verified_syslog_operation_ids: [], **context)
        if %w[syslog.destination syslog.reference].include?(operation.kind)
          unless verified_syslog_operation_ids.is_a?(Array) && verified_syslog_operation_ids.all? { |id| id.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(id) }
            raise ArgumentError, "Invalid verified Syslog operations"
          end
          raise UnsupportedOperation, "syslog_preconditions_unverified" unless verified_syslog_operation_ids.include?(operation.id)
        end
        super(operation, **context)
      end

      private

      # 按完整命名身份更新服务器叶子；从不删除 profile、格式或转发匹配项。
      def render_resource(operation)
        return render_syslog_reference(operation) if operation.kind == "syslog.reference"
        unless operation.kind == "syslog.destination" && operation.identity.keys == [ "name" ] && operation.scope.keys == [ "profile" ]
          raise UnsupportedOperation, "unsupported_panos_syslog_identity"
        end
        unless [ operation.identity["name"], operation.scope["profile"] ].all? { |name| name.bytesize <= 31 && /\A[a-zA-Z0-9_][a-zA-Z0-9_ -]*\z/.match?(name) }
          raise UnsupportedOperation, "unsupported_panos_syslog_name"
        end
        fields = { "address" => "server", "protocol" => "transport", "port" => "port", "format" => "format", "facility" => "facility" }
        [ operation.before, operation.after ].compact.each do |attributes|
          unless (attributes.keys - fields.keys).empty? && (!attributes.key?("protocol") || %w[udp tcp ssl].include?(attributes["protocol"])) &&
              (!attributes.key?("format") || %w[BSD IETF].include?(attributes["format"])) &&
              (!attributes.key?("facility") || /\ALOG_(?:USER|LOCAL[0-7])\z/.match?(attributes["facility"]))
            raise UnsupportedOperation, "unsupported_panos_syslog_options"
          end
        end
        prefix = "shared log-settings syslog \"#{operation.scope['profile']}\" server \"#{operation.identity['name']}\""
        commands = if operation.action == :remove
          [ "delete #{prefix}" ]
        else
          if operation.action == :add && !(fields.keys - operation.after.keys).empty?
            raise UnsupportedOperation, "incomplete_panos_syslog_server"
          end
          if %w[address port protocol].any? { |field| operation.after[field] != operation.before&.[](field) } &&
              !(%w[protocol port] - operation.after.keys).empty?
            raise UnsupportedOperation, "incomplete_panos_syslog_endpoint"
          end
          fields.filter_map do |field, command|
            next unless operation.after.key?(field) && operation.after[field] != operation.before&.[](field)
            value = operation.after[field]
            value = value.upcase if field == "protocol"
            value = "\"#{value}\"" if field == "address"
            "set #{prefix} #{command} #{value}"
          end
        end
        raise UnsupportedOperation, "no_supported_commands" if commands.empty?
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end

      # 接收成员逐个增加再逐个移除，绝不删除整个列表或重写过滤式和动作。
      def render_syslog_reference(operation)
        identity = operation.identity
        names = operation.before["profiles"] + operation.after["profiles"]
        match = identity.fetch("match")
        forwarding = identity["forwarding_profile"]
        unless names.all? { |name| /\A[a-zA-Z0-9_][a-zA-Z0-9_ -]*\z/.match?(name) && name.bytesize <= 31 } &&
            match.bytesize <= 31 && /\A[a-zA-Z0-9][a-zA-Z0-9_. -]*\z/.match?(match) &&
            (!forwarding || forwarding.bytesize <= 64 && /\A[a-zA-Z0-9_][a-zA-Z0-9_ -]*\z/.match?(forwarding))
          raise UnsupportedOperation, "unsupported_panos_syslog_name"
        end
        path = identity["kind"] == "syslog.device" ? identity["log_type"] : "profiles \"#{identity['forwarding_profile']}\""
        prefix = "shared log-settings #{path} match-list \"#{identity['match']}\" send-syslog"
        commands = (operation.after["profiles"] - operation.before["profiles"]).map { |profile| "set #{prefix} \"#{profile}\"" } +
          (operation.before["profiles"] - operation.after["profiles"]).map { |profile| "delete #{prefix} \"#{profile}\"" }
        raise UnsupportedOperation, "no_supported_commands" if commands.empty?
        commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
      end

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

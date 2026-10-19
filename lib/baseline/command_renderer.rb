# frozen_string_literal: true

require_relative "command_step"
require_relative "resource_schema"
require_relative "ntp_commands"
require_relative "access_commands"
require_relative "tacacs_commands"

module Baseline
  # 共享单行参数校验和视图编排；厂商仅声明已支持的精确语法。
  class CommandRenderer
    include NtpCommands
    include AccessCommands
    include TacacsCommands
    class UnsupportedOperation < StandardError; end
    SOURCE_COMMANDS = {}.freeze
    DISABLE_COMMANDS = {}.freeze
    SSH_VERSION_TWO = nil
    ENTER = nil
    LEAVE = nil
    EXIT_VIEW = "exit"
    PREREQUISITES = {}.freeze
    RESOURCE_KINDS = [].freeze
    VTY_PROTOCOL_COMMAND = nil
    SSH_DISABLE_COMMAND = nil
    SNMP_VERSION_REMOVAL = nil
    ACCESS_STYLE = nil
    SNMP_GLOBAL_ACL = nil
    TACACS_STYLE = nil

    # 原生命令依赖的独立事实由规划器核验，而非在命令里假定成立。
    def prerequisites(id) = self.class::PREREQUISITES.fetch(id, {})

    # 查询当前呈现器确实可生成的设置类型。
    def supports?(id)
      self.class::SOURCE_COMMANDS.key?(id) || id == "services.disabled" && self.class::DISABLE_COMMANDS.any? ||
        id == "ssh.vty_ssh_only" && !self.class::VTY_PROTOCOL_COMMAND.nil? ||
        id == "ssh.enabled" && !self.class::SSH_DISABLE_COMMAND.nil? ||
        %w[snmp.acl_bound snmp.acl_restricted snmp.sources].include?(id) && !self.class::SNMP_GLOBAL_ACL.nil? ||
        id == "snmp.versions" && !self.class::SNMP_VERSION_REMOVAL.nil? ||
        %w[management.acl_bound management.acl_restricted management.sources].include?(id) && !self.class::ACCESS_STYLE.nil? ||
        id == "ssh.versions" && !self.class::SSH_VERSION_TWO.nil? ||
        %w[tacacs.minimum_servers tacacs.servers tacacs.endpoints].include?(id) && !self.class::TACACS_STYLE.nil? ||
        self.class::RESOURCE_KINDS.include?(ResourceSchema::FACTS.key(id) ||
          { "syslog.servers" => "syslog.destination", "syslog.minimum_servers" => "syslog.destination",
            "ntp.servers" => "ntp.association", "ntp.minimum_servers" => "ntp.association" }[id])
    end

    # 将完整操作转换为命令；任何一个子命令不受支持则整体拒绝该操作。
    def render(operation, verified_ntp_key_ids: [], verified_ntp_slots: [])
      return render_tacacs(operation) if TacacsOperationSchema::KINDS.include?(operation.kind)
      return render_access(operation) if AccessOperationSchema::KINDS.include?(operation.kind)
      return render_ntp(operation, verified_key_ids: verified_ntp_key_ids, verified_slots: verified_ntp_slots) if operation.kind == "ntp.association" && self.class::RESOURCE_KINDS.include?(operation.kind)
      return render_resource(operation) unless operation.kind == "setting"
      id = operation.identity.fetch("rule")
      if id == "ssh.vty_ssh_only" && self.class::VTY_PROTOCOL_COMMAND && operation.after == true
        view = operation.scope["vty"]
        unless view.is_a?(String) && /\A(?:line|user-interface) vty \d+(?: \d+)?\z/.match?(view)
          raise ArgumentError, "Invalid VTY view"
        end
        return [ CommandStep.new(view: [ view ], command: self.class::VTY_PROTOCOL_COMMAND, phase: operation.phase, operation_id: operation.id) ]
      end
      commands = if id == "ssh.enabled" && operation.after == false && self.class::SSH_DISABLE_COMMAND
        [ self.class::SSH_DISABLE_COMMAND ]
      elsif id == "snmp.versions" && self.class::SNMP_VERSION_REMOVAL
        before = operation.before
        unless before.is_a?(Array) && (before - %w[v1 v2c v3]).empty? && before.include?("v3") && operation.after.include?("v3")
          raise UnsupportedOperation, "existing_snmp_v3_required"
        end
        removed = (before - operation.after).uniq.sort
        raise UnsupportedOperation, "no_version_removal" if removed.empty?
        [ "#{self.class::SNMP_VERSION_REMOVAL} #{removed.join(' ')}" ]
      elsif self.class::SOURCE_COMMANDS.key?(id)
        value = source_interface(operation.after)
        raise ArgumentError, "Invalid interface parameter" unless value
        [ "#{self.class::SOURCE_COMMANDS.fetch(id)} #{value}" ]
      elsif id == "ssh.versions" && self.class::SSH_VERSION_TWO && operation.after.include?("2")
        [ self.class::SSH_VERSION_TWO ]
      elsif id == "services.disabled" && operation.before.is_a?(Hash)
        operation.after.select { |name| operation.before[name] == true }.map do |name|
          self.class::DISABLE_COMMANDS.fetch(name) { raise UnsupportedOperation, "unsupported_service" }
        end
      else
        raise UnsupportedOperation, "unsupported_setting"
      end
      raise UnsupportedOperation, "no_supported_commands" if commands.empty?
      commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
    end

    # 命令块只进入和退出配置视图，不包含保存、提交或交互确认。
    def configuration_commands(steps)
      return [] if steps.empty?
      output = [ self.class::ENTER ]
      active = []
      steps.each do |step|
        common = active.zip(step.view).take_while { |left, right| left == right }.size
        (active.size - common).times { output << self.class::EXIT_VIEW }
        output.concat(step.view.drop(common))
        output << step.command
        active = step.view
      end
      output << self.class::LEAVE
      output.freeze
    end

    private

    # 未声明资源能力的厂商拒绝生成，不能通过通用字符串拼接伪装支持。
    def render_resource(_operation)
      raise UnsupportedOperation, "unsupported_resource"
    end

    # 通用接口词元归一化，厂商可收紧原生接口命名语法。
    def source_interface(value) = ResourceSchema.interface_name(value)
  end
end

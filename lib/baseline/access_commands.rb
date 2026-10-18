# frozen_string_literal: true

require "ipaddr"
require_relative "access_operation_schema"

module Baseline
  # 基本来源 ACL 的创建先于端点重绑，显式拒绝未核验的厂商语法。
  module AccessCommands
    # 只生成新 ACL 及已有 line VTY 的重绑，不输出删除现有 ACL 的命令。
    def render_access(operation)
      raise CommandRenderer::UnsupportedOperation, "unsupported_access_renderer" unless self.class::ACCESS_STYLE == :h3c
      if operation.kind == "access.acl"
        name, sources = operation.identity.fetch("name"), operation.after.fetch("sources")
        validate_basic_acl!(name)
        raise CommandRenderer::UnsupportedOperation, "acl_sequence_limit" if sources.size > 13_105
        commands = sources.each_with_index.map do |source, index|
          ip = IPAddr.new(source)
          wildcard = IPAddr.new((1 << (32 - ip.prefix)) - 1, Socket::AF_INET)
          "rule #{(index + 1) * 5} permit source #{ip} #{wildcard}"
        end
        commands << "rule #{(sources.size + 1) * 5} deny"
        view = [ "acl basic #{name}" ]
      else
        name = operation.identity.fetch("name")
        unless /\Aline vty \d+(?: \d+)?\z/.match?(name)
          raise CommandRenderer::UnsupportedOperation, "unsupported_vty_view"
        end
        acl = operation.after.fetch("acl")
        validate_basic_acl!(acl)
        commands, view = [ "acl #{acl}" ], [ name ]
      end
      commands.map { |command| CommandStep.new(view: view, command: command, phase: operation.phase, operation_id: operation.id) }
    end

    private

    # 数字基本 ACL 与已验证的 line 语法配套，不能把命名或高级 ACL 硬套成基本 ACL。
    def validate_basic_acl!(name)
      raise ArgumentError, "Invalid H3C basic ACL identity" unless /\A2\d{3}\z/.match?(name)
    end
  end
end

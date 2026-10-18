# frozen_string_literal: true

require "ipaddr"
require_relative "access_operation_schema"

module Baseline
  # 来源 ACL 的创建先于端点重绑，厂商语法和 VRF 修饰符不能互相替换。
  module AccessCommands
    # 只生成新 ACL 及已有 VTY 的重绑，不输出删除现有 ACL 的命令。
    def render_access(operation)
      style = self.class::ACCESS_STYLE
      raise CommandRenderer::UnsupportedOperation, "unsupported_access_renderer" unless %i[h3c vrp ios].include?(style)
      view, commands = operation.kind == "access.acl" ? access_acl_definition(operation, style) : access_binding_definition(operation, style)
      commands.map { |command| CommandStep.new(view: view, command: command, phase: operation.phase, operation_id: operation.id) }
    end

    private

    # 以显式拒绝结尾，避免绑定上下文中的未匹配缺省行为扩大许可。
    def access_acl_definition(operation, style)
      name, sources = operation.identity.fetch("name"), operation.after.fetch("sources")
      validate_acl_identity!(name, style)
      raise CommandRenderer::UnsupportedOperation, "acl_sequence_limit" if sources.size > 13_105
      commands = sources.each_with_index.map do |source, index|
        ip = IPAddr.new(source)
        wildcard = IPAddr.new((1 << (32 - ip.prefix)) - 1, Socket::AF_INET)
        style == :ios ? "#{(index + 1) * 5} permit #{ip} #{wildcard}" : "rule #{(index + 1) * 5} permit source #{ip} #{wildcard}"
      end
      commands << (style == :ios ? "#{(sources.size + 1) * 5} deny any" : "rule #{(sources.size + 1) * 5} deny")
      prefix = { h3c: "acl basic", vrp: "acl number", ios: "ip access-list standard" }.fetch(style)
      [ [ "#{prefix} #{name}" ], commands ]
    end

    # VRP 使用 inbound，现代 Comware line 视图省略方向；IOS 保留已批准的 VRF 范围。
    def access_binding_definition(operation, style)
      name, acl = operation.identity.fetch("name"), operation.after.fetch("acl")
      pattern = style == :vrp ? /\Auser-interface vty \d+(?: \d+)?\z/ : /\Aline vty \d+(?: \d+)?\z/
      raise CommandRenderer::UnsupportedOperation, "unsupported_vty_view" unless pattern.match?(name)
      validate_acl_identity!(acl, style)
      command = if style == :ios
        unless operation.after.key?("vrf_also")
          raise CommandRenderer::UnsupportedOperation, "missing_vrf_scope"
        end
        "access-class #{acl} in#{operation.after['vrf_also'] ? ' vrf-also' : ''}"
      else
        raise CommandRenderer::UnsupportedOperation, "unsupported_vrf_scope" if operation.after.key?("vrf_also")
        "acl #{acl}#{style == :vrp ? ' inbound' : ''}"
      end
      [ [ name ], [ command ] ]
    end

    # IOS 的标准数字范围与字母开头的命名标识分开，不能把扩展 ACL 编号作为标准 ACL。
    def validate_acl_identity!(name, style)
      valid = if style == :ios
        if /\A[0-9]+\z/.match?(name)
          number = name.to_i
          name == number.to_s && (number.between?(1, 99) || number.between?(1300, 1999))
        else
          ResourceSchema.token?(name) && /\A[a-zA-Z]/.match?(name)
        end
      else
        /\A2\d{3}\z/.match?(name)
      end
      raise ArgumentError, "Invalid vendor ACL identity" unless valid
    end
  end
end

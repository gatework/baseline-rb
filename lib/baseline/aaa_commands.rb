# frozen_string_literal: true

require_relative "aaa_chain_schema"
require_relative "vty_authentication_schema"

module Baseline
  # 原生命令仅消费规划器已核验的完整操作；配对顺序保留认证和协议联动。
  module AaaCommands
    private

    def render_aaa(operation, verified_ids:)
      native = operation.kind == VtyAuthenticationSchema::KIND ? self.class::VTY_AUTHENTICATION_PROFILE == operation.scope["syntax_profile"] : self.class::TACACS_STYLE == :h3c
      unless native && verified_ids.is_a?(Array) &&
          verified_ids.all? { |id| id.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(id) } && verified_ids.include?(operation.id)
        raise CommandRenderer::UnsupportedOperation, "management_method_preconditions_unverified"
      end
      schema = operation.kind == AaaChainSchema::KIND ? AaaChainSchema : VtyAuthenticationSchema
      schema.validate!(identity: operation.identity, scope: operation.scope, before: operation.before, after: operation.after, action: operation.action, phase: operation.phase)
      if operation.kind == VtyAuthenticationSchema::KIND
        view = operation.identity.fetch("vty")
        commands = [ "authentication-mode #{operation.after.fetch('authentication')}", "protocol inbound #{operation.after.fetch('protocols').first}" ]
      else
        view = "domain #{operation.scope.fetch('domain')}"
        methods = operation.after["methods"].map { |method| method["kind"] == "local" ? "local" : "hwtacacs-scheme #{method.fetch('group')}" }
        commands = [ "#{operation.identity.fetch('role')} login #{methods.join(' ')}" ]
      end
      commands.map { |command| CommandStep.new(view: [ view ], command: command, phase: operation.phase, operation_id: operation.id) }
    end
  end
end

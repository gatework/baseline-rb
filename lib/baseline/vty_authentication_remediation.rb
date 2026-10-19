# frozen_string_literal: true

require_relative "management_authentication"
require_relative "vty_authentication_schema"

module Baseline
  # 修正模式时显式保留有效协议，对依赖该范围的 SSH/TACACS 指标统一投影。
  class VtyAuthenticationRemediation
    Result = Data.define(:operations, :steps, :checks)
    Blocked = TargetRemediation::Blocked

    def initialize(policy:, renderer:)
      @policy, @renderer = policy, renderer
    end

    def call(audit)
      finding = audit.findings.find { |item| item.id == "ssh.vty_aaa" }
      return unless finding && finding.expected == true && %i[fail unknown].include?(finding.status) && audit.configuration.platform == "h3c"
      options = @policy.rules.find { |rule| rule.id == finding.id }.remediation
      return if options.empty?
      transport = audit.findings.find { |item| item.id == "ssh.vty_ssh_only" && item.status != :not_applicable && item.expected == true }
      related = [ transport ].compact.reject { |item| item.status == :pass }
      build(audit, finding, related, transport, options)
    end

    private

    def build(audit, finding, related, transport, options)
      evidence = audit.configuration
      row = ManagementAuthentication.new(audit: audit).call(options: options, role: "authentication")
      require!(row[:methods].map { |method| method.transform_keys(&:to_s) } == options["methods"], "existing_approved_management_method_chain")
      require!(evidence.fact_known?("ssh.vty"), "resolved_vty_inventory")
      vtys = evidence.fact("ssh.vty")
      names = vtys.map { |vty| vty[:name] }
      require!(VtyAuthenticationSchema.ranges?(names) && names.sort == options.fetch("vty_ranges", []).sort, "complete_matching_vty_scope")
      login = audit.findings.find { |item| item.id == "tacacs.login" && item.status != :not_applicable && !item.expected.nil? }
      uses_tacacs = options["methods"].first["kind"] == "tacacs"
      raise Blocked, :policy_conflict if login && login.expected != uses_tacacs
      related += [ login ] if login && login.status != :pass
      if transport
        disabled = audit.findings.any? { |item| item.id == "ssh.enabled" && item.status != :not_applicable && item.expected == false }
        raise Blocked, :policy_conflict if disabled
        require!(evidence.fact_known?("ssh.enabled") && evidence.fact("ssh.enabled") == true, "ssh.enabled")
      end
      risk = [ finding, *related ].any? { |item| item.severity == "critical" } ? "critical" : "high"
      operations = vtys.filter_map do |vty|
        before = { "authentication" => vty[:authentication], "protocols" => vty[:protocols], "local_protocols" => vty[:local_protocols] }
        require!(VtyAuthenticationSchema.settings?(before), "known_vty_authentication_and_protocols")
        after = { "authentication" => "scheme", "protocols" => transport ? [ "ssh" ] : vty[:protocols] }
        next if before.except("local_protocols") == after
        if VtyAuthenticationSchema.temporary_rebind?(before)
          require!(options["temporary_vty_protocol_rebind_approved"] == true, "temporary_vty_protocol_rebind_approved")
        end
        ConfigurationOperation.new(kind: VtyAuthenticationSchema::KIND, identity: { "vty" => vty[:name] }, scope: { "syntax_profile" => "comware7" },
          before: before, after: after, action: :replace, phase: :activate, risk: risk)
      end
      require!(operations.any?, "resolved_vty_authentication_deviation")
      ids = operations.map(&:id)
      steps = operations.flat_map { |operation| @renderer.render(operation, verified_aaa_operation_ids: ids) }
      checks = [ finding, *related ].to_h do |item|
        [ item.id, { status: :planned, reason: nil, operation_ids: ids, details: { preserved_management_method_chain: true,
          explicit_vty_protocol_pair: true, temporary_protocol_rebind: operations.any? { |operation| VtyAuthenticationSchema.temporary_rebind?(operation.before) }, verification_scope: :configured_inventory_and_external_management_approval } } ]
      end
      Result.new(operations: operations.freeze, steps: steps.freeze, checks: CtxParser::Immutable.copy(checks))
    rescue Blocked => error
      checks = [ finding, *related ].to_h { |item| [ item.id, { status: :blocked, reason: error.reason, requirements: error.requirements } ] }
      Result.new(operations: [].freeze, steps: [].freeze, checks: CtxParser::Immutable.copy(checks))
    rescue CommandRenderer::UnsupportedOperation, ArgumentError
      checks = [ finding, *related ].to_h { |item| [ item.id, { status: :blocked, reason: :unsupported_setting } ] }
      Result.new(operations: [].freeze, steps: [].freeze, checks: CtxParser::Immutable.copy(checks))
    end

    def require!(condition, requirement)
      raise Blocked.new(:authentication_chain_evidence_required, requirements: [ requirement ]) unless condition
    end
  end
end

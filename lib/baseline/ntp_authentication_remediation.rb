# frozen_string_literal: true

require_relative "ntp_remediation"

module Baseline
  # 全局开关与关联变更原子出图；完整投影通过前不暴露部分命令。
  class NtpAuthenticationRemediation
    Result = Data.define(:operations, :steps, :checks)
    Blocked = TargetRemediation::Blocked

    def initialize(policy:, renderer:)
      @policy, @renderer = policy, renderer
    end

    def call(audit)
      auth = audit.findings.find { |finding| finding.id == "ntp.authentication" }
      return unless auth && @renderer.class::NTP_AUTHENTICATION_COMMANDS.any? && [ :fail, :unknown ].include?(auth.status) && [ true, false ].include?(auth.expected)
      ids = NtpRemediation::IDS + (@renderer.source_requires_associations?("ntp.source") ? [ "ntp.source" ] : [])
      candidates = audit.findings.select { |finding| ids.include?(finding.id) && [ :fail, :unknown ].include?(finding.status) && !finding.expected.nil? }
      applicable = audit.findings.reject { |finding| finding.status == :not_applicable }
      targets = applicable.find { |finding| finding.id == "ntp.associations" } || applicable.find { |finding| finding.id == "ntp.servers" }
      related = targets&.expected.is_a?(Array) ? candidates : []
      build(audit, auth, related)
    end

    private

    def build(audit, auth, related)
      evidence = audit.configuration
      raise Blocked, :input_incomplete unless evidence.complete?
      unless evidence.fact_known?("ntp.authentication") && [ true, false ].include?(evidence.fact("ntp.authentication"))
        raise Blocked.new(:ntp_authentication_state_required, requirements: [ "known_ntp_authentication_state" ])
      end
      unless evidence.fact_known?("ntp.associations") && evidence.fact_known?("ntp.authentication_consumers_complete") && evidence.fact("ntp.authentication_consumers_complete") == true
        raise Blocked.new(:ntp_authentication_consumers_required, requirements: [ "resolved_ntp_authentication_consumers" ])
      end
      approval = @policy.rules.find { |rule| rule.id == auth.id }
      unless approval.remediation["ntp_peer_key_compatibility_verified"] == true
        raise Blocked.new(:ntp_authentication_dependency, requirements: [ "ntp_peer_key_compatibility_verified" ])
      end
      risk = [ auth, *related ].any? { |finding| finding.severity == "critical" } ? "critical" : "high"
      transition = ConfigurationOperation.new(kind: "ntp.authentication", identity: {}, scope: {}, before: evidence.fact("ntp.authentication"),
        after: auth.expected, action: :set, phase: auth.expected && !@renderer.authentication_precedes_associations? ? :activate : :prepare, risk: risk)
      target_result = NtpRemediation.new(policy: @policy).call(related.first, audit, authentication_transition: transition) if related.any?
      projected = target_result ? target_result.projected : evidence.fact("ntp.associations")
      verified = auth.expected ? verify_material!(projected, evidence) : []
      operations = auth.expected ? (target_result&.operations || []) + [ transition ] : [ transition ] + (target_result&.operations || [])
      if auth.expected && @renderer.authentication_precedes_associations?
        if projected.any? || evidence.fact("ntp.associations").any?
          profiles = evidence.platform == "h3c" ? %w[comware_legacy comware7] : [ "vrp_s_series" ]
          unless profiles.include?(approval.remediation["syntax_profile"])
            raise Blocked.new(:ntp_authentication_syntax_required, requirements: [ "native_ntp_syntax_profile" ])
          end
        end
        operations = recreate_associations(evidence.fact("ntp.associations"), projected, transition, approval)
      end
      context = { verified_ntp_authentication_operation_ids: [ transition.id ],
        verified_ntp_key_ids: (verified + (target_result&.details&.fetch(:verified_ntp_key_ids, []) || [])).uniq }
      context[:ntp_syntax_profile] = approval.remediation["syntax_profile"] if @renderer.authentication_precedes_associations?
      context[:verified_ntp_operation_ids] = target_result.details[:verified_ntp_operation_ids] if target_result&.details&.key?(:verified_ntp_operation_ids)
      steps = operations.flat_map { |operation| @renderer.render(operation, **context) }
      checks = { auth.id => { status: :planned, reason: nil, operation_ids: operations.map(&:id),
        details: { projected_associations: projected.size, verified_key_ids: verified,
          temporary_association_withdrawal: auth.expected && @renderer.authentication_precedes_associations? && evidence.fact("ntp.associations").any?,
          verification_scope: :configured_inventory_and_external_peer_approval } } }
      related.each do |finding|
        checks[finding.id] = { status: :planned, reason: nil, operation_ids: operations.map(&:id), details: target_result.details }
      end
      Result.new(operations: operations.freeze, steps: steps.freeze, checks: CtxParser::Immutable.copy(checks))
    rescue Blocked => error
      blocked(auth, related, error.reason, error.requirements)
    rescue CommandRenderer::UnsupportedOperation
      blocked(auth, related, :unsupported_setting, [])
    rescue ArgumentError
      blocked(auth, related, :invalid_command_parameter, [])
    end

    # 必须先移除既有基本关联，再开启认证并重建全部最终关联；禁止把重发当成重新配置。
    def recreate_associations(current, projected, transition, approval)
      if current.any? && approval.remediation["ntp_association_recreation_approved"] != true
        raise Blocked.new(:ntp_authentication_recreation_required, requirements: [ "ntp_association_recreation_approved" ])
      end
      removals = current.map do |object|
        ConfigurationOperation.new(kind: "ntp.association", identity: object["identity"], scope: object["scope"],
          before: object["attributes"], after: nil, action: :remove, phase: :prepare, risk: transition.risk)
      end
      additions = projected.map do |object|
        ConfigurationOperation.new(kind: "ntp.association", identity: object["identity"], scope: object["scope"],
          before: nil, after: object["attributes"], action: :add, phase: :create, risk: transition.risk)
      end
      removals + [ transition ] + additions
    end

    # 开启认证前核对全部投影关联，包括不在端点受管范围内但受全局开关影响的对象。
    def verify_material!(projected, evidence)
      if projected.any? { |object| !object["attributes"].key?("key_id") }
        raise Blocked.new(:ntp_authentication_dependency, requirements: [ "approved_ntp_key_references" ])
      end
      return [] if projected.empty?
      unless evidence.fact_known?("ntp.key_slots")
        raise Blocked.new(:ntp_authentication_dependency, requirements: [ "resolved_ntp_key_inventory" ])
      end
      by_id = evidence.fact("ntp.key_slots").to_h { |slot| [ slot[:key_id], slot ] }
      ids = projected.map { |object| object["attributes"].fetch("key_id") }.uniq.sort
      ids.each do |key_id|
        slot = by_id[key_id]
        unless slot && slot[:present] == true && slot[:complete] && (slot[:trust_required] == false || slot[:trusted] == true)
          requirement = slot&.fetch(:trust_required, true) == false ? "known_ntp_key_material" : "known_trusted_ntp_key"
          raise Blocked.new(:ntp_authentication_dependency, requirements: [ "#{requirement}:#{key_id}" ])
        end
      end
      ids
    end

    def blocked(auth, related, reason, requirements)
      checks = [ auth, *related ].to_h { |finding| [ finding.id, { status: :blocked, reason: reason, requirements: requirements } ] }
      Result.new(operations: [].freeze, steps: [].freeze, checks: CtxParser::Immutable.copy(checks))
    end
  end
end

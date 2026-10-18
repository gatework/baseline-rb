# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "target_remediation"

module Baseline
  # 通过额外全局过滤收紧所有主体，不重写含秘密的用户或团体字声明。
  class SnmpAccessRemediation
    IDS = %w[snmp.acl_bound snmp.acl_restricted snmp.sources].freeze
    Result = Data.define(:operations, :details)

    # 与审计共用策略及输入标识占用证据。
    def initialize(policy:, reserved_identifiers: nil)
      @policy, @reserved_identifiers = policy, reserved_identifiers
    end

    # 新过滤取现有全局许可与批准上限的交集，各主体原有 ACL 保持原样。
    def call(_finding, audit)
      applicable = audit.findings.select { |item| IDS.include?(item.id) && item.status != :not_applicable }
      limits = applicable.find { |item| item.id == "snmp.sources" }&.expected
      block!(:approved_access_limits_required, requirements: [ "snmp.sources" ]) unless limits.is_a?(Array)
      block!(:access_policy_unresolved) if applicable.any? { |item| item.expected.nil? }
      block!(:policy_conflict) if applicable.any? { |item| item.id != "snmp.sources" && item.expected != true }
      disabled = audit.findings.any? { |item| item.id == "snmp.enabled" && item.status != :not_applicable && item.expected == false }
      block!(:policy_conflict) if disabled
      evidence = audit.configuration
      block!(:snmp_service_dependency, requirements: [ "snmp.enabled" ]) unless evidence.fact_known?("snmp.enabled") && evidence.fact("snmp.enabled") == true
      global, endpoints = evidence.fact("snmp.global_access"), evidence.fact("snmp.access_endpoints")
      unless evidence.fact_known?("snmp.global_access") && global.is_a?(Hash) && global[:complete] &&
          evidence.fact_known?("snmp.access_endpoints") && endpoints.is_a?(Array) && endpoints.any? && endpoints.all? { |entry| entry[:complete] }
        block!(:access_endpoint_unresolved)
      end
      rules = @policy.rules.select { |rule| applicable.any? { |item| item.id == rule.id } }
      supported = global[:supported] || rules.any? { |rule| rule.remediation["global_acl_supported"] == true }
      block!(:snmp_global_acl_support_required, requirements: [ "global_acl_supported" ]) unless supported
      targets = rules.flat_map { |rule| rule.remediation.fetch("access_targets", []) }.uniq
      block!(:approved_acl_identity_required, requirements: [ "access_targets.acl" ]) if targets.empty?
      block!(:policy_conflict) unless targets.one?
      AccessApproval.validate!(targets, domain: :snmp)
      target = targets.first
      before = global.fetch(:sources)
      if target.key?("sources")
        block!(:policy_conflict) unless Acl.networks_within?(target["sources"], limits)
        block!(:access_target_expands_existing) unless Acl.networks_within?(target["sources"], before)
        desired = Acl.cidrs_from_ranges(target["sources"].map { |source| Acl.ipv4_range(source) })
      else
        block!(:approved_access_targets_required, requirements: [ "access_targets.sources" ]) if endpoints.any? { |entry| !entry[:bound] }
        desired = Acl.intersect_networks(before, limits)
      end
      projected = endpoints.map { |entry| entry.merge(sources: Acl.intersect_networks(entry[:sources], desired), bound: true) }
      if !target.key?("sources") && endpoints.zip(projected).any? { |old, current| current[:sources].empty? && old[:sources].any? }
        block!(:access_intersection_empty)
      end
      if applicable.any? { |item| item.id == "snmp.acl_restricted" } && projected.any? { |entry| entry[:sources] == [ "0.0.0.0/0" ] }
        block!(:approved_access_targets_required)
      end
      block!(:acl_reference_evidence_required) unless @reserved_identifiers.is_a?(Array) && evidence.fact_known?("acl.identifiers")
      acl = target.fetch("acl")
      occupied = @reserved_identifiers + evidence.fact("acl.identifiers")
      block!(:acl_identity_in_use) if occupied.any? { |name| name.casecmp?(acl) }
      risk = applicable.any? { |item| item.severity == "critical" } ? "critical" : "high"
      operations = [ ConfigurationOperation.new(kind: "access.acl", identity: { "name" => acl }, before: nil,
        after: { "sources" => desired }, action: :add, phase: :create, risk: risk),
        ConfigurationOperation.new(kind: "snmp.binding", identity: { "name" => "snmp.global" }, before: global[:acl] ? { "acl" => global[:acl] } : {},
          after: { "acl" => acl }, action: :replace, phase: :update, risk: risk) ]
      Result.new(operations: operations, details: { global_before: before, global_after: desired,
        endpoints: endpoints.zip(projected).map { |old, current| { endpoint: old[:name], before: old[:sources], after: current[:sources] } } })
    end

    private

    # 只返回稳定原因，秘密主体标识不进入异常文本。
    def block!(reason, requirements: []) = raise TargetRemediation::Blocked.new(reason, requirements: requirements)
  end
end

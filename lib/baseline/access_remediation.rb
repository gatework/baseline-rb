# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "target_remediation"

module Baseline
  # 在端点有效来源与批准上限之间构造专用 ACL，不改写已有共享对象。
  class AccessRemediation
    IDS = %w[management.acl_bound management.acl_restricted management.sources].freeze
    Result = Data.define(:operations, :details)

    # 使用同一审计所绑定的批准参数。
    def initialize(policy:)
      @policy = policy
    end

    # 所有范围先通过检查，才把创建及绑定操作一起交给呈现器。
    def call(_finding, audit)
      applicable = audit.findings.select { |item| IDS.include?(item.id) && item.status != :not_applicable }
      limit = applicable.find { |item| item.id == "management.sources" }
      block!(:approved_access_limits_required) unless limit&.expected.is_a?(Array)
      block!(:access_policy_unresolved) if applicable.any? { |item| item.expected.nil? }
      block!(:policy_conflict) if applicable.any? { |item| item.id != "management.sources" && item.expected != true }
      evidence = audit.configuration
      endpoints = evidence.fact("management.access_endpoints")
      unless evidence.fact_known?("management.access_endpoints") && endpoints.is_a?(Array) && endpoints.any? && endpoints.all? { |entry| entry[:complete] }
        block!(:access_endpoint_unresolved)
      end
      grouped = endpoints.group_by { |entry| entry[:name] }
      ranges = grouped.keys.map { |name| AccessApproval.range(name) }
      block!(:access_endpoint_unresolved) if ranges.any?(&:nil?) || ranges.sort.each_cons(2).any? { |left, right| left.last >= right.first }
      targets = approved_targets(applicable)
      block!(:access_endpoint_unresolved) unless (targets.keys - grouped.keys).empty?
      block!(:access_endpoint_unresolved) unless evidence.fact_known?("acl.reserved_numeric_ids") && evidence.fact_known?("acl.identifiers")
      occupied = (evidence.fact("acl.reserved_numeric_ids") + evidence.fact("acl.identifiers")).map { |value| /\A\d+\z/.match?(value) ? value.to_i.to_s : value }
      operations, details = [], []
      grouped.each do |name, entries|
        target = targets[name]
        restricted = applicable.find { |item| item.id == "management.acl_restricted" }
        retained = entries.all? { |entry| entry[:bound] && Acl.networks_within?(entry[:sources], limit.expected) && (!restricted || entry[:sources] != [ "0.0.0.0/0" ]) }
        next if retained && !target&.key?("sources")
        desired = desired_sources(entries, target, limit.expected)
        block!(:approved_access_targets_required) if restricted && desired == [ "0.0.0.0/0" ]
        next if entries.all? { |entry| entry[:bound] && entry[:sources] == desired }
        block!(:access_intersection_empty) if desired.empty? && (!target&.key?("sources") || !target["sources"].empty?)
        block!(:approved_acl_identity_required) unless target
        acl = target.fetch("acl")
        block!(:acl_identity_in_use) if occupied.any? { |value| value.casecmp?(acl) }
        old = evidence.fact("ssh.vty").find { |entry| entry[:name] == name }&.fetch(:acl, nil)
        risk = applicable.any? { |item| item.severity == "critical" } ? "critical" : "high"
        operations << ConfigurationOperation.new(kind: "access.acl", identity: { "name" => acl }, before: nil,
          after: { "sources" => desired }, action: :add, phase: :create, risk: risk)
        operations << ConfigurationOperation.new(kind: "access.binding", identity: { "name" => name }, before: old ? { "acl" => old } : {},
          after: { "acl" => acl }, action: :replace, phase: :update, risk: risk)
        details << { endpoint: name, before: entries.map { |entry| { transport: entry[:transport], sources: entry[:sources] } },
          after: desired, initial_binding: entries.any? { |entry| !entry[:bound] }, acl: acl }
      end
      block!(:resource_unresolved) if operations.empty?
      Result.new(operations: operations, details: { endpoints: details })
    end

    private

    # 基本 ACL 只有一组允许来源；目标不能合并原本不同的协议许可而扩大其中任一项。
    def desired_sources(entries, target, limits)
      if target&.key?("sources")
        requested = target.fetch("sources")
        block!(:policy_conflict) unless Acl.networks_within?(requested, limits)
        if entries.any? { |entry| entry[:bound] && !Acl.networks_within?(requested, entry[:sources]) }
          block!(:access_target_expands_existing)
        end
        return Acl.cidrs_from_ranges(requested.map { |source| Acl.ipv4_range(source) })
      end
      block!(:approved_access_targets_required) if entries.any? { |entry| !entry[:bound] }
      desired = entries.map { |entry| Acl.intersect_networks(entry[:sources], limits) }.uniq
      block!(:access_protocol_dependency) unless desired.one?
      desired.first
    end

    # 跨规则重复批准必须一致；来源上下限与 ACL 标识不能由声明顺序决定。
    def approved_targets(applicable)
      selected = @policy.rules.select { |rule| applicable.any? { |item| item.id == rule.id } }
      targets = {}
      selected.flat_map { |rule| rule.remediation.fetch("access_targets", []) }.each do |target|
        name = target.fetch("endpoint")
        block!(:policy_conflict) if targets.key?(name) && targets[name] != target
        targets[name] = target
      end
      AccessApproval.validate!(targets.values)
      targets
    end

    # 稳定原因不携带配置文本或秘密。
    def block!(reason) = raise TargetRemediation::Blocked, reason
  end
end

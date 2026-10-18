# frozen_string_literal: true

require_relative "configuration_operation"

module Baseline
  # 地址、数量和对象规则共同规划目标集合，领域子类保留各自身份与协议含义。
  class TargetRemediation
    Result = Data.define(:operations, :details)
    class Blocked < StandardError
      attr_reader :reason, :requirements
      # 受阻原因使用稳定代码，不携带配置文本。
      def initialize(reason, requirements: [])
        @reason = reason
        @requirements = CtxParser::Immutable.copy(requirements)
        super(reason.to_s)
      end
    end

    # 只绑定冻结策略，不保存设备或本次解析状态。
    def initialize(policy:)
      @policy = policy
    end

    # 将同一领域全部有效约束投影到最终对象集合，再生成最小操作集。
    def call(finding, audit)
      unless audit.configuration.fact_known?(structured_id)
        raise Blocked, :resource_unresolved
      end
      current = audit.configuration.fact(structured_id)
      applicable = audit.findings.select { |item| self.class::IDS.include?(item.id) && item.status != :not_applicable }
      structured = applicable.find { |item| item.id == structured_id }
      legacy = applicable.find { |item| item.id == servers_id }
      effective = structured || legacy
      raise Blocked, :approved_targets_required unless effective && effective.expected
      raise Blocked, :structured_policy_unresolved unless %i[pass fail].include?(effective.status)

      @legacy_mode = effective.id != structured_id
      if effective.id == structured_id
        managed = @policy.rules.find { |rule| rule.id == effective.id }.managed_scopes
        raise Blocked, :approved_scope_required unless managed
        targets = effective.expected
      else
        managed = [ { "vrf" => "default" } ]
        raise Blocked, :approved_scope_required unless countable_objects(current).all? { |object| managed.include?(object["scope"]) }
        targets = effective.expected.map do |address|
          { "identity" => legacy_identity(address), "scope" => { "vrf" => "default" }, "attributes" => {} }
        end
      end
      ResourceSchema.validate_expected!(self.class::KIND, targets)
      current_by_key = current.to_h { |object| [ key(object), object ] }
      desired = targets.map do |object|
        attributes = current_by_key[key(object)]&.fetch("attributes", {}) || {}
        object.merge("attributes" => attributes.merge(object.fetch("attributes", {})))
      end
      projected = current.reject { |object| managed_object?(object, managed) } + desired
      check_constraints!(applicable, projected)
      risk = applicable.max_by { |item| %w[low medium high critical].index(item.severity) }.severity
      operations = desired.filter_map do |object|
        before = current_by_key[key(object)]
        if before.nil?
          operation(object, :add, nil, object["attributes"], risk)
        elsif object["attributes"] != before.fetch("attributes", {})
          operation(object, :replace, before.fetch("attributes", {}), object["attributes"], risk)
        end
      end
      wanted = desired.to_h { |object| [ key(object), true ] }
      current.each do |object|
        next unless managed_object?(object, managed) && !wanted.key?(key(object))
        operations << operation(object, :remove, object.fetch("attributes", {}), nil, risk)
      end
      raise Blocked, :resource_unresolved if operations.empty?
      operations, details = order_for_capacity(operations, current, projected, applicable)
      ordered = operations.sort_by { |item| { prepare: -1, create: 0, update: 1, remove: 2 }.fetch(item.phase) }.freeze
      Result.new(operations: ordered, details: CtxParser::Immutable.copy(details))
    end

    private

    # 每个领域保留自己的对象身份及旧地址规则语义。
    def structured_id = self.class::IDS.last
    def servers_id = self.class::IDS[1]
    def minimum_id = self.class::IDS.first
    def legacy_identity(address) = { "address" => address }
    def countable_objects(objects) = objects
    def managed_object?(object, managed) = managed.include?(object["scope"])

    # 容量是调用方提供的设备证据，不从已有目标数或厂商名称猜测。
    def order_for_capacity(operations, current, projected, findings)
      ids = findings.map(&:id)
      options = @policy.rules.select { |rule| ids.include?(rule.id) }.map(&:remediation)
      maxima = options.filter_map { |item| item["maximum_targets"] }.uniq
      orders = options.filter_map { |item| item["order"] }.uniq
      raise Blocked, :policy_conflict if maxima.size > 1 || orders.size > 1
      maximum = maxima.first
      additions = operations.count { |operation| operation.action == :add }
      removals = operations.count { |operation| operation.action == :remove }
      if additions.positive? && maximum.nil? && (current.empty? || projected.size > current.size)
        raise Blocked, :capacity_confirmation_required
      end
      raise Blocked, :capacity_evidence_conflict if maximum && current.size > maximum
      raise Blocked, :capacity_exceeded if maximum && projected.size > maximum
      limit = maximum || current.size
      first = orders.first == "remove_before_add" ? removals : [ current.size + additions - limit, 0 ].max
      raise Blocked, :capacity_exceeded if first > removals
      details = { initial_targets: current.size, projected_targets: projected.size, additions: additions, early_removals: first,
        order: orders.first || "add_before_remove" }
      details.merge!(maximum_targets: maximum, capacity_source: :policy) if maximum
      details.merge!(capacity_lower_bound: current.size, capacity_source: :observed_occupancy) if maximum.nil? && additions.positive?
      details[:effective_order] = first.positive? ? "remove_to_fit_then_add" : "add_before_remove"
      ordered = operations.map do |operation|
        next operation unless operation.action == :remove && first.positive?
        first -= 1
        risk = %w[high critical].include?(operation.risk) ? operation.risk : "high"
        ConfigurationOperation.new(**operation.to_h.except(:id).merge(phase: :prepare, risk: risk))
      end
      [ ordered, details ]
    end

    # 已通过指标也约束修正后的集合；最低数量不能由重复地址满足。
    def check_constraints!(findings, projected)
      addresses = countable_objects(projected).map { |object| object["identity"]["address"] || object.fetch("attributes", {})["address"] }.uniq
      raise Blocked, :resource_unresolved if addresses.include?(nil)
      findings.each do |finding|
        next if finding.expected.nil?
        if finding.id == servers_id && addresses.sort != finding.expected.sort ||
            finding.id == minimum_id && addresses.size < finding.expected
          raise Blocked, :policy_conflict
        end
      end
    end

    # 身份和作用域不含可修改属性，支持保留正确配置与只替换错误字段。
    def key(object) = [ object["scope"], object["identity"] ]

    # 创建独立不可变操作，不在编译中修改解析资源或策略。
    def operation(object, action, before, after, risk)
      ConfigurationOperation.new(kind: self.class::KIND, identity: object["identity"], scope: object["scope"], before: before,
        after: after, action: action, phase: { add: :create, replace: :update, remove: :remove }.fetch(action), risk: risk)
    end
  end
end

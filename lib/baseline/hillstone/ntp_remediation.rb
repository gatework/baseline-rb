# frozen_string_literal: true

module Baseline
  module Hillstone
    # 对象审计保留路由作用域；原生操作按全局地址归并并核验全部受影响作用域。
    module NtpRemediation
      private

      def native_target_capacity = @stoneos ? 3 : super

      def attributes_for_target(object, current_by_key)
        return super unless @stoneos
        previous = @stoneos_objects[object["identity"]]
        attributes = previous&.fetch("attributes", {}) || {}
        @stoneos_source&.expected ? attributes.merge("source" => @stoneos_source.expected) : attributes
      end

      def applicable_findings(audit)
        findings = super
        @stoneos && @stoneos_source&.expected ? findings + [ @stoneos_source ] : findings
      end

      def validate_native_address_identities!(current, desired)
        return super unless @stoneos
        observed = current.group_by { |object| object["identity"] }
        if observed.values.any? { |values| values.size > 1 } || desired.map { |object| object["identity"] }.uniq.size != desired.size
          raise TargetRemediation::Blocked, :native_resource_identity_unresolved
        end
        desired.each do |object|
          previous = observed[object["identity"]]&.first
          if previous && previous["scope"] != object["scope"] && !@stoneos_scopes&.include?(previous["scope"])
            raise TargetRemediation::Blocked, :approved_scope_required
          end
        end
      end

      # 同地址的跨路由域增删合为一个完整替换，省略字段仍保留原生服务器的已知值。
      def normalize_operations(operations)
        return super unless @stoneos
        operations.group_by(&:identity).map do |identity, group|
          old = group.find { |operation| operation.before }
          fresh = group.find { |operation| operation.after }
          action = old && fresh ? :replace : fresh ? :add : :remove
          ConfigurationOperation.new(kind: "ntp.server", identity: identity, scope: {},
            before: old && old.before.merge("vrf" => old.scope.fetch("vrf"), "vrf_explicit" => old.scope["vrf"] != "default" || old.scope["vrf_mode"] == "named"),
            after: fresh && fresh.after.merge("vrf" => fresh.scope.fetch("vrf"), "vrf_explicit" => fresh.scope["vrf"] != "default" || fresh.scope["vrf_mode"] == "named"),
            action: action, phase: { add: :create, replace: :update, remove: :remove }.fetch(action), risk: group.first.risk)
        end
      end

      # 全局来源策略约束最终所有服务器，不能修改对象后破坏原本通过的来源指标。
      def check_constraints!(findings, projected)
        super
        return unless @stoneos && @stoneos_source&.expected
        unless projected.any? && projected.all? { |object| object["attributes"]["source"] == @stoneos_source.expected }
          raise TargetRemediation::Blocked, :policy_conflict
        end
      end

      def order_for_capacity(operations, current, projected, findings)
        ordered, details = super
        return [ ordered, details ] unless @stoneos
        raise TargetRemediation::Blocked, :capacity_evidence_conflict if current.size > 3
        raise TargetRemediation::Blocked, :capacity_exceeded if projected.size > 3
        needed = [ current.size + ordered.count { |operation| operation.action == :add } - ordered.count { |operation| operation.phase == :prepare } - 3, 0 ].max
        candidates = ordered.select { |operation| operation.action == :remove && operation.phase != :prepare }.take(needed)
        raise TargetRemediation::Blocked, :capacity_exceeded if candidates.size < needed
        replacements = candidates.to_h do |operation|
          risk = operation.risk == "critical" ? "critical" : "high"
          [ operation.id, ConfigurationOperation.new(**operation.to_h.except(:id).merge(phase: :prepare, risk: risk)) ]
        end
        details = details.merge(native_capacity: 3, early_removals: details[:early_removals] + replacements.size)
        details[:effective_order] = "remove_to_fit_then_add" if replacements.any?
        [ ordered.map { |operation| replacements.fetch(operation.id, operation) }, details ]
      end
    end
  end
end

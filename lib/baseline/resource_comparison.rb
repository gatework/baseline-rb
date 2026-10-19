# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 比较受管对象身份和明确批准属性；其他作用域及未指定属性不产生删除建议。
  module ResourceComparison
    # 返回评估状态和结构化差异，损坏外部事实不能冒充已知空集。
    def self.call(kind:, actual:, expected:, managed_scopes:)
      ResourceSchema.validate_expected!(kind, actual)
      ResourceSchema.validate_expected!(kind, expected)
      expected = ResourceSchema.normalize_objects(kind, expected)
      actual = ResourceSchema.normalize_objects(kind, actual)
      actual_by_key = actual.to_h { |object| [ [ object["scope"], object["identity"] ], object ] }
      expected_keys = expected.to_h { |object| [ [ object["scope"], object["identity"] ], true ] }
      managed = (managed_scopes || []).to_h { |scope| [ scope, true ] }
      missing, changed, unresolved, bindings = [], [], [], []
      expected.each do |object|
        observed = actual_by_key[[ object["scope"], object["identity"] ]]
        if observed.nil?
          missing << object
        else
          desired = object.fetch("attributes", {})
          attributes = observed["scope"].merge(observed.fetch("attributes", {})).merge(observed["identity"])
          unknown = desired.keys.reject { |key| attributes.key?(key) }
          unresolved << { identity: object["identity"], scope: object["scope"], fields: unknown } if unknown.any?
          if desired.any? { |key, value| attributes.key?(key) && attributes[key] != value }
            changed << { identity: object["identity"], scope: object["scope"], expected: desired, actual: attributes.slice(*desired.keys) }
          end
          if object.key?("bindings")
            if observed.key?("bindings")
              difference = ResourceBindings.compare(observed["bindings"], object["bindings"])
              unresolved << { identity: object["identity"], scope: object["scope"], fields: [ "bindings.selected" ] } if difference[:unresolved].any?
              if difference.except(:unresolved).values.any?(&:any?)
                bindings << { identity: object["identity"], scope: object["scope"], **difference.except(:unresolved) }
              end
            else
              unresolved << { identity: object["identity"], scope: object["scope"], fields: [ "bindings" ] }
            end
          end
        end
      end
      unexpected = actual.select do |object|
        managed.key?(object["scope"]) && !expected_keys.key?([ object["scope"], object["identity"] ])
      end
      details = { missing: missing, unexpected: unexpected, changed: changed }
      details[:binding_differences] = bindings if bindings.any?
      passed = details.values.all?(&:empty?)
      details[:verification_scope] = expected.any? { |object| object.key?("bindings") } ? :objects_and_requested_bindings : :objects_only
      if passed && unresolved.any?
        reason = unresolved.any? { |entry| entry[:fields].any? { |field| field.start_with?("bindings") } } ? :resource_binding_unresolved : :resource_attribute_unresolved
        return [ :unknown, reason, { unresolved: unresolved, verification_scope: details[:verification_scope] } ]
      end
      details[:unresolved] = unresolved if unresolved.any?
      [ passed ? :pass : :fail, passed ? nil : :deviation, details ]
    rescue ArgumentError
      [ :unknown, :fact_type_mismatch ]
    end
  end
end

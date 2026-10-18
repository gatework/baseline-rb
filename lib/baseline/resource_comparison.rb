# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # 比较受管对象身份和明确批准属性；其他作用域及未指定属性不产生删除建议。
  module ResourceComparison
    # 返回评估状态和结构化差异，损坏外部事实不能冒充已知空集。
    def self.call(kind:, actual:, expected:, managed_scopes:)
      ResourceSchema.validate_expected!(kind, actual)
      actual = ResourceSchema.normalize_objects(kind, actual)
      actual_by_key = actual.to_h { |object| [ [ object["scope"], object["identity"] ], object ] }
      expected_keys = expected.to_h { |object| [ [ object["scope"], object["identity"] ], true ] }
      managed = (managed_scopes || []).to_h { |scope| [ scope, true ] }
      missing, changed, unresolved = [], [], []
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
        end
      end
      unexpected = actual.select do |object|
        managed.key?(object["scope"]) && !expected_keys.key?([ object["scope"], object["identity"] ])
      end
      details = { missing: missing, unexpected: unexpected, changed: changed }
      passed = details.values.all?(&:empty?)
      return [ :unknown, :resource_attribute_unresolved, { unresolved: unresolved } ] if passed && unresolved.any?
      details[:unresolved] = unresolved if unresolved.any?
      [ passed ? :pass : :fail, passed ? nil : :deviation, details ]
    rescue ArgumentError
      [ :unknown, :fact_type_mismatch ]
    end
  end
end

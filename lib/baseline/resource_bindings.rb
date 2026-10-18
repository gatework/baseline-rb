# frozen_string_literal: true

module Baseline
  # 绑定身份使用领域字段，不接受任意 CLI 路径、命令或秘密参数。
  module ResourceBindings
    IDENTITY = %w[kind domain role position].freeze

    # 当前 aaa.domain 适用于已建模的 HWTACACS 域引用；其他类型必须显式扩展。
    def self.validate!(kind, bindings)
      valid = kind == "tacacs.endpoint" && bindings.is_a?(Array) && bindings.all? do |binding|
        binding.is_a?(Hash) && (binding.keys - [ *IDENTITY, "selected" ]).empty? && (IDENTITY - binding.keys).empty? &&
          binding["kind"] == "aaa.domain" && ResourceSchema.token?(binding["domain"]) &&
          %w[authentication authorization accounting].include?(binding["role"]) && %w[primary fallback].include?(binding["position"]) &&
          (!binding.key?("selected") || [ true, false ].include?(binding["selected"]))
      end
      raise ArgumentError, "Invalid resource bindings" unless valid
      identities = normalize(bindings).map { |binding| key(binding) }
      raise ArgumentError, "Duplicate resource binding" unless identities.uniq.size == identities.size
      true
    end

    # 已支持的 Comware/VRP 域名不区分大小写；省略 selected 不等同于 false。
    def self.normalize(bindings)
      bindings.map { |binding| binding.merge("domain" => binding.fetch("domain").downcase) }.sort_by { |binding| key(binding) }
    end

    # 绑定标识与可选选择状态分离，不能把字段更新误作全对象删除。
    def self.key(binding) = binding.values_at(*IDENTITY)

    # 数组是明确的期望引用集合；未声明 selected 的对象不要求改变域选择。
    def self.compare(actual, expected)
      observed = actual.to_h { |binding| [ key(binding), binding ] }
      desired = expected.to_h { |binding| [ key(binding), binding ] }
      changed, unresolved = [], []
      expected.each do |binding|
        current = observed[key(binding)]
        next unless current && binding.key?("selected")
        if !current.key?("selected")
          unresolved << binding
        elsif current["selected"] != binding["selected"]
          changed << { identity: binding.slice(*IDENTITY), expected: binding["selected"], actual: current["selected"] }
        end
      end
      { missing: expected.reject { |binding| observed.key?(key(binding)) }, unexpected: actual.reject { |binding| desired.key?(key(binding)) },
        changed: changed, unresolved: unresolved }
    end
  end
end

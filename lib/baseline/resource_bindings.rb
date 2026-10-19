# frozen_string_literal: true

module Baseline
  # 绑定身份使用领域字段，不接受任意 CLI 路径、命令或秘密参数。
  module ResourceBindings
    IDENTITY = %w[kind domain role position].freeze
    SYSLOG_DEVICE_TYPES = %w[system config userid iptag globalprotect hipmatch correlation].freeze
    SYSLOG_FORWARD_TYPES = %w[traffic threat wildfire url data tunnel auth decryption].freeze

    # 身份字段随引用能力变化；可选日志标志只参与明确要求的字段比较。
    def self.identity_fields(binding)
      case binding["kind"]
      when "syslog.device" then %w[kind log_type match]
      when "syslog.forwarding" then %w[kind forwarding_profile match log_type context] + (binding["context"] == "vsys" ? [ "vsys" ] : []) + %w[rulebase rule]
      else IDENTITY
      end
    end

    def self.predicate_fields(binding) = binding["kind"] == "aaa.domain" ? [ "selected" ] : %w[disabled log_start log_end]

    # 认证域及日志输出链分别校验，禁止跨资源种类借用引用身份。
    def self.validate!(kind, bindings)
      valid = %w[tacacs.endpoint syslog.destination].include?(kind) && bindings.is_a?(Array) && bindings.all? do |binding|
        next false unless binding.is_a?(Hash)
        identity, predicates = identity_fields(binding), predicate_fields(binding)
        shape = (binding.keys - identity - predicates).empty? && (identity - binding.keys).empty? &&
          predicates.all? { |field| !binding.key?(field) || [ true, false ].include?(binding[field]) }
        next false unless shape
        if kind == "tacacs.endpoint"
          binding["kind"] == "aaa.domain" && ResourceSchema.token?(binding["domain"]) &&
            %w[authentication authorization accounting].include?(binding["role"]) && %w[primary fallback].include?(binding["position"])
        elsif binding["kind"] == "syslog.device"
          SYSLOG_DEVICE_TYPES.include?(binding["log_type"]) && ResourceSchema.name?(binding["match"]) &&
            (binding.keys - identity).empty?
        elsif binding["kind"] == "syslog.forwarding"
          SYSLOG_FORWARD_TYPES.include?(binding["log_type"]) && %w[security default-security-rules].include?(binding["rulebase"]) &&
            %w[local vsys].include?(binding["context"]) && %w[forwarding_profile match rule].all? { |field| ResourceSchema.name?(binding[field]) } &&
            (binding["context"] != "vsys" || ResourceSchema.name?(binding["vsys"]))
        else false
        end
      end
      raise ArgumentError, "Invalid resource bindings" unless valid
      identities = normalize(bindings).map { |binding| key(binding) }
      raise ArgumentError, "Duplicate resource binding" unless identities.uniq.size == identities.size
      true
    end

    # 仅认证域名折叠大小写；日志 profile、匹配项和规则保留原名。
    def self.normalize(bindings)
      bindings.map { |binding| binding["kind"] == "aaa.domain" ? binding.merge("domain" => binding.fetch("domain").downcase) : binding.dup }.sort_by { |binding| key(binding) }
    end

    # 绑定标识与可选选择状态分离，不能把字段更新误作全对象删除。
    def self.key(binding) = binding.values_at(*identity_fields(binding))

    # 数组是明确的引用集合；未声明的选择或日志标志不要求改变。
    def self.compare(actual, expected)
      observed = actual.to_h { |binding| [ key(binding), binding ] }
      desired = expected.to_h { |binding| [ key(binding), binding ] }
      changed, unresolved = [], []
      expected.each do |binding|
        current = observed[key(binding)]
        next unless current
        predicate_fields(binding).each do |field|
          next unless binding.key?(field)
          if !current.key?(field)
            unresolved << binding
          elsif current[field] != binding[field]
            change = { identity: binding.slice(*identity_fields(binding)), expected: binding[field], actual: current[field] }
            change[:field] = field unless binding["kind"] == "aaa.domain"
            changed << change
          end
        end
      end
      { missing: expected.reject { |binding| observed.key?(key(binding)) }, unexpected: actual.reject { |binding| desired.key?(key(binding)) },
        changed: changed, unresolved: unresolved }
    end
  end
end

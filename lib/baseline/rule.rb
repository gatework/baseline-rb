# frozen_string_literal: true

require_relative "acl"

require "ctx_parser/immutable"

module Baseline
  # 规则声明事实、比较方式和批准值类型；厂商语法仅由解析器负责。
  class Rule
    # 校验与规则目录共用具名字段，避免从名称或元组位置猜测类型。
    Definition = Data.define(:title, :fact, :operator, :value_type, :allowed_values) do
      # 冻结规则目录条目的事实、比较方式及批准值类型。
      def initialize(title:, fact:, operator:, value_type:, allowed_values: nil)
        super(title: CtxParser::Immutable.copy(title), fact: CtxParser::Immutable.copy(fact), operator: CtxParser::Immutable.copy(operator),
          value_type: CtxParser::Immutable.copy(value_type), allowed_values: CtxParser::Immutable.copy(allowed_values))
      end
    end

    DEFINITIONS = {
      "snmp.enabled" => Definition.new(title: "SNMP 配置", fact: "snmp.enabled", operator: :equals, value_type: :boolean),
      "snmp.versions" => Definition.new(title: "SNMP 允许版本", fact: "snmp.versions", operator: :subset, value_type: :enum_set, allowed_values: %w[v1 v2c v3]),
      "snmp.write_enabled" => Definition.new(title: "SNMP 写权限", fact: "snmp.write_enabled", operator: :equals, value_type: :boolean),
      "snmp.auth_priv" => Definition.new(title: "SNMPv3 认证与加密", fact: "snmp.v3_auth_priv", operator: :equals, value_type: :boolean),
      "snmp.acl_bound" => Definition.new(title: "SNMP 来源 ACL 引用", fact: "snmp.acl.bound", operator: :equals, value_type: :boolean),
      "snmp.acl_restricted" => Definition.new(title: "SNMP 来源 ACL 限制", fact: "snmp.acl.restricted", operator: :equals, value_type: :boolean),
      "snmp.sources" => Definition.new(title: "SNMP 批准来源", fact: "snmp.acl.sources", operator: :networks_within, value_type: :network_set),
      "ntp.minimum_servers" => Definition.new(title: "NTP 服务器数量", fact: "ntp.servers", operator: :count_at_least, value_type: :positive_integer),
      "ntp.servers" => Definition.new(title: "NTP 批准服务器", fact: "ntp.servers", operator: :set_equals, value_type: :string_set),
      "ntp.authentication" => Definition.new(title: "NTP 认证开关", fact: "ntp.authentication", operator: :equals, value_type: :boolean),
      "ntp.source" => Definition.new(title: "NTP 源接口", fact: "ntp.source", operator: :equals, value_type: :string),
      "syslog.minimum_servers" => Definition.new(title: "Syslog 服务器数量", fact: "syslog.servers", operator: :count_at_least, value_type: :positive_integer),
      "syslog.servers" => Definition.new(title: "Syslog 批准服务器", fact: "syslog.servers", operator: :set_equals, value_type: :string_set),
      "syslog.source" => Definition.new(title: "Syslog 源接口", fact: "syslog.source", operator: :equals, value_type: :string),
      "ssh.enabled" => Definition.new(title: "SSH 配置", fact: "ssh.enabled", operator: :equals, value_type: :boolean),
      "ssh.versions" => Definition.new(title: "SSH 允许版本", fact: "ssh.versions", operator: :subset, value_type: :enum_set, allowed_values: %w[1 2]),
      "ssh.vty_ssh_only" => Definition.new(title: "VTY 只允许 SSH", fact: "ssh.vty_ssh_only", operator: :equals, value_type: :boolean),
      "ssh.vty_aaa" => Definition.new(title: "VTY 使用账户认证", fact: "ssh.vty_aaa", operator: :equals, value_type: :boolean),
      "management.acl_bound" => Definition.new(title: "管理来源 ACL 引用", fact: "management.acl.bound", operator: :equals, value_type: :boolean),
      "management.acl_restricted" => Definition.new(title: "管理来源 ACL 限制", fact: "management.acl.restricted", operator: :equals, value_type: :boolean),
      "management.sources" => Definition.new(title: "管理批准来源", fact: "management.acl.sources", operator: :networks_within, value_type: :network_set),
      "services.disabled" => Definition.new(title: "关闭非必要服务", fact: "services", operator: :all_disabled, value_type: :enum_set, allowed_values: %w[telnet http https ftp tftp finger]),
      "credentials.storage" => Definition.new(title: "凭据安全存储", fact: "credentials.storage_safe", operator: :equals, value_type: :boolean),
      "credentials.strength" => Definition.new(title: "可观察口令强度", fact: "credentials.records", operator: :password_strength, value_type: :password_strength),
      "tacacs.minimum_servers" => Definition.new(title: "TACACS 服务器数量", fact: "tacacs.servers", operator: :count_at_least, value_type: :positive_integer),
      "tacacs.servers" => Definition.new(title: "TACACS 批准服务器", fact: "tacacs.servers", operator: :set_equals, value_type: :string_set),
      "tacacs.login" => Definition.new(title: "管理认证引用 TACACS", fact: "tacacs.login", operator: :equals, value_type: :boolean),
      "tacacs.authorization" => Definition.new(title: "管理授权引用 TACACS", fact: "tacacs.authorization", operator: :equals, value_type: :boolean),
      "tacacs.accounting" => Definition.new(title: "管理审计引用 TACACS", fact: "tacacs.accounting", operator: :equals, value_type: :boolean),
      "tacacs.keys" => Definition.new(title: "TACACS 密钥配置", fact: "tacacs.keys_present", operator: :equals, value_type: :boolean)
    }.freeze
    CONTEXT_FIELDS = %w[host model site role vendor].freeze
    # 适用条件采用标量相等或备选值匹配；集合事实不隐含成员比较语义。
    APPLICABILITY_FACTS = DEFINITIONS.values.each_with_object({}) do |definition, facts|
      facts[definition.fact] = definition.value_type if %i[boolean string].include?(definition.value_type)
    end.merge("hostname" => :string, "snmp.community_present" => :boolean, "credentials.present" => :boolean).freeze

    attr_reader :id, :definition, :title, :fact, :operator, :value_type, :allowed_values, :expected, :severity, :applies_to

    # 校验规则定义，并冻结比较契约。
    def initialize(id, options)
      @definition = DEFINITIONS.fetch(id) { raise ArgumentError, "Unknown baseline rule" }
      unless options.is_a?(Hash) && (options.keys - %w[enabled expected severity applies_to]).empty? &&
          [ true, false ].include?(options.fetch("enabled", true)) &&
          %w[low medium high critical].include?(options.fetch("severity", "medium"))
        raise ArgumentError, "Invalid baseline rule options"
      end
      @id = CtxParser::Immutable.copy(id)
      @title, @fact, @operator = definition.title, definition.fact, definition.operator
      @value_type, @allowed_values = definition.value_type, definition.allowed_values
      @expected = CtxParser::Immutable.copy(options["expected"])
      @enabled, @severity = options.fetch("enabled", true), CtxParser::Immutable.copy(options.fetch("severity", "medium"))
      @applies_to = CtxParser::Immutable.copy(options.fetch("applies_to", {}))
      validate_applicability!
      freeze
    end

    # 判断策略规则是否已启用评估。
    def enabled? = @enabled

    # 将 nil 保留为批准值缺失；具体值则按规则目录声明的领域类型校验。
    def validate_expected!(value)
      valid = case value_type
      when :boolean, :string then scalar?(value, value_type)
      when :positive_integer then value.is_a?(Integer) && value.positive?
      when :password_strength
        value.is_a?(Hash) && value.size == 2 && (value.keys - %w[min_classes min_length]).empty? &&
          value["min_length"].is_a?(Integer) && value["min_length"].between?(1, 1024) &&
          value["min_classes"].is_a?(Integer) && value["min_classes"].between?(1, 4)
      when :enum_set then string_set?(value) && !value.empty? && (value - allowed_values).empty?
      when :string_set, :network_set then string_set?(value)
      end
      raise ArgumentError, "Invalid baseline expected value for #{id}" unless valid
      value.each { |network| Acl.address_range(network) } if value_type == :network_set
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} id=#{id} enabled=#{enabled?}>"

    private

    # 拒绝拼错的事实名和空条件，避免将应失败的检查静默排除为不适用。
    def validate_applicability!
      unless applies_to.is_a?(Hash) && (applies_to.keys - CONTEXT_FIELDS - [ "facts" ]).empty?
        raise ArgumentError, "Invalid baseline applicability for #{id}"
      end
      applies_to.each do |key, value|
        if key == "facts"
          unless value.is_a?(Hash) && !value.empty?
            raise ArgumentError, "Invalid baseline applicability facts for #{id}"
          end
          value.each do |name, criterion|
            type = APPLICABILITY_FACTS.fetch(name) { raise ArgumentError, "Unknown baseline applicability fact for #{id}" }
            validate_criterion!(criterion, type)
          end
        else
          validate_criterion!(value, :string)
        end
      end
    end

    # 按声明的值类型校验策略比较操作数。
    def validate_criterion!(criterion, type)
      values = criterion.is_a?(Array) ? criterion : [ criterion ]
      unless !values.empty? && values.all? { |value| scalar?(value, type) }
        raise ArgumentError, "Invalid baseline applicability value for #{id}"
      end
    end

    # 按声明类型校验标量策略值。
    def scalar?(value, type)
      case type
      when :string then value.is_a?(String) && !value.strip.empty?
      when :boolean then [ true, false ].include?(value)
      end
    end

    # 要求策略值为内容有效且不重复的文本数组。
    def string_set?(value)
      value.is_a?(Array) && value.all? { |item| scalar?(item, :string) } && value.uniq == value
    end
  end
end

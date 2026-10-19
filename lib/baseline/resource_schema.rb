# frozen_string_literal: true

require_relative "server_address"
require_relative "resource_bindings"

module Baseline
  # 资源只持有配置生成所需的非秘密属性；未知字段不能进入报告。
  module ResourceSchema
    FACTS = { "syslog.destination" => "syslog.destinations", "ntp.association" => "ntp.associations", "tacacs.endpoint" => "tacacs.endpoints" }.freeze
    SYSLOG_FIELDS = %w[address name protocol port facility severity channel dscp filter source format types certificate_check].freeze
    NTP_FIELDS = %w[address version key_id prefer source minpoll maxpoll burst iburst normal_sync authenticated].freeze
    TACACS_FIELDS = %w[address port source key_present timeout single_connection].freeze
    IDENTITY_FIELDS = %w[address name protocol port types role priority family].freeze
    SCOPE_FIELDS = %w[vrf profile source group vrf_mode].freeze

    # 校验完整资源数据，拒绝控制字符及未声明的配置字段。
    def self.validate!(kind:, identity:, scope:, attributes:, lines:, complete:)
      fields = { "syslog.destination" => SYSLOG_FIELDS, "ntp.association" => NTP_FIELDS, "tacacs.endpoint" => TACACS_FIELDS }[kind]
      valid = fields && identity.is_a?(Hash) && !identity.empty? &&
        (identity.keys - IDENTITY_FIELDS).empty? && scope.is_a?(Hash) && (scope.keys - SCOPE_FIELDS).empty? &&
        attributes.is_a?(Hash) && (attributes.keys - fields).empty? &&
        lines.is_a?(Array) && lines.all? { |line| line.is_a?(Integer) && line.positive? } &&
        [ true, false ].include?(complete)
      raise ArgumentError, "Invalid configuration resource" unless valid
      identity_fields, scope_fields, roles = case kind
      when "syslog.destination" then [ %w[address name protocol port types], %w[vrf profile source vrf_mode], [] ]
      when "ntp.association" then [ %w[address name role], %w[vrf vrf_mode], %w[server peer] ]
      when "tacacs.endpoint" then [ %w[address name role priority family], %w[vrf profile group], %w[authentication authorization accounting all] ]
      end
      valid_identity = (identity.keys - identity_fields).empty? && (scope.keys - scope_fields).empty? &&
        (identity.key?("address") ^ identity.key?("name")) &&
        (!identity.key?("role") || roles.include?(identity["role"])) &&
        (kind != "ntp.association" || identity.key?("name") || identity.key?("role")) &&
        (!scope.key?("vrf_mode") || scope["vrf_mode"] == "named" && scope["vrf"] == "default") &&
        identity.all? { |key, value| !attributes.key?(key) || (key == "address" ? ServerAddress.normalize(attributes[key]) == ServerAddress.normalize(value) : attributes[key] == value) }
      raise ArgumentError, "Invalid configuration resource identity" unless valid_identity

      [ identity, scope, attributes ].each do |fields|
        fields.each do |key, value|
          valid = case key
          when "address" then address?(value)
          when "port" then value.is_a?(Integer) && value.between?(1, 65_535)
          when "dscp" then value.is_a?(Integer) && value.between?(0, 63)
          when "severity" then value.is_a?(Integer) && value.between?(0, 7)
          when "version" then value.is_a?(Integer) && value.between?(1, 4)
          when "key_id" then value.is_a?(Integer) && value.between?(1, 4_294_967_295)
          when "minpoll", "maxpoll" then value.is_a?(Integer) && value.between?(4, 17)
          when "timeout" then value.is_a?(Integer) && value.between?(1, 65_535)
          when "certificate_check", "prefer", "burst", "iburst", "normal_sync", "authenticated", "key_present", "single_connection" then [ true, false ].include?(value)
          when "role" then %w[server peer authentication authorization accounting all].include?(value)
          when "priority" then %w[primary secondary host backup1 backup2].include?(value)
          when "family" then %w[ipv4 ipv6].include?(value)
          when "name", "group", "profile" then name?(value)
          when "protocol" then %w[udp tcp secure-tcp ssl].include?(value)
          when "types" then value.is_a?(Array) && !value.empty? && value.uniq == value && value.all? { |item| token?(item) }
          else token?(value)
          end
          raise ArgumentError, "Invalid configuration resource field" unless valid
        end
      end
    end

    # 白名单词元不接受空白、分号及 CLI 视图控制字符。
    def self.token?(value)
      value.is_a?(String) && value.bytesize.between?(1, 253) && /\A[a-zA-Z0-9_][a-zA-Z0-9_.:\/-]*\z/.match?(value)
    end

    # 接口参数可分写类型及编号，但不能包含控制字符或额外词元。
    def self.interface_name(value)
      return unless value.is_a?(String) && value.bytesize.between?(1, 253) && !/[[:cntrl:]]/.match?(value)
      match = /\A([a-zA-Z][\w.:\/-]*)(?: +(\d[\d.:\/-]*))?\z/.match(value)
      return unless match && (!match[2] || !/\d/.match?(match[1]))

      match[1] + match[2].to_s
    end

    # 某些厂商的引号对象名允许空格，但不接受换行及命令分隔符。
    def self.name?(value)
      value.is_a?(String) && value.bytesize.between?(1, 253) && /\A[a-zA-Z0-9_][a-zA-Z0-9_.:\/ -]*\z/.match?(value) && !value.end_with?(" ")
    end

    # 批准对象只声明身份、作用域及受管属性，不能夹带原始命令或秘密。
    def self.validate_expected!(kind, objects)
      raise ArgumentError, "Invalid baseline resources" unless objects.is_a?(Array)
      keys = objects.map do |object|
        unless object.is_a?(Hash) && (object.keys - %w[identity scope attributes bindings]).empty? && object.key?("identity") && object.key?("scope")
          raise ArgumentError, "Invalid baseline resource object"
        end
        validate!(kind: kind, identity: object["identity"], scope: object["scope"], attributes: object.fetch("attributes", {}), lines: [], complete: true)
        ResourceBindings.validate!(kind, object["bindings"]) if object.key?("bindings")
        [ normalize_scope(kind, object["identity"], object["scope"]), ServerAddress.normalize_fields(object["identity"]) ]
      end
      raise ArgumentError, "Duplicate baseline resource identity" unless keys.uniq.size == keys.size
      true
    end

    # 只有地址型默认域及已命名方案缺省 VRF 可规范化，命名主备槽位保留原作用域。
    def self.normalize_scope(kind, identity, scope)
      default_vrf = kind == "ntp.association" && identity.key?("address") ||
        kind == "syslog.destination" && !scope.key?("profile") && !scope.key?("source") ||
        kind == "tacacs.endpoint" && scope.key?("group")
      default_vrf ? { "vrf" => "default" }.merge(scope) : scope
    end

    # 归一化只创建新容器，调用方的批准参数及已解析资源不被修改。
    def self.normalize_objects(kind, objects)
      objects.map do |object|
        normalized = object.merge("scope" => normalize_scope(kind, object["identity"], object["scope"]), "identity" => ServerAddress.normalize_fields(object["identity"]))
        normalized["attributes"] = ServerAddress.normalize_fields(object["attributes"]) if object.key?("attributes")
        normalized["bindings"] = ResourceBindings.normalize(object["bindings"]) if object.key?("bindings")
        normalized
      end
    end

    # 受管作用域使用精确匹配，不从批准对象推导删除边界。
    def self.validate_scopes!(scopes)
      unless scopes.is_a?(Array) && !scopes.empty? && scopes.uniq.size == scopes.size && scopes.all? do |scope|
        scope.is_a?(Hash) && (scope.keys - SCOPE_FIELDS).empty? &&
          (!scope.key?("vrf_mode") || scope["vrf"] == "default" && scope["vrf_mode"] == "named") && scope.all? do |key, value|
          %w[group profile].include?(key) ? name?(value) : token?(value)
        end
      end
        raise ArgumentError, "Invalid managed resource scopes"
      end
      true
    end

    # 地址与 DNS 名沿用同一校验契约，资源和旧事实不能对非法目标判断不同。
    def self.address?(value) = ServerAddress.valid?(value)
  end
end

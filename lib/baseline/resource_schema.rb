# frozen_string_literal: true

require "ipaddr"

module Baseline
  # 资源只持有配置生成所需的非秘密属性；未知字段不能进入报告。
  module ResourceSchema
    SYSLOG_FIELDS = %w[address name protocol port facility severity channel dscp filter source format types certificate_check].freeze
    NTP_FIELDS = %w[address version key_id prefer source minpoll maxpoll burst iburst normal_sync authenticated].freeze
    IDENTITY_FIELDS = %w[address name protocol port types role].freeze
    SCOPE_FIELDS = %w[vrf profile source].freeze

    # 校验完整资源数据，拒绝控制字符及未声明的配置字段。
    def self.validate!(kind:, identity:, scope:, attributes:, lines:, complete:)
      fields = { "syslog.destination" => SYSLOG_FIELDS, "ntp.association" => NTP_FIELDS }[kind]
      valid = fields && identity.is_a?(Hash) && !identity.empty? &&
        (identity.keys - IDENTITY_FIELDS).empty? && scope.is_a?(Hash) && (scope.keys - SCOPE_FIELDS).empty? &&
        attributes.is_a?(Hash) && (attributes.keys - fields).empty? &&
        lines.is_a?(Array) && lines.all? { |line| line.is_a?(Integer) && line.positive? } &&
        [ true, false ].include?(complete)
      raise ArgumentError, "Invalid configuration resource" unless valid

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
          when "certificate_check", "prefer", "burst", "iburst", "normal_sync", "authenticated" then [ true, false ].include?(value)
          when "role" then %w[server peer].include?(value)
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

    # 地址与 DNS 名沿用同一校验契约，资源和旧事实不能对非法目标判断不同。
    def self.address?(value)
      return false unless value.is_a?(String) && !value.empty?
      IPAddr.new(value)
      !value.include?("/")
    rescue IPAddr::Error
      value.bytesize <= 253 && !/\A[\d.]+\z/.match?(value) && value.delete_suffix(".").split(".", -1).all? do |label|
        /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i.match?(label)
      end
    end
  end
end

# frozen_string_literal: true

require "ipaddr"

module Baseline
  # IP 和 DNS 目标使用一致身份；对象名称、接口、路由域及 DNS 解析结果不在这里归一化。
  module ServerAddress
    FACTS = %w[ntp.servers syslog.servers tacacs.servers].freeze

    # 保留绝对/相对 DNS 名称区别，不执行解析，也不合并 IPv4 与 IPv4 映射 IPv6。
    def self.normalize(value)
      unless value.is_a?(String) && value.ascii_only? && value.bytesize.between?(1, 253) && !/[\/%\[\]]/.match?(value)
        raise ArgumentError, "Invalid server address", cause: nil
      end
      if (ipv4 = /\A(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\z/.match(value))
        raise ArgumentError, "Invalid server address", cause: nil unless ipv4.captures.all? { |octet| octet.to_i <= 255 }
        return value
      end
      if value.include?(":")
        begin
          return IPAddr.new(value).to_s
        rescue IPAddr::Error
          raise ArgumentError, "Invalid server address", cause: nil
        end
      end
      unless !/\A[\d.]+\z/.match?(value) && value.delete_suffix(".").split(".", -1).all? do |label|
          /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i.match?(label)
        end
        raise ArgumentError, "Invalid server address", cause: nil
      end
      /[A-Z]/.match?(value) ? value.downcase(:ascii) : value
    end

    # 语法校验和身份计算共用同一边界，非法地址不能退化成名称或网段。
    def self.valid?(value)
      normalize(value)
      true
    rescue ArgumentError
      false
    end

    # 地址集合按语义去重，重复声明或文本变体不能证明独立服务器数量。
    def self.normalize_set(values)
      raise ArgumentError, "Invalid server address set" unless values.is_a?(Array)
      normalized = values.map { |value| normalize(value) }
      normalized.uniq!
      normalized
    end

    # 仅地址字段具有网络端点语义，其他同形名称保持原有大小写及内容。
    def self.normalize_fields(fields)
      return fields unless fields&.key?("address")
      address = normalize(fields["address"])
      address == fields["address"] ? fields : fields.merge("address" => address)
    end
  end
end

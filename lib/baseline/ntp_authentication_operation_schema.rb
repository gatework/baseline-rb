# frozen_string_literal: true

module Baseline
  # 全局认证切换使用独立阶段，不能把依赖完成后的激活伪装成核验命令。
  module NtpAuthenticationOperationSchema
    KIND = "ntp.authentication"

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      unless identity == {} && scope == {} && action == :set && [ true, false ].include?(before) &&
          [ true, false ].include?(after) && before != after && (after ? %i[prepare activate].include?(phase) : phase == :prepare)
        raise ArgumentError, "Invalid NTP authentication operation"
      end
      true
    end
  end
end

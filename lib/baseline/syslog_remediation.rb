# frozen_string_literal: true

require_relative "target_remediation"

module Baseline
  # 日志对象共享目标集合规划，但保留自身身份和审批规则。
  class SyslogRemediation < TargetRemediation
    IDS = %w[syslog.minimum_servers syslog.servers syslog.destinations].freeze
    KIND = "syslog.destination"
  end
end

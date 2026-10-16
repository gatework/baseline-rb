# frozen_string_literal: true

require_relative "baseline/version"

require "ctx_parser/immutable"

module Baseline
  # 复制并冻结可序列化的基线事实，避免调用方修改策略或报告状态。
  def self.immutable(value)
    CtxParser::Immutable.copy(value)
  rescue ArgumentError
    raise ArgumentError, "Baseline values must be plain data"
  end
end

require_relative "baseline/configuration"
require_relative "baseline/document"
require_relative "baseline/acl"
require_relative "baseline/credential"
require_relative "baseline/facts"
require_relative "baseline/parsers/base"
require_relative "baseline/parsers/comware"
require_relative "baseline/parsers/h3c"
require_relative "baseline/parsers/huawei"
require_relative "baseline/parsers/cisco"
require_relative "baseline/parsers/cisco_ios"
require_relative "baseline/parsers/cisco_nxos"
require_relative "baseline/parsers/hillstone"
require_relative "baseline/parsers/palo_alto"
require_relative "baseline/rule"
require_relative "baseline/policy"
require_relative "baseline/report"
require_relative "baseline/evaluator"
require_relative "baseline/audit"

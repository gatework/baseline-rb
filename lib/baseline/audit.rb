# frozen_string_literal: true

require_relative "configuration"
require_relative "evaluator"
require_relative "h3c/parser"
require_relative "huawei/parser"
require_relative "cisco_ios/parser"
require_relative "cisco_nxos/parser"
require_relative "hillstone/parser"
require_relative "palo_alto/parser"

require "digest"

module Baseline
  # 仅分析传入文本，不读取文件、访问数据库、连接设备或执行修复。
  class Audit
    PARSERS = { "h3c" => H3c::Parser, "huawei" => Huawei::Parser,
      "cisco_ios" => CiscoIos::Parser, "cisco_nxos" => CiscoNxos::Parser,
      "hillstone" => Hillstone::Parser, "palo_alto" => PaloAlto::Parser }.freeze
    ALIASES = { "h3c_wireless" => "h3c", "comware" => "h3c", "huawei_wireless" => "huawei", "vrp" => "huawei",
      "ios" => "cisco_ios", "iosxe" => "cisco_ios", "ios_xe" => "cisco_ios", "cisco_ios_xe" => "cisco_ios",
      "nxos" => "cisco_nxos", "nx_os" => "cisco_nxos", "stoneos" => "hillstone", "stone_os" => "hillstone",
      "paloalto" => "palo_alto", "panos" => "palo_alto", "pan_os" => "palo_alto" }.freeze

    # 绑定配置解析与基线评估使用的策略。
    def initialize(policy:)
      @evaluator = Evaluator.new(policy: policy)
    end

    # 解析配置证据，并评估适用的基线规则。
    def call(configuration:, platform:, complete: false, context: {})
      unless configuration.is_a?(String) && (platform.is_a?(String) || platform.is_a?(Symbol)) && [ true, false ].include?(complete)
        raise ArgumentError, "Configuration text, platform and boolean completeness are required"
      end
      name = platform.to_s.strip.downcase.tr("-", "_")
      name = ALIASES.fetch(name, name)
      parser = PARSERS[name]
      result = parser ? parser.parse(configuration, complete: complete) :
        CtxParser::Result.new(status: :unsupported, issues: [ { code: :unsupported_platform } ])
      facts = Configuration.new(platform: name, sha256: Digest::SHA256.hexdigest(configuration), result: result, input_complete: complete)
      @evaluator.call(configuration: facts, context: context)
    end

    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class}>"
  end
end

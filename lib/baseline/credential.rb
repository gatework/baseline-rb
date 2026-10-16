# frozen_string_literal: true

module Baseline
  # 仅在构造时分析凭据，不保留明文、密文或可枚举的摘要。
  class Credential
    COMMON = %w[admin administrator password passwd public private cisco huawei h3c root guest test 123456 12345678 123456789 1234567890 qwerty welcome changeme].freeze
    attr_reader :attributes

    # 提取可安全报告的凭据属性，随后丢弃传入的秘密值。
    def initialize(owner:, kind:, format:, secret:, line:)
      storage = case format.to_s
      when "plain", "simple", "0" then "plaintext"
      when "4", "5", "7" then "legacy"
      when "6", "8", "9", "hash", "cipher", "irreversible-cipher" then "protected"
      else "unknown"
      end
      values = { owner: owner, kind: kind, storage: storage, format: format.to_s, present: !secret.to_s.empty?, line: line }
      if storage == "plaintext"
        text = secret.to_s
        values.merge!(length: text.length, character_classes: [ /[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d]/ ].count { |pattern| pattern.match?(text) },
          common: COMMON.include?(text.downcase) || text.downcase == owner.to_s.downcase || /\A(.)\1+\z/.match?(text))
      end
      @attributes = Baseline.immutable(values)
      freeze
    end

    # 返回公开的数据结构，并保留状态与诊断信息。
    def to_h = attributes
    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} kind=#{attributes[:kind]} storage=#{attributes[:storage]}>"
  end
end

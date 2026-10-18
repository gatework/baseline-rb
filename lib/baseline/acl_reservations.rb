# frozen_string_literal: true

module Baseline
  # 只保留已批准标识的出现结果；不导出任意配置词元或秘密摘要。
  module AclReservations
    # 一次扫描覆盖所有目标，未建模命令、注释或横幅中的出现也保守占用。
    def self.from(configuration:, identifiers:)
      selected = identifiers.uniq
      return [].freeze if selected.empty?
      index = selected.group_by { |identifier| key(identifier) }
      starts = index.keys.map { |identifier| identifier[0] }
      starts << "0" if index.keys.any? { |identifier| /\A[0-9]+\z/.match?(identifier) }
      initial = starts.uniq.map { |character| Regexp.escape(character) }.join
      pattern = Regexp.new("(?<![a-zA-Z0-9_.:/-])[#{initial}][a-zA-Z0-9_.:/-]*".b, Regexp::IGNORECASE)
      seen = {}
      configuration.b.scan(pattern) do |token|
        matches = index[key(token)]
        matches&.each { |identifier| seen[identifier] = true }
      end
      selected.select { |identifier| seen[identifier] }.freeze
    end

    # 字母忽略大小写，数字去掉前导零；不构造可能任意大的整数。
    def self.key(value)
      /\A[0-9]+\z/.match?(value) ? value.sub(/\A0+(?=[0-9])/, "") : value.downcase
    end
    private_class_method :key
  end
end

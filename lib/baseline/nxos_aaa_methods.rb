# frozen_string_literal: true

require_relative "resource_schema"

module Baseline
  # NX-OS 的 group-list 是单个有序组列表，本地错误后备不是认证列表尾部方法。
  module NxosAaaMethods
    def self.group?(name) = name == "tacacs+" || ResourceSchema.token?(name) && !%w[group local none fallback error default console].include?(name)

    def self.parse(text, role:)
      return [ { "kind" => "local" } ] if text == "local"
      return [ { "kind" => "none" } ] if text == "none" && %w[authentication authorization].include?(role)
      tokens = text.split
      return unless tokens.shift == "group"
      terminal = tokens.pop if role == "authorization" && %w[local none].include?(tokens.last) || role == "authentication" && tokens.last == "none"
      return unless !tokens.empty? && tokens.join(" ").bytesize <= 127 && tokens.uniq == tokens && tokens.all? { |name| group?(name) }
      methods = tokens.map { |name| { "kind" => "server_group", "group" => name } }
      methods << { "kind" => terminal } if terminal
      methods
    end
  end
end

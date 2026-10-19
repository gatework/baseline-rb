# frozen_string_literal: true

module Baseline
  # 只确认已配置的消费者模式；运行时对端仍需要外部核验，不能由静态空集推导。
  module NtpAuthenticationInventory
    def self.unresolved(roots, style:)
      stack = roots.map { |entry| [ entry, true ] }
      unknown = []
      until stack.empty?
        entry, global = stack.pop
        stack.concat(entry.children.map { |child| [ child, false ] })
        prefix = style == :stoneos ? /\A(?:no )?ntp(?:\s|\z)/ : /\A(?:undo )?ntp-service(?:\s|\z)/
        next unless prefix.match?(entry.text)
        known = global && (style == :stoneos ? stoneos?(entry.text) : comware?(entry.text))
        unknown << entry unless known
      end
      unknown
    end

    # 服务器、材料和开关各有严格的语义解析；此处只判断是否存在尚未建模的模式。
    def self.stoneos?(text)
      /\A(?:no )?ntp (?:server|authentication-key)(?:\s|\z)/.match?(text) ||
        /\A(?:no )?ntp (?:authentication|enable)\z/.match?(text) ||
        /\Antp (?:query-interval|max-adjustment) \d+\z/.match?(text) || /\Ano ntp (?:query-interval|max-adjustment)\z/.match?(text)
    end

    def self.comware?(text)
      /\A(?:undo )?ntp-service (?:(?:ipv6 )?unicast-(?:server|peer)|authentication-keyid|reliable authentication-keyid)(?:\s|\z)/.match?(text) ||
        /\A(?:undo )?ntp-service (?:authentication enable|enable)\z/.match?(text) ||
        /\A(?:undo )?ntp-service (?:ipv6 )?source(?:\s|\z)/.match?(text) ||
        /\A(?:undo )?ntp-service (?:ipv6 )?(?:dscp|max-dynamic-sessions)(?: \d+)?\z/.match?(text) ||
        /\A(?:undo )?ntp-service (?:ipv6 )?(?:peer|server|query|synchronization) acl(?:\s|\z)/.match?(text)
    end
  end
end

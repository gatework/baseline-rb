# frozen_string_literal: true

require_relative "access_approval"

module Baseline
  # VTY 配对设置只承载明确范围及有效协议，不允许通过视图字符串执行额外命令。
  module VtyAuthenticationSchema
    KIND = "aaa.vty"

    def self.ranges?(names)
      return false unless names.is_a?(Array) && names.any? && names.all? { |name| name.is_a?(String) && name.start_with?("line vty ") && AccessApproval.range(name) }
      ranges = names.map { |name| AccessApproval.range(name) }.sort
      ranges.each_cons(2).all? { |left, right| left.last < right.first }
    end

    def self.settings?(value, target: false)
      value.is_a?(Hash) && (target ? value.keys.sort == %w[authentication protocols] : value.keys.sort == %w[authentication local_protocols protocols]) &&
        (target ? value["authentication"] == "scheme" : %w[scheme password none].include?(value["authentication"])) &&
        protocols?(value["protocols"]) && (target || value["local_protocols"].nil? || protocols?(value["local_protocols"]))
    end

    def self.protocols?(value) = value.is_a?(Array) && value.one? && %w[all ssh telnet].include?(value.first)

    # 模式非默认化可使另一项脱离 class；在收敛命令前短暂采用设备缺省协议。
    def self.temporary_rebind?(before)
      before["protocols"] != [ "all" ] && before["local_protocols"] != before["protocols"]
    end

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      valid = identity.is_a?(Hash) && identity.keys == [ "vty" ] && ranges?([ identity["vty"] ]) && scope == { "syntax_profile" => "comware7" } &&
        action == :replace && phase == :activate && settings?(before) && settings?(after, target: true) && before.except("local_protocols") != after
      raise ArgumentError, "Invalid VTY authentication operation" unless valid
    end
  end
end

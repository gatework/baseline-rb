# frozen_string_literal: true

require_relative "access_approval"

module Baseline
  # VTY 配对设置只承载明确范围及有效协议，不允许通过视图字符串执行额外命令。
  module VtyAuthenticationSchema
    KIND = "aaa.vty"
    PROFILES = CtxParser::Immutable.copy({ "comware7" => { platform: "h3c", view: "line vty", mode: "scheme", coupled: true },
      "vrp_s_series" => { platform: "huawei", view: "user-interface vty", mode: "aaa", coupled: false } })

    def self.profile_for(platform) = PROFILES.find { |_, profile| profile[:platform] == platform }&.first

    def self.ranges?(names, syntax_profile: "comware7")
      views = syntax_profile ? [ PROFILES[syntax_profile]&.fetch(:view) ].compact : PROFILES.values.map { |profile| profile[:view] }
      return false unless names.is_a?(Array) && names.any? && names.all? { |name| name.is_a?(String) && views.any? { |view| name.start_with?("#{view} ") } && AccessApproval.range(name) }
      ranges = names.map { |name| AccessApproval.range(name) }.sort
      ranges.each_cons(2).all? { |left, right| left.last < right.first }
    end

    def self.settings?(value, target: false, syntax_profile: "comware7")
      mode = PROFILES[syntax_profile]&.fetch(:mode)
      mode && value.is_a?(Hash) && (target ? value.keys.sort == %w[authentication protocols] : value.keys.sort == %w[authentication local_protocols protocols]) &&
        (target ? value["authentication"] == mode : [ mode, "password", "none" ].include?(value["authentication"])) &&
        protocols?(value["protocols"]) && (target || value["local_protocols"].nil? || protocols?(value["local_protocols"]))
    end

    def self.protocols?(value) = value.is_a?(Array) && value.one? && %w[all ssh telnet].include?(value.first)

    # 模式非默认化可使另一项脱离 class；在收敛命令前短暂采用设备缺省协议。
    def self.temporary_rebind?(before, syntax_profile: "comware7")
      PROFILES[syntax_profile]&.fetch(:coupled) && before["protocols"] != [ "all" ] && before["local_protocols"] != before["protocols"]
    end

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      profile = scope.is_a?(Hash) && scope.keys == [ "syntax_profile" ] && scope["syntax_profile"]
      valid = PROFILES.key?(profile) && identity.is_a?(Hash) && identity.keys == [ "vty" ] && ranges?([ identity["vty"] ], syntax_profile: profile) &&
        action == :replace && phase == :activate && settings?(before, syntax_profile: profile) && settings?(after, target: true, syntax_profile: profile) && before.except("local_protocols") != after
      raise ArgumentError, "Invalid VTY authentication operation" unless valid
    end
  end
end

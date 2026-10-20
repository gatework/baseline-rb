# frozen_string_literal: true

require_relative "aaa_chain_schema"
require_relative "nxos_aaa_methods"

module Baseline
  # 原生全局 default 范围与职责语法独立于 Comware 域和 IOS 命名登录列表。
  module NxosAaaSchema
    KIND = "aaa.nxos_chain"
    IDS = AaaChainSchema::IDS.merge("ssh.vty_aaa" => "authentication").freeze
    APPROVALS = %w[syntax_profile methods local_fallback_on_error local_fallback_access_verified management_consumers_verified tacacs_peer_compatibility_verified].freeze

    def self.methods?(methods, role:, approved:)
      return false unless methods.is_a?(Array) && methods.any? && methods.all? { |method| method.is_a?(Hash) }
      return true if methods == [ { "kind" => "local" } ]
      return !approved && role != "accounting" if methods == [ { "kind" => "none" } ]
      terminal = methods.last if %w[local none].include?(methods.last&.fetch("kind", nil))
      groups = terminal ? methods[0...-1] : methods
      valid = groups.any? && groups.all? do |method|
        method.is_a?(Hash) && (method.keys.sort == %w[group kind] && method["kind"] == "tacacs" && NxosAaaMethods.group?(method["group"]) ||
          !approved && method == { "kind" => "radius" })
      end
      return false unless valid && groups.uniq == groups && groups.map { |method| method["group"] || "radius" }.join(" ").bytesize <= 127
      return terminal.nil? if role == "accounting"
      return !terminal || !approved && terminal == { "kind" => "none" } if role == "authentication"

      approved ? terminal == { "kind" => "local" } : !terminal || [ { "kind" => "local" }, { "kind" => "none" } ].include?(terminal)
    end

    def self.validate_approval!(value, id:)
      role = IDS.fetch(id)
      valid = (value.keys - APPROVALS).empty? && (!value.key?("methods") || methods?(value["methods"], role: role, approved: true)) &&
        (!value.key?("local_fallback_on_error") || role == "authentication" && value["methods"] != [ { "kind" => "local" } ] && [ true, false ].include?(value["local_fallback_on_error"]))
      raise ArgumentError, "Invalid native NX-OS method approval" unless valid
    end

    def self.validate!(identity:, scope:, before:, after:, action:, phase:)
      role = identity.is_a?(Hash) && identity["role"]
      fields = role == "authentication" ? %w[fallback_on_error methods] : [ "methods" ]
      identity_valid = role == "authorization" ? identity.keys.sort == %w[function role] && %w[commands config-commands].include?(identity["function"]) :
        %w[authentication accounting].include?(role) && identity.keys == [ "role" ]
      valid = identity_valid && scope == { "selector" => "default", "syntax_profile" => "nxos" } && action == :replace && phase == :activate &&
        before.is_a?(Hash) && before.keys.sort == fields && methods?(before["methods"], role: role, approved: false) &&
        after.is_a?(Hash) && after.keys.sort == fields && methods?(after["methods"], role: role, approved: true)
      if valid && role == "authentication"
        valid = [ true, false ].include?(before["fallback_on_error"]) &&
          (after["methods"] == [ { "kind" => "local" } ] ? after["fallback_on_error"] == before["fallback_on_error"] : after["fallback_on_error"] == true)
      end
      raise ArgumentError, "Invalid native NX-OS method operation" unless valid
    end
  end
end

# frozen_string_literal: true

require_relative "../ntp_authentication"

module Baseline
  module Hillstone
    # StoneOS 按全局地址归约服务器；vrouter 是当前配置，撤销命令没有路由域参数。
    module NtpConfiguration
      private

      def parse_ntp
        entries = matching_blocks(/\A(?:no )?ntp server(?:\s|\z)/)
        active = {}
        unresolved = matching_blocks(/\A(?:no )?ntp peer(?:\s|\z)/)
        entries.each do |entry|
          parts = command_tokens(entry)
          negative = parts.first == "no"
          parts = parts.drop(1) if negative
          unless server_address?(parts[2]) && parts[2].bytesize <= 127
            unresolved << entry
            next
          end
          address = ServerAddress.normalize(parts[2])
          options = parse_keyword_options(parts.drop(3), flags: [ "prefer" ], keys: %w[key source vrouter])
          valid = options && (!options["key"] || valid_ntp_key_id?(options["key"])) &&
            options.values.grep(String).all? { |value| ResourceSchema.token?(value) }
          if negative && parts.size == 3
            active.delete(address)
          elsif negative || !valid
            active[address] = { entry: entry, complete: false }
          else
            options["prefer"] = false unless options.key?("prefer")
            active[address] = { entry: entry, options: options, complete: true }
          end
        end
        sources = []
        active.each do |address, state|
          unless state[:complete]
            unresolved << state[:entry]
            next
          end
          options, entry = state.values_at(:options, :entry)
          scope = { "vrf" => options["vrouter"] || "default" }
          scope["vrf_mode"] = "named" if options["vrouter"] == "default"
          record_ntp_resource(address: address, role: "server", vrf: options["vrouter"], options: options, entry: entry, scope: scope)
          sources << options["source"]
          analyze(entry) { address }
        end
        record_fact("ntp.servers", active.select { |_, state| state[:complete] }.keys, entries)
        record_fact("ntp.source", sources.first, entries) if sources.any? && sources.first && sources.uniq.size == 1
        record_unknown_fact("ntp", unresolved, code: :ntp_server_unresolved) unless unresolved.empty?
        enabled = stoneos_ntp_authentication_switch
        parse_stoneos_ntp_material(enabled)
      end

      # 文档明确缺省关闭；不完整输入或损坏的最终声明不能使用缺省或旧值。
      def stoneos_ntp_authentication_switch
        entries = matching_blocks(/\A(?:no )?ntp authentication(?:\s|\z)/)
        enabled = if entries.empty?
          false if @fact_builder.complete?
        elsif entries.last.text == "ntp authentication"
          true
        elsif entries.last.text == "no ntp authentication"
          false
        end
        if !entries.empty? && enabled.nil?
          record_unknown_fact("ntp.authentication", [ entries.last ], code: :ntp_authentication_state_unresolved)
        else
          record_fact("ntp.authentication", enabled, entries)
        end
        enabled
      end

      # 只分析最终材料的存储和强度元数据；完整材料、删除及损坏声明分别保留。
      def parse_stoneos_ntp_material(enabled)
        entries = matching_blocks(/\A(?:no )?ntp authentication-key(?:\s|\z)/)
        keys, unresolved = {}, []
        entries.each do |entry|
          parts = command_tokens(entry)
          negative = parts.first == "no"
          parts = parts.drop(1) if negative
          unless valid_ntp_key_id?(parts[2])
            unresolved << entry
            next
          end
          state = if negative && parts.size == 3
            { present: false, complete: true }
          elsif !negative && parts.size == 5 && parts[3] == "md5" && parts[4].length.between?(1, 31) && !/[[:cntrl:]]/.match?(parts[4])
            { present: true, complete: true, algorithm: "md5", format: "plain", secret: parts[4] }
          else
            { present: nil, complete: false }
          end
          keys[parts[2].to_i] = state.merge(entry: entry)
        end
        associations = @fact_builder.resources_for("ntp.association")
        ids = keys.keys | associations.filter_map { |object| object[:attributes]["key_id"] }
        slots = ids.map do |key_id|
          state = keys[key_id] || { present: @fact_builder.complete? && unresolved.empty? ? false : nil, complete: @fact_builder.complete? && unresolved.empty? }
          entry = state[:entry]
          if state[:present] == true
            record_credential("ntp-key:#{key_id}", "ntp", state[:format], state[:secret], entry, purpose: "authentication")
          elsif state[:present].nil? && entry
            value = Credential.new(owner: "ntp-key:#{key_id}", kind: "ntp", format: "unknown", secret: nil,
              line: entry.line, purpose: "authentication").to_h.merge(present: nil)
            index = @fact_builder.record_credential(value)
            capture(entry, value, [ "facts", "credentials.records", index ])
          end
          { key_id: key_id, present: state[:present], complete: state[:complete], algorithm: state[:algorithm], format: state[:format],
            trust_required: false, trusted: nil, trust_lines: [], lines: entry ? [ entry.line ] : [] }
        end
        record_fact("ntp.key_slots", slots, entries)
        if !@fact_builder.complete? || unresolved.any? || slots.any? { |slot| !slot[:complete] }
          record_unknown_fact("ntp.key_slots", unresolved, code: :ntp_key_inventory_unresolved)
        end
        bindings = Baseline::NtpAuthentication.bindings(associations, slots, enabled: enabled, complete: @fact_builder.complete?)
        if unresolved.any?
          bindings = bindings.map { |binding| binding.merge(configured_ready: nil, reason: :ntp_key_inventory_unresolved) }
        end
        record_fact("ntp.authentication_bindings", bindings)
        record_unknown_fact("ntp.authentication_bindings", unresolved, code: :ntp_authentication_unresolved) unless @fact_builder.complete? && unresolved.empty?
      end

      def valid_ntp_key_id?(value) = value.is_a?(String) && /\A\d{1,5}\z/.match?(value) && value.to_i.between?(1, 65_535)
    end
  end
end

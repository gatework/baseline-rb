# frozen_string_literal: true

require_relative "../ntp_authentication"

module Baseline
  module Comware
    # Comware/VRP 的全局 NTP 材料与可信声明按源顺序归约，接口命令不借用为全局材料。
    module NtpAuthentication
      private

      # 最后一个同族开关声明决定状态；未知参数不能回落到旧的已知值。
      def ntp_authentication_switch
        entries = matching_blocks(/\A(?:undo )?ntp-service authentication(?:\s|\z)/)
        entry = entries.last
        return unless entry
        enabled = case entry.text
        when "ntp-service authentication enable" then true
        when "undo ntp-service authentication enable" then false
        end
        if enabled.nil?
          record_unknown_fact("ntp.authentication", [ entry ], code: :ntp_authentication_state_unresolved)
        else
          analyze(entry) { enabled }
          record_fact("ntp.authentication", enabled, [ entry ])
        end
        enabled
      end

      # 先归约替换和撤销，再分析最终凭据，旧秘密及旧安全属性不进入报告。
      def parse_ntp_authentication(enabled)
        entries = matching_blocks(/\A(?:undo )?ntp-service (?:authentication-keyid|reliable authentication-keyid)(?:\s|\z)/)
        keys, trusts, unresolved = {}, {}, []
        entries.each do |entry|
          text = entry.text
          if (match = /\A(undo )?ntp-service reliable authentication-keyid (\d+)\z/.match(text)) && valid_ntp_key_id?(match[2])
            trusts[match[2].to_i] = { trusted: match[1].nil?, lines: [ entry.line ] }
          elsif (match = /\A(?:undo )?ntp-service reliable authentication-keyid (\d+)(?:\s|\z)/.match(text)) && valid_ntp_key_id?(match[1])
            trusts[match[1].to_i] = { trusted: nil, lines: [ entry.line ] }
          elsif (match = /\Aundo ntp-service authentication-keyid (\d+)\z/.match(text)) && valid_ntp_key_id?(match[1])
            key_id = match[1].to_i
            keys[key_id] = { present: false, complete: true, entry: entry }
            trusts[key_id] = { trusted: ntp_delete_clears_trust? ? false : nil, lines: [ entry.line ] }
          elsif (match = /\Antp-service authentication-keyid (\d+)(?:\s+(.*))?\z/.match(text)) && valid_ntp_key_id?(match[1])
            keys[match[1].to_i] = ntp_material_state(match[2].to_s).merge(entry: entry)
          else
            unresolved << entry
          end
        end
        associations = @fact_builder.resources_for("ntp.association")
        references = associations.filter_map { |object| object[:attributes]["key_id"] }
        slots = (keys.keys | trusts.keys | references).map do |key_id|
          key = keys[key_id] || { present: @fact_builder.complete? && unresolved.empty? ? false : nil, complete: @fact_builder.complete? && unresolved.empty? }
          trust = trusts[key_id] || { trusted: @fact_builder.complete? && unresolved.empty? ? false : nil, lines: [] }
          trust = trust.merge(trusted: nil) if unresolved.any?
          if key[:present] == true
            record_credential("ntp-key:#{key_id}", "ntp", key[:format], key[:secret], key[:entry], purpose: "authentication")
          elsif key[:present].nil? && key[:entry]
            record_unresolved_ntp_credential(key_id, key[:entry])
          end
          { key_id: key_id, present: key[:present], complete: key[:complete], algorithm: key[:algorithm], format: key[:format],
            trusted: trust[:trusted], lines: key[:entry] ? [ key[:entry].line ] : [], trust_lines: trust[:lines] }
        end
        record_fact("ntp.key_slots", slots, entries)
        if !@fact_builder.complete? || unresolved.any? || slots.any? { |slot| !slot[:complete] || slot[:trusted].nil? }
          record_unknown_fact("ntp.key_slots", unresolved, code: :ntp_key_inventory_unresolved)
        end
        bindings = Baseline::NtpAuthentication.bindings(associations, slots, enabled: enabled, complete: @fact_builder.complete?)
        record_fact("ntp.authentication_bindings", bindings)
        record_unknown_fact("ntp.authentication_bindings", unresolved, code: :ntp_authentication_unresolved) unless @fact_builder.complete? && unresolved.empty?
      end

      # 未知材料作为未知凭据参与归纳，不能用全局未知标记掩盖其他已确认违规。
      def record_unresolved_ntp_credential(key_id, entry)
        attributes = Credential.new(owner: "ntp-key:#{key_id}", kind: "ntp", format: "unknown", secret: nil,
          line: entry.line, purpose: "authentication").to_h.merge(present: nil)
        index = @fact_builder.record_credential(attributes)
        capture(entry, attributes, [ "facts", "credentials.records", index ])
      end

      # 只接收已确认的算法和秘密格式；密钥 ACL 等未建模参数不能被忽略。
      def ntp_material_state(settings)
        match = /\Aauthentication-mode (\S+) (.+)\z/.match(settings)
        if match && ntp_key_algorithms.include?(match[1])
          format, secret = ntp_key_secret(match[2])
          return { present: true, complete: true, algorithm: match[1], format: format, secret: secret } if secret
        end
        { present: nil, complete: false }
      end

      # Comware 7 要求显式 cipher/simple，VRP 使用独立语法覆盖。
      def ntp_key_secret(value)
        match = /\A(cipher|simple) (\S+)\z/.match(value)
        match ? match.captures : [ nil, nil ]
      end

      # 基础 profile 仅声明共同确认的算法，厂商扩展不能互相借用。
      def ntp_key_algorithms = %w[md5]
      def valid_ntp_key_id?(value) = value.bytesize <= 10 && /\A\d+\z/.match?(value) && value.to_i.between?(1, 4_294_967_295)
      # 未确认的厂商删除联动保持未知，由后续显式可信声明消除。
      def ntp_delete_clears_trust? = false
    end
  end
end

# frozen_string_literal: true

module Baseline
  # 认证开关、材料存在、可信声明和关联引用分别判断；此处不证明对端或同步成功。
  module NtpAuthentication
    # 只连接非秘密的最终槽位与关联对象，不从空材料或局部输入推导可用。
    def self.bindings(associations, slots, enabled:, complete:)
      by_id = slots.to_h { |slot| [ slot[:key_id], slot ] }
      associations.map do |object|
        key_id = object.fetch(:attributes)["key_id"]
        slot = by_id[key_id]
        ready, reason = if !complete
          [ nil, :input_incomplete ]
        elsif !object[:complete]
          [ nil, :ntp_association_unresolved ]
        elsif key_id.nil?
          [ false, :ntp_key_reference_missing ]
        elsif slot.nil? || slot[:present] == false
          [ false, :ntp_key_missing ]
        elsif slot[:present].nil? || !slot[:complete]
          [ nil, :ntp_key_unresolved ]
        elsif slot[:trusted].nil?
          [ nil, :ntp_trust_unresolved ]
        elsif !slot[:trusted]
          [ false, :ntp_key_untrusted ]
        elsif enabled.nil?
          [ nil, :ntp_authentication_state_unknown ]
        elsif !enabled
          [ false, :ntp_authentication_disabled ]
        else
          [ true, nil ]
        end
        { identity: object[:identity], scope: object[:scope], key_id: key_id, key_present: slot&.fetch(:present),
          key_trusted: slot&.fetch(:trusted), algorithm: slot&.fetch(:algorithm, nil), configured_ready: ready, reason: reason,
          lines: (object[:lines] + (slot ? slot[:lines] + slot[:trust_lines] : [])).uniq }
      end
    end
  end
end

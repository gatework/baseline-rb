# frozen_string_literal: true

require_relative "target_remediation"

module Baseline
  # 旧地址规则只管理 server，对等关联仅由显式对象规则管理。
  class NtpRemediation < TargetRemediation
    IDS = %w[ntp.minimum_servers ntp.servers ntp.associations].freeze
    KIND = "ntp.association"

    # 全局或批准的认证要求不能因新增无密钥关联而被绕过。
    def call(finding, audit)
      result = super
      auth = audit.findings.find { |item| item.id == "ntp.authentication" && item.status != :not_applicable }
      slots = audit.configuration.platform == "palo_alto" ? verify_panos_slot_dependencies!(result, auth, audit.configuration) : []
      required = auth&.expected == true || audit.configuration.fact_known?("ntp.authentication") && audit.configuration.fact("ntp.authentication") == true
      unresolved_switch = audit.configuration.issues.any? { |issue| issue[:fact] == "ntp.authentication" }
      if (required || unresolved_switch) && result.operations.any? { |operation| operation.action == :add && !operation.after.key?("key_id") }
        raise Blocked, :ntp_authentication_dependency
      end
      verified = verify_key_dependencies!(result.operations, audit.configuration)
      details = result.details.merge(verified_ntp_key_ids: verified)
      details[:verified_ntp_slots] = slots if audit.configuration.platform == "palo_alto"
      Result.new(operations: result.operations, details: CtxParser::Immutable.copy(details))
    end

    private

    # PAN-OS 的材料属于主备槽位；地址变化不能自动证明原有密钥适用于新对端。
    def verify_panos_slot_dependencies!(result, auth, evidence)
      if auth && result.details[:projected_targets].zero?
        raise Blocked, :policy_conflict
      end
      if auth && [ true, false ].include?(auth.expected)
        projected = evidence.fact("ntp.associations").to_h { |object| [ key(object), object.fetch("attributes") ] }
        result.operations.each do |operation|
          identity = [ operation.scope, operation.identity ]
          operation.action == :remove ? projected.delete(identity) : projected[identity] = operation.after
        end
        unless projected.any? && projected.values.all? { |attributes| attributes["authenticated"] == true } == auth.expected
          raise Blocked, :policy_conflict
        end
      end
      approved = @policy.rules.find { |rule| rule.id == "ntp.associations" && rule.enabled? }
      verified = []
      result.operations.each do |operation|
        next unless operation.after
        if operation.action == :add && operation.after["authenticated"] != false ||
            operation.action == :replace && operation.after["authenticated"] != operation.before["authenticated"]
          requirement = operation.after.key?("authenticated") ? "approved_ntp_authentication_material" : "explicit_ntp_authentication_choice"
          raise Blocked.new(:ntp_authentication_dependency, requirements: [ requirement ])
        end
        if operation.action == :replace && operation.before["authenticated"] == true &&
            operation.after["address"] != operation.before["address"]
          unless approved&.remediation&.fetch("ntp_peer_key_compatibility_verified", false) == true
            raise Blocked.new(:ntp_authentication_dependency, requirements: [ "ntp_peer_key_compatibility_verified" ])
          end
          verified << operation.identity.fetch("name")
        end
      end
      verified.uniq
    end

    # 新引用必须关联已知可信材料及外部对端证据；保留引用也不能绕过已知损坏的材料。
    def verify_key_dependencies!(operations, evidence)
      keyed = operations.select { |operation| operation.after&.key?("key_id") }
      changed = keyed.select { |operation| operation.before&.fetch("key_id", nil) != operation.after["key_id"] }
      if changed.any? && @policy.rules.find { |rule| rule.id == "ntp.associations" && rule.enabled? }&.remediation&.fetch("ntp_peer_key_compatibility_verified", false) != true
        raise Blocked.new(:ntp_authentication_dependency, requirements: [ "ntp_peer_key_compatibility_verified" ])
      end
      slots = evidence.fact("ntp.key_slots")
      checked = slots ? keyed : changed
      by_id = (slots || []).to_h { |slot| [ slot[:key_id], slot ] }
      checked.each do |operation|
        key_id = operation.after.fetch("key_id")
        slot = by_id[key_id]
        unless evidence.fact_known?("ntp.key_slots") && slot && slot[:present] == true && slot[:complete] && slot[:trusted] == true
          raise Blocked.new(:ntp_authentication_dependency, requirements: [ "known_trusted_ntp_key:#{key_id}" ])
        end
      end
      changed.map { |operation| operation.after.fetch("key_id") }.uniq.sort
    end

    def legacy_identity(address) = { "address" => address, "role" => "server" }
    def countable_objects(objects) = objects.select { |object| object["identity"]["role"] == "server" || object["identity"].key?("name") }
    def managed_object?(object, managed) = super && (!@legacy_mode || object["identity"]["role"] == "server")
  end
end

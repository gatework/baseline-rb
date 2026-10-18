# frozen_string_literal: true

module Baseline
  # 秘密不进入执行产物；按对象说明轮换材料或无法从备份证明的强度证据。
  class CredentialRemediation
    IDS = %w[credentials.storage credentials.strength].freeze
    DEPENDENCIES = {
      "local_user" => [ "local_fallback_access_verified" ], "line" => [ "line_access_recovery_verified" ],
      "enable" => [ "privileged_access_recovery_verified" ], "snmp" => [ "snmp_manager_update" ],
      "snmp_user" => [ "snmp_manager_update", "snmp_group_reference_verified" ],
      "ntp" => [ "ntp_peer_key_update", "ntp_trusted_key_reference_verified", "time_synchronization_recovery_verified" ],
      "tacacs" => [ "tacacs_peer_update", "authentication_reference_evidence", "local_fallback_access_verified" ]
    }.transform_values(&:freeze).freeze

    # 未知强度可以列出验证对象，但不将不适用、缺策略或局部输入变成轮换授权。
    def self.applicable?(finding, evidence)
      IDS.include?(finding.id) && evidence.complete? && !finding.expected.nil? &&
        [ :fail, :unknown ].include?(finding.status) &&
        [ nil, :deviation, :weak_password, :password_strength_unobservable, :fact_unavailable ].include?(finding.reason) &&
        evidence.fact_known?("credentials.records") && evidence.fact("credentials.records").is_a?(Array) && evidence.fact("credentials.records").any?
    end

    # 只导出白名单身份和非秘密偏差；凭据序号局限于当前配置指纹。
    def call(finding, evidence)
      return { reason: :unsupported_setting, requirements: [ "approved_protected_storage_policy" ], details: {} } if finding.id == "credentials.storage" && finding.expected != true

      objects = evidence.fact("credentials.records").each_with_index.filter_map do |record, index|
        deviations = deviations(record, finding)
        next if deviations.empty?

        rotate = !(deviations - %w[strength_unobservable storage_unobservable]).empty?
        requirements = rotate ? %w[approved_replacement_credential supported_protected_storage_format manual_rotation_procedure] :
          deviations.include?("strength_unobservable") ? [ "external_password_strength_evidence" ] : [ "credential_storage_evidence" ]
        identity = record.slice(:owner, :kind, :purpose)
        identity.merge(id: "credential:#{index + 1}", lines: [ record[:line] ].compact, action: rotate ? "rotate" : "verify",
          deviations: deviations, requirements: requirements,
          dependencies: rotate ? DEPENDENCIES.fetch(record[:kind], [ "credential_consumer_reference_evidence" ]) : [])
      end
      return { reason: :unresolved_prerequisites, requirements: [ "credential_object_evidence" ], details: {} } if objects.empty?

      rotating = objects.any? { |object| object[:action] == "rotate" }
      reason = rotating ? :credential_rotation_required : finding.id == "credentials.storage" ? :credential_storage_verification_required : :credential_strength_verification_required
      { reason: reason, requirements: objects.flat_map { |object| object[:requirements] + object[:dependencies] }.uniq, details: { credentials: objects } }
    end

    private

    # 保护格式不等于强度可观察；明确弱项与未知材料分开列出。
    def deviations(record, finding)
      if finding.id == "credentials.storage"
        return [] if record[:storage] == "protected"
        return [ "storage_unobservable" ] unless %w[plaintext legacy].include?(record[:storage])

        return [ "#{record[:storage]}_storage" ]
      end
      return [ "strength_unobservable" ] unless record[:storage] == "plaintext"

      expected = finding.expected
      result = []
      result << "common_password" if record[:common]
      result << "minimum_length" if record.fetch(:length) < expected.fetch("min_length")
      result << "minimum_character_classes" if record.fetch(:character_classes) < expected.fetch("min_classes")
      result
    end
  end
end

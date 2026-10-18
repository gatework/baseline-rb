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
      required = auth&.expected == true || audit.configuration.fact_known?("ntp.authentication") && audit.configuration.fact("ntp.authentication") == true
      if required && result.operations.any? { |operation| operation.action == :add && !operation.after.key?("key_id") }
        raise Blocked, :ntp_authentication_dependency
      end
      result
    end

    private

    def legacy_identity(address) = { "address" => address, "role" => "server" }
    def countable_objects(objects) = objects.select { |object| object["identity"]["role"] == "server" || object["identity"].key?("name") }
    def managed_object?(object, managed) = super && (!@legacy_mode || object["identity"]["role"] == "server")
  end
end

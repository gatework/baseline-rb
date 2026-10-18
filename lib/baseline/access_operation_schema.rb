# frozen_string_literal: true

require_relative "access_approval"

module Baseline
  # ACL 创建与端点重绑是不同操作，禁止通用资源删除绕开共享引用保护。
  module AccessOperationSchema
    KINDS = %w[access.acl access.binding].freeze

    # 只允许创建新 ACL、更新既有端点的绑定；身份不含原始 CLI。
    def self.validate!(kind:, identity:, scope:, before:, after:, action:, phase:)
      common = identity.is_a?(Hash) && identity.keys == [ "name" ] && scope == {} && after.is_a?(Hash)
      valid = if kind == "access.acl"
        common && ResourceSchema.token?(identity["name"]) && action == :add && phase == :create && before.nil? && after.keys == [ "sources" ] &&
          after["sources"].is_a?(Array) && after["sources"].all? { |source| source.is_a?(String) && Acl.ipv4_range(source) }
      elsif kind == "access.binding"
        common && AccessApproval.range(identity["name"]) && action == :replace && phase == :update && before.is_a?(Hash) &&
          (before.keys - [ "acl" ]).empty? && (!before.key?("acl") || ResourceSchema.token?(before["acl"])) &&
          after.keys == [ "acl" ] && ResourceSchema.token?(after["acl"])
      end
      raise ArgumentError, "Invalid ACL operation" unless valid
      true
    rescue IPAddr::Error
      raise ArgumentError, "Invalid ACL operation network"
    end
  end
end

# frozen_string_literal: true

require_relative "../syslog_reference_schema"
require_relative "../target_remediation"

module Baseline
  module PaloAlto
    # 按匹配项同时投影成员变化，完整消费者批准不能由当前配置反推。
    class SyslogBindingRemediation
      Result = Data.define(:operations, :references, :declared, :profiles)
      Blocked = TargetRemediation::Blocked

      def call(migrations:, evidence:, managed_scopes:, targets:)
        unless evidence.fact_known?("syslog.reference_sets") && evidence.fact("syslog.reference_inventory_complete") == true
          raise Blocked.new(:resource_binding_unresolved, requirements: [ "resolved_syslog_reference_inventory" ])
        end
        by_reference = migrations.group_by { |migration| migration.fetch("reference") }
        rows = evidence.fact("syslog.reference_sets")
        known = rows.to_h { |row| [ row.fetch("identity"), row ] }
        unless (by_reference.keys - known.keys).empty?
          raise Blocked.new(:syslog_reference_match_required, requirements: [ "existing_syslog_reference_match" ])
        end
        profiles = migrations.flat_map { |migration| migration.values_at("from_profile", "to_profile") }.compact.uniq
        scopes = managed_scopes.to_h { |scope| [ scope, true ] }
        unless profiles.all? { |profile| scopes.key?({ "profile" => profile }) }
          raise Blocked, :approved_scope_required
        end
        affected = profiles.to_h { |profile| [ profile, true ] }
        if targets.any? { |target| affected.key?(target["scope"]["profile"]) && !target.key?("bindings") }
          raise Blocked.new(:syslog_reference_approval_required, requirements: [ "explicit_projected_profile_bindings" ])
        end
        operations = []
        projected = rows.map do |row|
          changes = by_reference[row["identity"]]
          next row unless changes
          changes.each { |migration| verify_consumers!(migration, row) }
          before = row.fetch("profiles")
          changes.each do |migration|
            from, to = migration.values_at("from_profile", "to_profile")
            if from && !before.include?(from) && to && !before.include?(to)
              raise Blocked.new(:syslog_reference_source_unresolved, requirements: [ "known_syslog_reference_membership" ])
            end
          end
          after = ((before - changes.filter_map { |migration| migration["from_profile"] }) + changes.filter_map { |migration| migration["to_profile"] }).uniq.sort
          if before != after
            operations << ConfigurationOperation.new(kind: "syslog.reference", identity: row["identity"], scope: {},
              before: { "profiles" => before }, after: { "profiles" => after }, action: :replace, phase: :update, risk: "high")
          end
          row.merge("profiles" => after)
        end
        references, declared = {}, Hash.new(0)
        projected.each do |row|
          row["profiles"].each do |profile|
            declared[profile] += 1
            (references[profile] ||= []).concat(row["consumers"])
          end
        end
        references.transform_values! { |values| ResourceBindings.normalize(values.uniq) }
        Result.new(operations: operations.freeze, references: CtxParser::Immutable.copy(references),
          declared: CtxParser::Immutable.copy(declared), profiles: profiles.freeze)
      end

      private

      # 共用转发匹配项的所有规则和 zone 都受影响；只批准其中一项不能改变共享成员。
      def verify_consumers!(migration, row)
        return if row["identity"]["kind"] == "syslog.device"
        unless migration.key?("consumers")
          raise Blocked.new(:syslog_shared_scope_required, requirements: [ "approved_syslog_consumers" ])
        end
        difference = ResourceBindings.compare(row["consumers"], migration["consumers"])
        if difference.values.any?(&:any?)
          raise Blocked.new(:syslog_consumer_scope_mismatch, requirements: [ "complete_matching_syslog_consumers" ])
        end
      end
    end
  end
end

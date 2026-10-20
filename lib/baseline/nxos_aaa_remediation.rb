# frozen_string_literal: true

require_relative "configuration_operation"
require_relative "nxos_aaa_schema"
require_relative "tacacs_remediation"

module Baseline
  # 只激活现有已核验的原生方法引用，不改变共享服务器对象、控制台或既有材料。
  class NxosAaaRemediation
    def self.applicable?(finding, evidence)
      evidence.platform == "cisco_nxos" && evidence.complete? && NxosAaaSchema::IDS.key?(finding.id) &&
        !finding.expected.nil? && %i[fail unknown].include?(finding.status)
    end

    def initialize(policy:) = @policy = policy

    def call(finding, audit)
      options = @policy.rules.find { |rule| rule.id == finding.id }.remediation
      require!(options["syntax_profile"] == "nxos", "native_management_method_syntax_profile")
      %w[methods local_fallback_access_verified management_consumers_verified].each do |key|
        require!(options[key] && (!key.end_with?("verified") || options[key] == true), key)
      end
      evidence = audit.configuration
      require!(evidence.complete? && evidence.platform == "cisco_nxos", "complete_native_configuration")
      graph = evidence.fact("aaa.nxos")
      require!(evidence.fact_known?("aaa.nxos") && graph["scope_complete"], "resolved_native_management_method_scope")
      nodes = [ graph["authentication"]["default"], *graph["authorization"].values, graph["accounting"]["default"] ]
      require!(nodes.all? { |node| node["complete"] }, "resolved_management_login_roles")
      role = NxosAaaSchema::IDS.fetch(finding.id)
      methods = options.fetch("methods")
      remote = methods.first["kind"] == "tacacs"
      conflict! if finding.id == "ssh.vty_aaa" ? finding.expected != true : remote != finding.expected
      verify_authentication_policy!(audit, methods) if role == "authentication"
      stable = audit.findings.select { |item| TacacsRemediation::IDS.include?(item.id) && item.status != :not_applicable && !item.expected.nil? }
      require!(stable.all? { |item| item.status == :pass }, "stable_approved_tacacs_endpoints")
      if remote
        require!(graph["tacacs_enabled"] == true, "existing_enabled_tacacs_feature")
        require!(options["tacacs_peer_compatibility_verified"] == true, "tacacs_peer_compatibility_verified")
        require!(options["local_fallback_on_error"] == true, "local_fallback_on_error") if role == "authentication"
        verify_targets!(evidence, methods)
      end
      functions = role == "authorization" ? %w[commands config-commands] : [ "default" ]
      functions.filter_map do |function|
        node = graph.fetch(role).fetch(function)
        before = { "methods" => node.fetch("methods") }
        after = { "methods" => methods }
        if role == "authentication"
          before["fallback_on_error"] = node.fetch("fallback_on_error")
          after["fallback_on_error"] = remote ? true : before["fallback_on_error"]
        end
        next if before == after
        identity = { "role" => role }
        identity["function"] = function if role == "authorization"
        ConfigurationOperation.new(kind: NxosAaaSchema::KIND, identity: identity, scope: { "selector" => "default", "syntax_profile" => "nxos" },
          before: before, after: after, action: :replace, phase: :activate, risk: finding.severity == "critical" ? "critical" : "high")
      end
    end

    private

    def require!(condition, requirement)
      raise TargetRemediation::Blocked.new(:authentication_chain_evidence_required, requirements: [ requirement ]) unless condition
    end

    def conflict! = raise(TargetRemediation::Blocked, :policy_conflict)

    # 同一 default 登录链不得接受两个不同目标，已有通过的标量规则仍约束投影结果。
    def verify_authentication_policy!(audit, methods)
      related = audit.findings.select { |item| %w[tacacs.login ssh.vty_aaa].include?(item.id) && item.status != :not_applicable && !item.expected.nil? }
      related.each do |item|
        conflict! if item.id == "ssh.vty_aaa" ? item.expected != true : item.expected != (methods.first["kind"] == "tacacs")
        rule = @policy.rules.find { |candidate| candidate.id == item.id }
        if rule.remediation["syntax_profile"] == "nxos"
          flags = %w[management_consumers_verified local_fallback_access_verified]
          flags += %w[tacacs_peer_compatibility_verified local_fallback_on_error] if methods.first["kind"] == "tacacs"
          conflict! if flags.any? { |key| rule.remediation[key] == false }
        end
        if item.status != :pass && rule.remediation["syntax_profile"] == "nxos" && rule.remediation.key?("methods")
          conflict! unless rule.remediation["methods"] == methods
        end
      end
    end

    # 现有地址成员逐个关联相同身份的材料；原生组的 VRF/source 等保持原样，由外部对端核验覆盖运行路径。
    def verify_targets!(evidence, methods)
      require!(%w[tacacs.servers tacacs.groups tacacs.group_references tacacs.endpoints].all? { |fact| evidence.fact_known?(fact) }, "resolved_tacacs_reference_inventory")
      methods.select { |method| method["kind"] == "tacacs" }.each do |method|
        group = method.fetch("group")
        refs = evidence.fact("tacacs.group_references")[group]
        addresses = if group == "tacacs+"
          evidence.fact("tacacs.servers")
        else
          require!(refs && refs.any? && refs.all? { |ref| ref[:kind] == "address" && ref[:complete] }, "resolved_native_tacacs_group_members")
          refs.flat_map { |ref| ref[:servers] }.uniq
        end
        require!(addresses.any?, "resolved_tacacs_role_endpoints")
        addresses.each do |address|
          targets = evidence.fact("tacacs.endpoints").select { |target| target["identity"] == { "address" => address } }
          require!(targets.any? && targets.all? { |target| target["attributes"]["key_present"] == true }, "existing_tacacs_endpoint_key")
        end
      end
    end
  end
end

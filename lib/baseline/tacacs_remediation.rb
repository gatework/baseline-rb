# frozen_string_literal: true

require_relative "target_remediation"
require_relative "tacacs_operation_schema"

module Baseline
  # HWTACACS 端点变化保留方案、密钥及所有域引用，主槽位替换不拆成独立删除。
  class TacacsRemediation < TargetRemediation
    IDS = %w[tacacs.minimum_servers tacacs.servers tacacs.endpoints].freeze
    KIND = "tacacs.endpoint"

    def call(_finding, audit)
      findings = audit.findings.select { |item| IDS.include?(item.id) && item.status != :not_applicable }
      approved = findings.find { |item| item.id == "tacacs.endpoints" }
      unless approved&.expected
        raise Blocked.new(:unresolved_prerequisites, requirements: [ "approved_tacacs_endpoints" ])
      end
      rule = @policy.rules.find { |item| item.id == "tacacs.endpoints" }
      raise Blocked, :approved_scope_required unless rule.managed_scopes
      options = rule.remediation
      required = []
      required << "syntax_profile" unless options["syntax_profile"] == "comware7"
      %w[local_fallback_access_verified tacacs_key_compatibility_verified].each { |key| required << key unless options[key] == true }
      raise Blocked.new(:unresolved_prerequisites, requirements: required) if required.any?
      evidence = audit.configuration
      unless evidence.fact_known?("tacacs.endpoints") && evidence.fact_known?("tacacs.schemes") && evidence.fact_known?("aaa.domain_bindings")
        raise Blocked.new(:resource_unresolved, requirements: [ "resolved_tacacs_reference_inventory" ])
      end
      current = evidence.fact("tacacs.endpoints")
      schemes = evidence.fact("tacacs.schemes")
      bindings = domain_bindings(evidence, schemes)
      managed = rule.managed_scopes
      touched = current.select { |object| managed.include?(object["scope"]) }
      targets = approved.expected
      groups = managed.filter_map { |scope| scope["group"] }
      (current.select { |object| groups.include?(object["scope"]["group"]) } + targets).each { |object| validate_context(object, schemes) }
      desired = targets.map { |object| desired_object(object, touched, bindings) }
      projected = current.reject { |object| managed.include?(object["scope"]) } + desired
      validate_transition_identity!(touched, desired)
      validate_projected(projected.select { |object| groups.include?(object["scope"]["group"]) })
      check_constraints!(findings, projected)
      preserve_references!(projected, bindings)
      risk = findings.any? { |item| item.severity == "critical" } ? "critical" : "high"
      operations = primary_operations(touched, desired, risk) + secondary_operations(touched, desired, risk)
      raise Blocked, :resource_unresolved if operations.empty?
      verify_keys!(operations, evidence)
      operations, details = order_for_capacity(operations, current, projected, findings)
      ordered = operations.sort_by { |item| { prepare: 0, create: 1, update: 2, remove: 3 }.fetch(item.phase) }
      verify_transition!(current, ordered, bindings)
      Result.new(operations: ordered.freeze, details: CtxParser::Immutable.copy(details.merge(
        shared_domain_references: bindings.values.sum(&:size), primary_replacements: ordered.count { |operation| operation.kind == "tacacs.primary" && operation.action == :replace })))
    end

    private

    # 只读取已解析的方法和组身份，端点缺失可由新增修复，未知方法不能推测。
    def domain_bindings(evidence, schemes)
      rows = evidence.fact("aaa.domain_bindings")
      known = rows.all? do |row|
        row[:domain] && row[:methods].any? && row[:reason] != :vty_authentication_unknown &&
          row[:references].all? { |reference| schemes.key?(reference[:group]) }
      end
      raise Blocked.new(:resource_unresolved, requirements: [ "resolved_tacacs_reference_inventory" ]) unless known
      rows.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |row, index|
        row[:references].each do |reference|
          position = row[:methods].index { |method| method[:kind] == "tacacs" && method[:group].casecmp?(reference[:group]) }
          index[[ reference[:group], row[:role] ]] << { "kind" => "aaa.domain", "domain" => row[:domain], "role" => row[:role],
            "position" => position.zero? ? "primary" : "fallback", "selected" => row[:selected] }
        end
      end
    end

    # 当前实现不创建新方案，也不复制未建模路由、显式阻断或多端口别名。
    def validate_context(object, schemes)
      identity, scope = object.values_at("identity", "scope")
      unless identity.keys.sort == %w[address priority role] && %w[primary secondary].include?(identity["priority"]) &&
          TacacsOperationSchema::ROLES.include?(identity["role"]) && scope.keys.sort == %w[group vrf] && scope["vrf"] == "default" &&
          schemes[scope["group"]]&.fetch(:target_context_supported, false)
        raise Blocked.new(:tacacs_context_unresolved, requirements: [ "existing_default_routing_scheme", "unambiguous_tacacs_endpoint_identity" ])
      end
      address = IPAddr.new(identity["address"])
      invalid = identity["address"].include?("/") || address.to_i.zero? || address.ipv4? && (IPAddr.new("224.0.0.0/4").include?(address) || address.to_i == 4_294_967_295) || address.ipv6? && IPAddr.new("ff00::/8").include?(address)
      raise Blocked, :unsupported_tacacs_target if invalid
    rescue IPAddr::Error
      raise Blocked, :unsupported_tacacs_target
    end

    def slot(object) = [ object["scope"]["group"], object["identity"]["role"] ]

    # 省略参数保留原槽位的非秘密设置；新增备服务器不借用其他主机的参数。
    def desired_object(object, current, bindings)
      before = if object["identity"]["priority"] == "primary"
        current.find { |entry| entry["identity"]["priority"] == "primary" && slot(entry) == slot(object) }
      else
        current.find { |entry| key(entry) == key(object) }
      end
      attributes = (before ? before.fetch("attributes", {}) : {}).merge(object.fetch("attributes", {}))
      parameters = normalized_parameters(object.merge("attributes" => attributes))
      references = ResourceBindings.normalize(bindings[slot(object)])
      if object.key?("bindings") && ResourceBindings.compare(references, object["bindings"]).values.any?(&:any?)
        raise Blocked.new(:tacacs_binding_change_required, requirements: [ "approved_reference_migration" ])
      end
      object.merge("attributes" => parameters.except("address", "vrf"), "bindings" => references)
    end

    def normalized_parameters(object)
      attributes = object.fetch("attributes", {})
      unless (attributes.keys - %w[port single_connection]).empty?
        raise Blocked, :unsupported_tacacs_options
      end
      { "address" => object["identity"]["address"], "vrf" => object["scope"]["vrf"],
        "port" => attributes.fetch("port", 49), "single_connection" => attributes.fetch("single_connection", false) }
    end

    # 主备不能指向相同原生端点；每个主槽位只允许一个目标。
    def validate_projected(objects)
      primary = objects.select { |object| object["identity"]["priority"] == "primary" }
      raise Blocked, :policy_conflict unless primary.map { |object| slot(object) }.uniq.size == primary.size
      native = objects.map { |object| [ *slot(object), object["scope"]["vrf"], IPAddr.new(object["identity"]["address"]).to_s, object.fetch("attributes", {}).fetch("port", 49) ] }
      raise Blocked, :policy_conflict unless native.uniq.size == native.size
      objects.select { |object| object["identity"]["priority"] == "secondary" }.group_by { |object| slot(object) }.each_value do |entries|
        raise Blocked, :capacity_exceeded if entries.size > 16
      end
    rescue IPAddr::Error
      raise Blocked, :unsupported_tacacs_target
    end

    # 原生地址相同但文本或主备身份不同，不能用独立新增/删除表达迁移。
    def validate_transition_identity!(current, desired)
      native_key = ->(object) { [ object["scope"], object["identity"]["role"], IPAddr.new(object["identity"]["address"]).to_s ] }
      existing = current.group_by(&native_key)
      desired.each do |target|
        existing.fetch(native_key.call(target), []).each do |old|
          if old["identity"] != target["identity"]
            raise Blocked.new(:tacacs_context_unresolved, requirements: [ "unambiguous_tacacs_endpoint_identity" ])
          end
        end
      end
    end

    def preserve_references!(objects, bindings)
      bindings.each do |identity, references|
        next if references.empty?
        raise Blocked, :tacacs_reference_would_break unless objects.any? { |object| slot(object) == identity }
      end
    end

    def primary_operations(current, desired, risk)
      before = current.select { |object| object["identity"]["priority"] == "primary" }.to_h { |object| [ slot(object), object ] }
      after = desired.select { |object| object["identity"]["priority"] == "primary" }.to_h { |object| [ slot(object), object ] }
      (before.keys | after.keys).filter_map do |identity|
        old, target = before[identity], after[identity]
        previous, following = old && normalized_parameters(old), target && normalized_parameters(target)
        next if previous == following
        action = old.nil? ? :add : target.nil? ? :remove : :replace
        ConfigurationOperation.new(kind: "tacacs.primary", identity: { "role" => identity.last }, scope: { "group" => identity.first },
          before: previous, after: following, action: action, phase: { add: :create, remove: :remove, replace: :update }.fetch(action), risk: risk)
      end
    end

    def secondary_operations(current, desired, risk)
      before = current.select { |object| object["identity"]["priority"] == "secondary" }.to_h { |object| [ key(object), object ] }
      after = desired.select { |object| object["identity"]["priority"] == "secondary" }.to_h { |object| [ key(object), object ] }
      (before.keys | after.keys).filter_map do |identity|
        old, target = before[identity], after[identity]
        previous, following = old && normalized_parameters(old), target && normalized_parameters(target)
        next if previous == following
        raise Blocked, :unsupported_tacacs_port_transition if old && target && previous["port"] != following["port"]
        action = old.nil? ? :add : target.nil? ? :remove : :replace
        parameters = following || previous
        ConfigurationOperation.new(kind: "tacacs.secondary", identity: { "role" => (target || old)["identity"]["role"], **parameters.except("single_connection") },
          scope: { "group" => (target || old)["scope"]["group"] }, before: previous && previous.slice("single_connection"), after: following && following.slice("single_connection"),
          action: action, phase: { add: :create, remove: :remove, replace: :update }.fetch(action), risk: risk)
      end
    end

    def verify_keys!(operations, evidence)
      slots = evidence.fact("tacacs.key_slots")
      operations.select(&:after).each do |operation|
        known = evidence.fact_known?("tacacs.key_slots") && slots.any? do |entry|
          entry[:group] == operation.scope["group"] && entry[:role] == operation.identity["role"] && entry[:complete] && entry[:present] == true
        end
        raise Blocked.new(:tacacs_key_dependency, requirements: [ "existing_scheme_role_key" ]) unless known
      end
    end

    # 只保护变更前已有的域路径；修复原本缺失的端点不被误当作主动断开。
    def verify_transition!(current, operations, bindings)
      touched = operations.map { |operation| [ operation.scope["group"], operation.identity["role"] ] }
      live = current.select { |object| touched.include?(slot(object)) }.map { |object| [ slot(object), object["identity"]["priority"], normalized_parameters(object) ] }
      protected = bindings.keys.select { |identity| bindings[identity].any? && live.any? { |entry| entry.first == identity } }
      operations.each do |operation|
        identity = [ operation.scope["group"], operation.identity["role"] ]
        reset = operation.action == :replace && operation.before["single_connection"] && !operation.after["single_connection"]
        if reset && protected.include?(identity) && live.count { |entry| entry.first == identity } < 2
          raise Blocked, :tacacs_transition_would_disconnect
        end
        primary = operation.kind == "tacacs.primary"
        live.reject! do |entry|
          entry.first == identity && (primary ? entry[1] == "primary" : entry[1] == "secondary" && entry[2].slice("address", "port", "vrf") == operation.identity.except("role"))
        end
        if operation.after
          parameters = primary ? operation.after : operation.identity.except("role").merge(operation.after)
          live << [ identity, primary ? "primary" : "secondary", parameters ]
        end
        secondary_count = live.count { |entry| entry.first == identity && entry[1] == "secondary" }
        raise Blocked, :capacity_exceeded if secondary_count > 16
        raise Blocked, :tacacs_transition_would_disconnect unless protected.all? { |role| live.any? { |entry| entry.first == role } }
      end
    end
  end
end

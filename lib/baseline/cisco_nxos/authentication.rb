# frozen_string_literal: true

require_relative "../nxos_aaa_methods"

module Baseline
  module CiscoNxos
    # 原生默认方法、独立后备与命令/配置命令授权分别归约，不套用 IOS 的逐线登录列表。
    module Authentication
      private

      def prepare_configuration
        super
        @nxos_aaa_graph = nil
        @nxos_features = {}
      end

      def nxos_feature_state(name, default: nil)
        key = [ name, default ]
        return @nxos_features[key] if @nxos_features.key?(key)
        entry = matching_blocks(/\A(?:no )?feature #{Regexp.escape(name)}(?:\s|\z)/).last
        value = if entry
          case entry.text
          when "feature #{name}" then analyze(entry) { true }
          when "no feature #{name}" then analyze(entry) { false }
          else
            fact = { "ssh" => "ssh.enabled", "telnet" => "services.telnet", "tacacs+" => "tacacs" }.fetch(name)
            record_unknown_fact(fact, [ entry ], code: :unsupported_authentication_method)
            nil
          end
        elsif @fact_builder.complete?
          default
        end
        @nxos_features[key] = value
      end

      # SSH 缺省稳定；Telnet 缺省跨 Nexus 产品不同，缺显式声明时继续未知。
      def nxos_remote_protocols
        ssh, telnet = nxos_feature_state("ssh", default: true), nxos_feature_state("telnet")
        return if ssh.nil? || telnet.nil?
        values = []
        values << "ssh" if ssh
        values << "telnet" if telnet
        values.empty? ? [ "none" ] : values
      end

      def configured_vty_login(section, default_aaa:)
        foreign = matching_blocks(/\A(?:no )?(?:login|transport input)(?:\s|\z)/, section.children)
        if foreign.any?
          record_unknown_fact("ssh.vty_aaa", foreign, code: :unsupported_authentication_method)
          record_unknown_fact("tacacs.login", foreign, code: :unsupported_authentication_method)
        end
        state = nxos_method_state("aaa authentication login default", "authentication")
        account = state["complete"] && state["methods"].none? { |method| method["kind"] == "none" }
        { authentication: foreign.any? || !state["complete"] ? nil : account ? "aaa" : "none", authentication_list: "default" }
      end

      # 后备行不参与主列表覆盖；撤销独立控制也不能清除现有服务器组。
      def nxos_method_state(prefix, role)
        state = { "methods" => [ { "kind" => "local" } ], "declared" => false, "complete" => @fact_builder.complete?, "lines" => [] }
        matching_blocks(/\A(?:no )?#{Regexp.escape(prefix)}(?:\s|\z)/).each do |entry|
          text = entry.text.delete_prefix("no ")
          tail = text.delete_prefix(prefix).strip
          next if role == "authentication" && (tail == "fallback" || tail.start_with?("fallback "))
          methods = NxosAaaMethods.parse(tail, role: role)
          negative = entry.text.start_with?("no ")
          if methods || negative && tail.empty?
            analyze(entry) { true }
            state = { "methods" => negative ? [ { "kind" => "local" } ] : methods, "declared" => !negative, "complete" => true, "lines" => [ entry.line ] }
          else
            state = { "methods" => [], "declared" => true, "complete" => false, "lines" => [ entry.line ] }
          end
        end
        state
      end

      def nxos_login_state(selector)
        node = nxos_method_state("aaa authentication login #{selector}", "authentication")
        fallback, lines = @fact_builder.complete? ? true : nil, []
        matching_blocks(/\A(?:no )?aaa authentication login #{selector} fallback(?:\s|\z)/).each do |entry|
          fallback = case entry.text
          when "aaa authentication login #{selector} fallback error local" then analyze(entry) { true }
          when "no aaa authentication login #{selector} fallback error local" then analyze(entry) { false }
          end
          lines = [ entry.line ]
        end
        node.merge("fallback_on_error" => fallback, "fallback_lines" => lines, "complete" => node["complete"] && !fallback.nil?)
      end

      def nxos_resolve_methods(node, servers, inventory)
        complete = node["complete"]
        methods = node["methods"].map do |method|
          next method unless method["kind"] == "server_group"
          name = method["group"]
          known = name == "tacacs+" ? servers.any? && !@fact_builder.unresolved?("tacacs.servers") :
            inventory.closed && inventory.groups.fetch(name, []).any? && inventory.references.fetch(name, []).all? { |reference| reference[:complete] }
          if known
            { "kind" => "tacacs", "group" => name }
          elsif name == "radius"
            { "kind" => "radius" }
          else
            complete = false
            { "kind" => "unresolved" }
          end
        end
        node.merge("methods" => methods, "complete" => complete)
      end

      def record_tacacs_login_usage(servers, inventory)
        authentication = %w[default console].to_h { |selector| [ selector, nxos_resolve_methods(nxos_login_state(selector), servers, inventory) ] }
        authorization = %w[commands config-commands].to_h do |action|
          [ action, nxos_resolve_methods(nxos_method_state("aaa authorization #{action} default", "authorization"), servers, inventory) ]
        end
        accounting = nxos_resolve_methods(nxos_method_state("aaa accounting default", "accounting"), servers, inventory)
        unsupported = matching_blocks(/\A(?:no )?aaa (?:authentication login|authorization|accounting)(?:\s|\z)/).reject do |entry|
          /\A(?:no )?aaa (?:authentication login (?:default|console|ascii-authentication|error-enable|invalid-username-log|(?:mschap|mschapv2|chap) enable)(?:\s|\z)|authorization (?:commands|config-commands) default(?:\s|\z)|accounting (?:default|dot1x)(?:\s|\z))/.match?(entry.text)
        end
        foreign = matching_blocks(/\Aline vty(?:\s|\z)/).flat_map do |section|
          matching_blocks(/\A(?:no )?(?:login|transport input)(?:\s|\z)/, section.children)
        end
        scope_complete = unsupported.empty? && foreign.empty?
        @nxos_aaa_graph = CtxParser::Immutable.copy({ "authentication" => authentication, "authorization" => authorization,
          "accounting" => { "default" => accounting }, "scope_complete" => scope_complete, "tacacs_enabled" => nxos_feature_state("tacacs+", default: false) })
        record_fact("aaa.nxos", @nxos_aaa_graph)
        record_unknown_fact("aaa.nxos", unsupported + foreign, code: :unsupported_authentication_method) unless scope_complete
        node = authentication.fetch("default")
        nxos_record_usage("tacacs.login", [ node ], scope_complete: scope_complete)
        if node["complete"]
          record_fact("ssh.vty_aaa", node["methods"].none? { |method| method["kind"] == "none" })
        else
          record_unknown_fact("ssh.vty_aaa", code: :authentication_list_unresolved)
        end
        if (protocols = nxos_remote_protocols)
          record_fact("ssh.vty_ssh_only", protocols == [ "ssh" ])
        end
      end

      def record_tacacs_action_usage(kind, _servers, _inventory)
        nodes = @nxos_aaa_graph.fetch(kind).values
        nxos_record_usage("tacacs.#{kind}", nodes, scope_complete: @nxos_aaa_graph["scope_complete"])
      end

      def nxos_record_usage(fact, nodes, scope_complete:)
        feature = @nxos_aaa_graph["tacacs_enabled"]
        if !scope_complete || nodes.empty? || nodes.any? { |node| !node["complete"] } || feature.nil?
          record_unknown_fact(fact, code: :tacacs_group_unresolved)
        else
          used = feature && nodes.all? { |node| node["methods"].first&.fetch("kind") == "tacacs" }
          lines = nodes.flat_map { |node| node["lines"] }
          entries = roots.select { |entry| lines.include?(entry.line) }
          record_fact(fact, used, entries)
        end
      end
    end
  end
end

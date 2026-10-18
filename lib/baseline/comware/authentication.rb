# frozen_string_literal: true

module Baseline
  module Comware
    # 归约管理域的方法、共享方案引用及选中域的 VTY 关系，不保留原始命令。
    module Authentication
      private

      # 标量检查与审核依赖共用同一份引用证据，不能各自猜测使用链。
      def record_authentication_bindings(schemes)
        domain = authentication_binding_domain
        endpoints = @fact_builder.resources_for("tacacs.endpoint")
        lookup = { schemes: schemes.group_by { |name, _| name.downcase },
          endpoints: endpoints.group_by { |resource| [ resource[:scope]["group"].downcase, resource[:identity]["role"] ] },
          unresolved: @fact_builder.unresolved?("tacacs.servers") || @fact_builder.unresolved?("tacacs.endpoints") }
        selected = authentication_bindings_for(domain, lookup, selected: true)
        others = authentication_binding_inventory.reject { |entry| entry[:name]&.casecmp?(domain[:name].to_s) }
          .flat_map { |entry| authentication_bindings_for(entry, lookup, selected: false) }
        inventory = selected + others
        complete = %w[authentication authorization accounting].to_h do |role|
          rows = inventory.select { |binding| binding[:role] == role }
          [ role, @fact_builder.complete? && rows.all? { |binding| binding[:methods].any? && binding[:references].all? { |reference| reference[:resolved] } } ]
        end
        @fact_builder.record_authentication_graph(bindings: inventory, completeness: complete)
        record_tacacs_domain_bindings(endpoints, inventory, complete)
        selected.each do |binding|
          fact = "tacacs.#{binding[:role] == 'authentication' ? 'login' : binding[:role]}"
          if binding[:uses_tacacs].nil?
            @fact_builder.record_unknown_fact(fact, lines: binding[:lines], code: binding[:reason])
          elsif @fact_builder.complete? || binding[:uses_tacacs]
            @fact_builder.record_fact(fact, binding[:uses_tacacs], lines: binding[:lines])
          end
        end
      end

      # 引用库存按定义一次归约，未选中域也必须保护其共享服务器组。
      def authentication_binding_inventory
        active = {}
        authentication_domain_entries.each do |entry|
          next if /\A(?:undo )?domain (?:default enable|if-unknown)(?:\s|\z)/.match?(entry.text)
          match = /\A(undo )?domain(?: name)? (\S+)\z/.match(entry.text)
          if match && ResourceSchema.token?(match[2])
            name = match[2]
            if match[1]
              active.delete(name.downcase)
            else
              item = active[name.downcase] ||= { name: name, sections: [], valid: true }
              item[:sections] << entry
            end
          elsif (family = /\A(?:undo )?domain(?: name)? (\S+)(?:\s|\z)/.match(entry.text))
            name = ResourceSchema.token?(family[1]) ? family[1] : nil
            item = active[name&.downcase] ||= { name: name, sections: [], valid: false }
            item[:valid] = false
          elsif /\A(?:undo )?domain(?:\s|\z)/.match?(entry.text)
            active[nil] = { name: nil, sections: [], valid: false }
          end
        end
        active.values.map do |item|
          { name: item[:name], entries: item[:sections].flat_map(&:children), lines: item[:sections].map(&:line),
            complete: item[:valid], reason: item[:valid] ? nil : :authentication_domain_unresolved }
        end
      end

      # 管理域库存所在层级由厂商选择，不能从接口或其他子视图提取全局域。
      def authentication_domain_entries = roots

      # 只有对应职责的引用库存明确时才提供 bindings；nil 与已知空数组不同。
      def record_tacacs_domain_bindings(endpoints, inventory, complete)
        uses = Hash.new { |index, key| index[key] = [] }
        inventory.each do |row|
          row[:references].each do |reference|
            position = row[:methods].index { |method| method[:kind] == "tacacs" && method[:group].casecmp?(reference[:group]) }
            next unless position && row[:domain]
            binding = { "kind" => "aaa.domain", "domain" => row[:domain], "role" => row[:role],
              "position" => position.zero? ? "primary" : "fallback", "selected" => row[:selected] }
            uses[[ reference[:group].downcase, row[:role] ]] << [ binding, row[:lines] ]
          end
        end
        endpoints.each do |resource|
          role, group = resource[:identity]["role"], resource[:scope]["group"]
          next unless complete[role]
          links = uses[[ group.downcase, role ]]
          @fact_builder.record_resource_bindings(kind: resource[:kind], identity: resource[:identity], scope: resource[:scope],
            bindings: links.map(&:first), lines: (resource[:lines] + links.flat_map(&:last)).uniq)
        end
      end

      # 选中域执行额外 VTY 核验，其他域仅归纳配置引用而不声称当前管理路径可用。
      def authentication_bindings_for(domain, lookup, selected:)
        %w[authentication authorization accounting].map do |role|
          chain = domain[:complete] ? authentication_binding_chain(role, domain) : { methods: nil, lines: [], reason: domain[:reason] }
          methods = chain[:methods]
          references = methods.to_a.filter_map do |method|
            next unless method[:kind] == "tacacs"
            matches = lookup[:schemes].fetch(method[:group].downcase, [])
            definition = matches.one? ? matches.first.last : nil
            servers = definition && definition[:server_types].fetch(role, [])
            group = matches.one? ? matches.first.first : method[:group]
            resources = lookup[:endpoints].fetch([ group.downcase, role ], [])
            resolved = !servers.to_a.empty? && resources.any? && resources.all? { |resource| resource[:complete] } &&
              !lookup[:unresolved]
            { group: group, role: role, servers: servers || [], resolved: resolved,
              endpoints: resources.map { |resource| resource.slice(:identity, :scope, :lines, :complete) },
              lines: [ *(definition ? [ definition[:line] ] : []), *resources.flat_map { |resource| resource[:lines] } ].uniq }
          end
          reason = chain[:reason]
          reason ||= :tacacs_scheme_unresolved if references.any? { |reference| !reference[:resolved] }
          used = reason ? nil : methods.first[:kind] == "tacacs"
          vtys = selected && role == "authentication" ? authentication_binding_vtys : []
          if used && selected && role == "authentication"
            if vtys.any? { |vty| vty[:authentication] && !%w[scheme aaa].include?(vty[:authentication]) }
              used = false
            elsif vtys.empty? || vtys.any? { |vty| !vty[:complete] }
              used, reason = nil, :vty_authentication_unknown
            end
          end
          lines = [ *domain[:lines], *chain[:lines], *references.flat_map { |reference| reference[:lines] }, *vtys.map { |vty| vty[:line] } ].uniq
          { domain: domain[:name], selected: selected, role: role, scheme: chain[:scheme], methods: methods || [], references: references,
            local_fallback: methods && methods.first[:kind] == "tacacs" && methods.drop(1).any? { |method| method[:kind] == "local" },
            allows_none: methods && methods.any? { |method| method[:kind] == "none" }, inherited: chain[:inherited] || false,
            vtys: vtys, uses_tacacs: used, complete: reason.nil?, reason: reason, lines: lines }
        end
      end

      # VTY 名称只有明确范围语法才进入绑定图，未知状态不能充当 AAA 证明。
      def authentication_binding_vtys
        @fact_builder.vtys.map do |vty|
          name = vty[:name] if /\A(?:line|user-interface) vty [0-9]+(?: [0-9]+)?\z/.match?(vty[:name])
          { name: name, authentication: vty[:authentication], line: vty[:line], complete: !name.nil? && !vty[:authentication].nil? }
        end
      end

      # 最后一次域选择决定作用域；恢复默认后也必须解析对应域，不能沿用旧域。
      def authentication_binding_domain
        entry = matching_blocks(/\A(?:undo )?domain default enable(?:\s|\z)/).last
        name = if entry&.text == "undo domain default enable" || entry.nil? && @fact_builder.complete?
          "system"
        else
          entry&.text&.[](/\Adomain default enable (\S+)\z/, 1)
        end
        selected_authentication_domain(name, roots, lines: entry ? [ entry.line ] : [])
      end

      # 同名域或方案支持重新进入，整段撤销必须清除其旧子命令。
      def authentication_named_sections(entries, command, name)
        sections, valid = [], true
        optional = command == "domain" ? "(?: name)?" : ""
        pattern = /\A(undo )?#{Regexp.escape(command)}#{optional} (\S+)\z/
        entries.each do |entry|
          match = pattern.match(entry.text)
          if match && match[2].casecmp?(name)
            if match[1]
              sections.clear
              valid = true
            else
              sections << entry
            end
          elsif /\A(?:undo )?#{Regexp.escape(command)}#{optional} #{Regexp.escape(name)}(?:\s|\z)/i.match?(entry.text)
            valid = false
          end
        end
        [ sections, valid ]
      end

      # 缺失选中对象是未解析引用，不是已经确定“不使用 TACACS”。
      def selected_authentication_domain(name, entries, lines:)
        return { name: nil, entries: [], lines: lines, complete: false, reason: :authentication_domain_unknown } unless ResourceSchema.token?(name)

        sections, valid = authentication_named_sections(entries, "domain", name)
        { name: name, entries: sections.flat_map(&:children), lines: [ *lines, *sections.map(&:line) ].uniq,
          complete: valid && sections.any?, reason: valid && sections.any? ? nil : :authentication_domain_unresolved }
      end

      # login 撤销恢复域 default；缺省或 default 撤销采用已建模的本地方法。
      def authentication_binding_chain(role, domain)
        entries = domain[:entries]
        login = matching_blocks(/\A(?:undo )?#{role} login(?:\s|\z)/, entries).last
        inherited = login.nil? || login.text == "undo #{role} login"
        entry = inherited ? matching_blocks(/\A(?:undo )?#{role} default(?:\s|\z)/, entries).last : login
        lines = [ login, entry ].compact.map(&:line).uniq
        if entry.nil? || entry.text == "undo #{role} default"
          return { methods: [ { kind: "local" } ], lines: lines, inherited: true }
        end
        match = /\A#{role} (?:login|default) (.+)\z/.match(entry.text)
        methods = match && comware_authentication_methods(match[1], role)
        analyze(entry) { true } if methods
        { methods: methods, lines: lines, inherited: inherited, reason: methods ? nil : :unsupported_authentication_method }
      end

      # 参数按位置消费，只允许文档中的有序方法组合，未知尾部不进入图。
      def comware_authentication_methods(text, role)
        tokens, methods = text.split, []
        until tokens.empty?
          token = tokens.shift
          if %w[local none].include?(token)
            methods << { kind: token }
          elsif %w[hwtacacs-scheme radius-scheme ldap-scheme].include?(token)
            name = tokens.shift
            return unless ResourceSchema.token?(name)
            methods << { kind: { "hwtacacs-scheme" => "tacacs", "radius-scheme" => "radius", "ldap-scheme" => "ldap" }.fetch(token), group: name }
          else
            return
          end
        end
        kinds = methods.map { |method| method[:kind] }
        return unless kinds.any? && kinds.uniq == kinds
        grammar = /\A(?:(?:tacacs(?:,radius)?|radius(?:,tacacs)?)(?:,local)?|local(?:,(?:tacacs(?:,radius)?|radius(?:,tacacs)?))?|none)(?:,none)?\z/
        return methods if grammar.match?(kinds.join(","))
        methods if role == "authentication" && /\A(?:ldap(?:,local)?|local,ldap)(?:,none)?\z/.match?(kinds.join(","))
      end
    end
  end
end

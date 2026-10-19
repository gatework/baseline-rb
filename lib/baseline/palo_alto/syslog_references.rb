# frozen_string_literal: true

module Baseline
  module PaloAlto
    # 日志服务器 profile、转发匹配项和规则消费者分别归约；不保留过滤式或动作秘密。
    module SyslogReferences
      private

      # 绑定是配置引用证据；规则日志标志仅在显式声明时保留，不推断运行时投递。
      def record_syslog_bindings
        @syslog_references_closed = @fact_builder.complete?
        @syslog_reference_unresolved = []
        roots.select { |entry| /\Aset (?:template|device-group|panorama)(?:\s|\z)/.match?(entry.text) }.each { |entry| unresolved_syslog_reference(entry) }
        references, forwarding, lines = {}, {}, Hash.new { |hash, key| hash[key] = [] }
        declared = Hash.new(0)
        rows = statements_with_prefix("shared", "log-settings")
        rows.reject { |row| supported_syslog_reference_path?(row[:tokens]) }.each { |row| unresolved_syslog_reference(row[:entry]) }
        matches = rows.select { |row| row[:tokens][3] == "match-list" || row[:tokens][2] == "profiles" && row[:tokens][4] == "match-list" }
          .group_by { |row| row[:tokens].take(row[:tokens][2] == "profiles" ? 6 : 5) }
        matches.each do |path, entries|
          profile = path[2] == "profiles" ? path[3] : nil
          match = path.last
          type = profile ? final_syslog_log_type(entries, path.size) : path[2]
          allowed = profile ? ResourceBindings::SYSLOG_FORWARD_TYPES : ResourceBindings::SYSLOG_DEVICE_TYPES
          unless ResourceSchema.name?(match) && (!profile || ResourceSchema.name?(profile)) && allowed.include?(type)
            unresolved_syslog_reference(*entries.map { |row| row[:entry] })
            next
          end
          receivers = entries.select { |row| row[:tokens][path.size] == "send-syslog" }.flat_map do |row|
            syslog_reference_values(row[:tokens].drop(path.size + 1), row[:entry])
          end.uniq
          receivers.each { |receiver| declared[receiver] += 1 }
          if profile
            (forwarding[profile] ||= []) << { match: match, log_type: type, receivers: receivers, lines: entries.map { |row| row[:entry].line } }
          else
            receivers.each do |receiver|
              (references[receiver] ||= []) << { "kind" => "syslog.device", "log_type" => type, "match" => match }
              lines[receiver].concat(entries.map { |row| row[:entry].line })
            end
          end
        end
        # 空的转发 profile 仍是已知定义；未挂接的 profile 不成为已使用链。
        rows.select { |row| row[:tokens][2] == "profiles" && ResourceSchema.name?(row[:tokens][3]) }.each { |row| forwarding[row[:tokens][3]] ||= [] }
        record_syslog_rule_consumers(forwarding, references, lines)
        record_syslog_zone_consumers(forwarding, references, lines)
        statements_with_prefix("vsys").select { |row| row[:tokens][2] == "log-settings" }.each { |row| unresolved_syslog_reference(row[:entry]) }
        statements_with_prefix("log-settings").each { |row| unresolved_syslog_reference(row[:entry]) }
        statements_with_prefix("profiles").select { |row| row[:tokens].drop(3).include?("log-setting") }.each { |row| unresolved_syslog_reference(row[:entry]) }
        record_fact("syslog.profile_references", references.transform_values { |values| ResourceBindings.normalize(values.uniq) })
        record_fact("syslog.declared_profile_references", declared)
        record_fact("syslog.reference_inventory_complete", @syslog_references_closed)
        unless @syslog_references_closed
          %w[syslog.profile_references syslog.declared_profile_references].each do |fact|
            record_unknown_fact(fact, @syslog_reference_unresolved.uniq, code: :syslog_reference_inventory_unresolved)
          end
        end
        @fact_builder.resources_for("syslog.destination").each do |resource|
          profile = resource[:scope]["profile"]
          bindings = @syslog_references_closed ? references.fetch(profile, []).uniq : nil
          @fact_builder.record_resource_bindings(kind: "syslog.destination", identity: resource[:identity], scope: resource[:scope],
            bindings: bindings, lines: resource[:lines] + lines[profile])
        end
      end

      # zone 的日志消费者独立于规则；只采用最后一次 profile 选择，不推定日志事件存在。
      def record_syslog_zone_consumers(forwarding, references, lines)
        consumers = (statements_with_prefix("zone") + statements_with_prefix("vsys")).filter_map do |row|
          tokens = row[:tokens]
          context, vsys, path = tokens.first == "vsys" ? [ "vsys", tokens[1], tokens.drop(2) ] : [ "local", nil, tokens ]
          next unless path.first == "zone"
          unless path[2..3] == %w[network log-setting]
            unresolved_syslog_reference(row[:entry]) if path[2] == "log-setting"
            next
          end
          { context: context, vsys: vsys, zone: path[1], values: path.drop(4), entry: row[:entry] }
        end.group_by { |row| row.values_at(:context, :vsys, :zone) }.values.map(&:last)
        consumers.each do |row|
          profile = row[:values].first
          unless row[:values].one? && ResourceSchema.name?(row[:zone]) && (row[:context] == "local" || ResourceSchema.name?(row[:vsys])) && forwarding.key?(profile)
            unresolved_syslog_reference(row[:entry])
            next
          end
          forwarding.fetch(profile).each do |match|
            binding = { "kind" => "syslog.zone", "forwarding_profile" => profile, "match" => match[:match], "log_type" => match[:log_type],
              "context" => row[:context], "zone" => row[:zone] }
            binding["vsys"] = row[:vsys] if row[:context] == "vsys"
            match[:receivers].each do |receiver|
              (references[receiver] ||= []) << binding
              lines[receiver].concat(match[:lines] + [ row[:entry].line ])
            end
          end
        end
      end

      # 不可解析的配置只保留来源行，便于人工定位，不把原文或尾部写进公开诊断。
      def unresolved_syslog_reference(*entries)
        @syslog_references_closed = false
        @syslog_reference_unresolved.concat(entries)
      end

      # 只排除已证明与引用无关的通知对象族；旧式或未知日志路径不能冒充没有引用。
      def supported_syslog_reference_path?(tokens)
        branch = tokens[2]
        return true if %w[syslog snmptrap email http].include?(branch)
        fields = %w[description filter send-to-panorama send-snmptrap send-email send-syslog send-http quarantine actions]
        if branch == "profiles"
          return false unless ResourceSchema.name?(tokens[3])
          return true if tokens.size == 4 || tokens[4] == "enhanced-application-logging"
          tokens[4] == "match-list" && ResourceSchema.name?(tokens[5]) && (tokens.size == 6 || (fields + [ "log-type" ]).include?(tokens[6]))
        elsif ResourceBindings::SYSLOG_DEVICE_TYPES.include?(branch)
          tokens.size == 3 || tokens[3] == "match-list" && ResourceSchema.name?(tokens[4]) && (tokens.size == 5 || fields.include?(tokens[5]))
        else false
        end
      end

      # list 的 set 形式按成员累加；畸形列表不输出未经验证的尾部。
      def syslog_reference_values(tokens, entry)
        values = if tokens.first == "[" && tokens.last == "]"
          tokens[1...-1]
        elsif tokens.one?
          tokens
        end
        unless values && values.all? { |value| ResourceSchema.name?(value) }
          unresolved_syslog_reference(entry)
          return []
        end
        values
      end

      # 转发匹配项只采用最终日志类型；缺失或损坏不能退回先前有效声明。
      def final_syslog_log_type(entries, index)
        row = entries.reverse.find { |entry| entry[:tokens][index] == "log-type" }
        row && row[:tokens].size == index + 2 ? row[:tokens].last : nil
      end

      # 当前只解析本机共享转发 profile 与 security/default-security-rules 的显式消费者。
      def record_syslog_rule_consumers(forwarding, references, lines)
        rows = statements_with_prefix("rulebase") + statements_with_prefix("vsys")
        consumers = rows.filter_map do |row|
          tokens = row[:tokens]
          context, vsys, path = tokens.first == "vsys" ? [ "vsys", tokens[1], tokens.drop(2) ] : [ "local", nil, tokens ]
          next unless path.first == "rulebase" && path[2] == "rules" && %w[log-setting log-start log-end disabled].include?(path[4])
          unless %w[security default-security-rules].include?(path[1]) && (context == "local" || ResourceSchema.name?(vsys)) && ResourceSchema.name?(path[3])
            unresolved_syslog_reference(row[:entry]) if path[4] == "log-setting"
            next
          end
          { context: context, vsys: vsys, rulebase: path[1], rule: path[3], field: path[4], values: path.drop(5), entry: row[:entry] }
        end.group_by { |row| row.values_at(:context, :vsys, :rulebase, :rule) }
        consumers.each do |(context, vsys, rulebase, rule), entries|
          selected = entries.reverse.find { |row| row[:field] == "log-setting" }
          next unless selected
          unless selected[:values].one? && ResourceSchema.name?(selected[:values].first) && forwarding.key?(selected[:values].first)
            unresolved_syslog_reference(selected[:entry])
            next
          end
          profile = selected[:values].first
          flags = entries.group_by { |row| row[:field] }.filter_map do |field, declarations|
            next if field == "log-setting"
            values = declarations.last[:values]
            unless values.one? && %w[yes no].include?(values.first)
              unresolved_syslog_reference(declarations.last[:entry])
              next
            end
            [ field.tr("-", "_"), values.first == "yes" ]
          end.to_h
          forwarding.fetch(profile).each do |match|
            binding = { "kind" => "syslog.forwarding", "forwarding_profile" => profile, "match" => match[:match], "log_type" => match[:log_type],
              "context" => context, "rule" => rule, "rulebase" => rulebase }.merge(flags)
            binding["vsys"] = vsys if context == "vsys"
            match[:receivers].each do |receiver|
              (references[receiver] ||= []) << binding
              lines[receiver].concat(match[:lines] + entries.map { |row| row[:entry].line })
            end
          end
        end
      end
    end
  end
end

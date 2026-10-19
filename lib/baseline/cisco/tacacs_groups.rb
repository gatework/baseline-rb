# frozen_string_literal: true

module Baseline
  module Cisco
    # 命名服务器引用与地址引用属于不同身份，组重新进入及撤销按配置顺序归约。
    module TacacsGroups
      Inventory = Data.define(:groups, :references, :closed)
      private

      # 只输出非秘密成员和解析完整性，未识别的成员语法不能使空组冒充已知状态。
      def parse_tacacs_groups(named_servers, servers)
        states, malformed = {}, []
        sections = matching_blocks(/\A(?:no )?aaa group server tacacs(?:\+)?(?:\s|\z)/)
        sections.each do |section|
          match = /\A(no )?aaa group server tacacs\+ (\S+)\z/.match(section.text)
          unless match
            malformed << section
            next
          end
          name = match[2]
          if match[1]
            states.delete(name)
            next
          end
          state = states[name] ||= {}
          matching_blocks(/\A(?:no )?server(?:[ -]|\z)/, section.children).each do |entry|
            negative = entry.text.start_with?("no ")
            text = entry.text.delete_prefix("no ")
            reference = tacacs_group_reference(text, entry, named_servers, servers)
            identity = case reference[:kind]
            when "named_server" then [ "named_server", reference[:name] ]
            when "address" then [ "address", reference[:address] ]
            else [ "unresolved", entry.line ]
            end
            if negative && reference[:kind] != "unresolved"
              state.delete(identity)
            else
              state[identity] = reference
            end
          end
        end
        references = states.transform_values(&:values)
        groups = references.transform_values { |rows| rows.flat_map { |row| row[:servers] }.uniq }
        record_unknown_fact("tacacs.group_references", malformed, code: :tacacs_group_inventory_unresolved) if malformed.any?
        Inventory.new(**CtxParser::Immutable.copy(groups: groups, references: references, closed: malformed.empty? && @fact_builder.complete?))
      end

      # 显式 name 只匹配命名声明；相同 DNS 或 IP 字符串不能代替不存在的对象。
      def tacacs_group_reference(text, entry, named_servers, servers)
        if (match = /\Aserver name (\S+)\z/.match(text))
          addresses = named_servers.fetch(match[1], [])
          { kind: "named_server", name: match[1], servers: addresses, complete: addresses.any? && (addresses - servers).empty?, line: entry.line }
        elsif (match = /\Aserver (\S+)\z/.match(text)) && server_address?(match[1])
          address = ServerAddress.normalize(match[1])
          { kind: "address", address: address, servers: [ address ], complete: servers.include?(address), line: entry.line }
        else
          { kind: "unresolved", servers: [], complete: false, line: entry.line }
        end
      end
    end
  end
end

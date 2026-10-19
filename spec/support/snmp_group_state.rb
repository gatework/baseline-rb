# frozen_string_literal: true

# 独立模拟 VACM 组和用户归属；删除仍有用户的组会连带删除材料，因此直接判定迁移失败。
class SnmpGroupState
  GROUP = /\Asnmp-agent group v3 (\S+)(?: (privacy|authentication|noauthentication))?(?:\s|\z)/

  def initialize(text) = @lines = text.lines

  def apply(commands)
    commands.each do |command|
      next if %w[system-view return].include?(command)
      if command.start_with?("undo snmp-agent group v3 ")
        match = GROUP.match(command.delete_prefix("undo "))
        raise "Invalid group withdrawal" unless match
        raise "Group deletion would destroy user material" if bindings.value?(match[1])
        @lines.reject! { |line| (old = GROUP.match(line)) && identity(old) == identity(match) }
      elsif (match = GROUP.match(command))
        raise "Existing group overwritten" if @lines.any? { |line| (old = GROUP.match(line)) && identity(old) == identity(match) }
        insert(command)
      elsif (match = /\Asnmp-agent usm-user v3 (\S+) group (\S+)\z/.match(command))
        user, group = match.captures
        raise "User material absent" unless bindings.key?(user)
        raise "Destination group absent" unless @lines.any? { |line| (row = GROUP.match(line)) && row[1] == group }
        @lines.map! do |line|
          next line unless (entry = binding(line)) && entry.first == user
          line.sub(/(\Asnmp-agent usm-user v3 \S+ (?:group )?)\S+/, "\\1#{group}")
        end
      else
        raise "Unsupported SNMP test command"
      end
    end
    self
  end

  def configuration = @lines.join

  private

  def identity(match) = [ match[1], match[2] || "noauthentication" ]

  def binding(line)
    match = /\Asnmp-agent usm-user v3 (\S+) (?:(group) )?(\S+)/.match(line)
    return unless match && (match[2] || !%w[authentication-mode privacy-mode acl cipher simple local engineid remote].include?(match[3]))
    [ match[1], match[3] ]
  end

  def bindings = @lines.filter_map { |line| binding(line) }.to_h

  def insert(command)
    index = @lines.index { |line| line.strip == "return" } || @lines.size
    @lines[index - 1] += "\n" if index.positive? && !@lines[index - 1].end_with?("\n")
    @lines.insert(index, command + "\n")
  end
end

# frozen_string_literal: true

require "ipaddr"

# 测试专用的原生命令状态模型，不调用生产解析器、操作类型或命令呈现器。
class H3cTacacsState
  ENDPOINT = /\A(primary|secondary) (authentication|authorization|accounting) (?:ipv6 )?(\S+)(?: (\d+))?( single-connection)?\z/

  def initialize(text)
    @lines = text.lines
    @protected = inventory.map { |entry| entry.take(2) }.uniq
  end

  # 逐条应用命令并验证物理身份、原生容量及既有职责不中断。
  def apply(commands)
    group = nil
    commands.each do |command|
      if %w[system-view return].include?(command)
        group = nil
        next
      end
      if (view = /\Ahwtacacs scheme (\S+)\z/.match(command))
        group = view[1]
        next
      end
      raise "Missing scheme view" unless group
      start = @lines.index { |line| line.strip == "hwtacacs scheme #{group}" }
      raise "Unknown scheme" unless start
      finish = ((start + 1)...@lines.size).find { |index| @lines[index].strip == "#" } || @lines.size
      removing = command.start_with?("undo ")
      body = command.delete_prefix("undo ")
      reset = /\Aprimary (authentication|authorization|accounting)\z/.match(body)
      endpoint = ENDPOINT.match(body)
      raise "Unsupported test command" unless endpoint || removing && reset
      role = reset ? reset[1] : endpoint[2]
      matches = ((start + 1)...finish).select do |index|
        old = ENDPOINT.match(@lines[index].strip)
        old && old[2] == role && (reset || endpoint[1] == "primary" ? old[1] == "primary" : old[1] == "secondary" && native(old) == native(endpoint))
      end
      insertion = matches.first || finish
      matches.reverse_each { |index| @lines.delete_at(index) }
      @lines.insert(insertion, " #{body}\n") unless removing
      entries = inventory
      raise "Role disconnected" unless @protected.all? { |identity| entries.any? { |entry| entry.take(2) == identity } }
      raise "Duplicate native endpoint" unless entries.map { |entry| entry.values_at(0, 1, 3, 4) }.uniq.size == entries.size
      entries.group_by { |entry| entry.take(2) }.each_value do |servers|
        raise "Native capacity exceeded" if servers.count { |entry| entry[2] == "secondary" } > 16
      end
    end
    self
  end

  def configuration = @lines.join

  private

  def native(match) = [ IPAddr.new(match[3]).to_s, (match[4] || "49").to_i ]

  def inventory
    group = nil
    @lines.filter_map do |line|
      if (view = /\Ahwtacacs scheme (\S+)\z/.match(line.strip))
        group = view[1]
        next
      end
      group = nil if line.strip == "#"
      endpoint = ENDPOINT.match(line.strip)
      [ group, endpoint[2], endpoint[1], *native(endpoint) ] if group && endpoint
    end
  end
end

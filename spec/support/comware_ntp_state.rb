# frozen_string_literal: true

# 独立的测试状态模型，仅接受已确认的 Comware/VRP 时间关联命令。
class ComwareNtpState
  TARGET = /\A(?:undo )?ntp-service (?:ipv6 )?unicast-(server|peer) (?:vpn-instance (\S+) )?(\S+)(?:\s|\z)/

  def initialize(text, capacity: 4)
    @lines, @capacity = text.lines, capacity
  end

  # 仅在全局视图修改完整身份，所有密钥、可信声明及其他配置保持原文。
  def apply(commands)
    commands.each do |command|
      next if %w[system-view return].include?(command)
      target = TARGET.match(command)
      raise "Unsupported NTP test command" unless target
      indexes = @lines.each_index.select do |index|
        # 合成配置使用顶层零缩进，不能误改接口内命令。
        old = TARGET.match(@lines[index])
        old && old.captures == target.captures
      end
      insertion = indexes.first || @lines.index { |line| line.strip == "return" } || @lines.size
      indexes.reverse_each { |index| @lines.delete_at(index) }
      @lines.insert(insertion, "#{command}\n") unless command.start_with?("undo ")
      raise "NTP test capacity exceeded" if @lines.count { |line| TARGET.match?(line) } > @capacity
    end
    self
  end

  def configuration = @lines.join
end

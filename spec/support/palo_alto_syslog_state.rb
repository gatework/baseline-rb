# frozen_string_literal: true

require "shellwords"

# 原生候选树模型仅实现服务器叶子和精确 server 删除，禁止 profile 及转发配置泛删。
class PaloAltoSyslogState
  def initialize(text)
    @lines = text.lines
  end

  # 按原生四服务器/profile 上限检查每个中间步骤，未修改行保留原文。
  def apply(commands)
    commands.each do |command|
      next if %w[configure exit].include?(command)
      action, *path = Shellwords.shellsplit(command)
      unless path.take(3) == %w[shared log-settings syslog] && path[4] == "server" &&
          (action == "delete" && path.size == 6 || action == "set" && path.size == 8 && %w[server transport port format facility].include?(path[6]))
        raise "Unsupported PAN-OS Syslog test command"
      end
      prefix = action == "delete" ? path : path.take(7)
      @lines.reject! { |line| syslog_path(line).take(prefix.size) == prefix }
      @lines.unshift(command + "\n") if action == "set"
      counts = @lines.map { |line| syslog_path(line) }.select { |row| row[4] == "server" }.map { |row| row.take(6) }.uniq.group_by { |row| row[3] }
      raise "PAN-OS Syslog profile capacity exceeded" if counts.values.any? { |rows| rows.size > 4 }
    end
    self
  end

  def configuration = @lines.join

  private

  # 名称引号只在定位时解码，不重写其他配置或自定义格式。
  def syslog_path(line)
    line.lstrip.start_with?("set shared log-settings syslog ") ? Shellwords.shellsplit(line).drop(1) : []
  end
end

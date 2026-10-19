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
      if %w[set delete].include?(action) && reference_path?(path)
        apply_reference(action, path)
        next
      end
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

  # 独立按列表成员语义归约；保留同一路径其他接收者，不接受整个列表删除。
  def reference_path?(path)
    path.take(2) == %w[shared log-settings] &&
      (path[2] == "profiles" ? path.size == 8 && path[4] == "match-list" && path[6] == "send-syslog" :
        %w[system config userid iptag globalprotect hipmatch correlation].include?(path[2]) && path.size == 7 && path[3] == "match-list" && path[5] == "send-syslog")
  end

  def apply_reference(action, path)
    prefix, member = path[...-1], path.last
    members = []
    @lines.reject! do |line|
      next false unless line.lstrip.start_with?("set shared log-settings ")
      tokens = Shellwords.shellsplit(line).drop(1)
      next false unless tokens.take(prefix.size) == prefix
      values = tokens.drop(prefix.size)
      values = values[1...-1] if values.first == "[" && values.last == "]"
      members.concat(values)
      true
    end
    action == "set" ? members << member : members.delete(member)
    unless members.empty?
      @lines.unshift("set #{prefix.map { |token| token.include?(' ') ? token.inspect : token }.join(' ')} [ #{members.uniq.map(&:inspect).join(' ')} ]\n")
    end
  end

  # 名称引号只在定位时解码，不重写其他配置或自定义格式。
  def syslog_path(line)
    line.lstrip.start_with?("set shared log-settings syslog ") ? Shellwords.shellsplit(line).drop(1) : []
  end
end

# frozen_string_literal: true

require "shellwords"

# 独立候选配置模型按原生树路径应用 set/delete，不调用生产呈现或解析辅助函数。
class PaloAltoNtpState
  def initialize(text)
    @lines = text.lines
  end

  # 仅接受 NTP 槽位树；任何跨域命令、保存或提交均使验证失败。
  def apply(commands)
    commands.each do |command|
      next if %w[configure exit].include?(command)
      action, *path = command.split
      unless %w[set delete].include?(action) && path.take(3) == %w[deviceconfig system ntp-servers] &&
          %w[primary-ntp-server secondary-ntp-server].include?(path[3])
        raise "Unsupported PAN-OS NTP test command"
      end
      if action == "delete"
        raise "Unsupported PAN-OS NTP deletion" unless path.size == 4
        @lines.reject! { |line| ntp_path(line).take(path.size) == path }
      else
        unless path.size == 6 && (path[4] == "ntp-server-address" || path.drop(4) == %w[authentication-type none])
          raise "Unsupported PAN-OS NTP setting"
        end
        @lines.reject! { |line| ntp_path(line).take(5) == path.take(5) }
        @lines.unshift([ "set", *path ].join(" ") + "\n")
      end
    end
    self
  end

  def configuration = @lines.join

  private

  # set 导出可给固定名称加引号，比较解码路径时保留未修改行的原始字节。
  def ntp_path(line)
    line.lstrip.start_with?("set deviceconfig system ntp-servers ") ? Shellwords.shellsplit(line).drop(1) : []
  end
end

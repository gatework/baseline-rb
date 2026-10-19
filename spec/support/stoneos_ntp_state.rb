# frozen_string_literal: true

require "shellwords"
require "ipaddr"

# 独立模型按全局地址应用完整服务器声明；绝不接受密钥、开关或保存命令。
class StoneosNtpState
  def initialize(text)
    @lines = text.lines
  end

  def apply(commands)
    commands.each do |command|
      next if %w[configure exit].include?(command)
      parts = Shellwords.shellsplit(command)
      negative = parts.first == "no"
      parts = parts.drop(1) if negative
      raise "Unsupported StoneOS NTP test command" unless parts.take(2) == %w[ntp server] && parts[2] && (!negative || parts.size == 3)
      address = canonical(parts[2])
      @lines.reject! do |line|
        next false unless line.start_with?("ntp server ")
        canonical(Shellwords.shellsplit(line)[2]) == address
      end
      insertion = @lines.index { |line| line.strip == "End" } || (@lines.last && !@lines.last.end_with?("\n") ? @lines.size - 1 : @lines.size)
      @lines.insert(insertion, command + "\n") unless negative
      active = {}
      @lines.each do |line|
        next unless /\A(?:no )?ntp server /.match?(line)
        row = Shellwords.shellsplit(line)
        withdrawn = row.first == "no"
        row.shift if withdrawn
        withdrawn ? active.delete(canonical(row[2])) : active[canonical(row[2])] = true
      end
      raise "Native StoneOS NTP capacity exceeded" if active.size > 3
    end
    self
  end

  def configuration = @lines.join

  private

  def canonical(address)
    IPAddr.new(address).to_s
  rescue IPAddr::Error
    address.downcase
  end
end

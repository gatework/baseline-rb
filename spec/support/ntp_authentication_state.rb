# frozen_string_literal: true

require_relative "stoneos_ntp_state"
require_relative "comware_ntp_state"

# 独立按原生命令应用开关，启用时要求当前每台静态服务器/peer 都有可用引用。
class NtpAuthenticationState
  def initialize(text, platform:, capacity: 4)
    @text, @platform, @capacity = text, platform, capacity
  end

  def apply(commands)
    positive = @platform == "hillstone" ? "ntp authentication" : "ntp-service authentication enable"
    negative = @platform == "hillstone" ? "no ntp authentication" : "undo ntp-service authentication enable"
    commands.each do |command|
      next if [ "configure", "exit", "system-view", "return" ].include?(command)
      if [ positive, negative ].include?(command)
        if command == positive && @platform != "hillstone" && @text.lines.any? { |line| /\Antp-service (?:ipv6 )?unicast-(?:server|peer) /.match?(line) }
          raise "Authentication must precede basic associations"
        end
        verify_references! if command == positive
        lines = @text.lines.reject { |line| [ positive, negative ].include?(line.chomp) }
        index = lines.index { |line| %w[End return].include?(line.strip) } || lines.size
        lines.insert(index, command + "\n")
        @text = lines.join
      else
        active = @text.lines.filter_map { |line| line.chomp if [ positive, negative ].include?(line.chomp) }.last == positive
        if active && !command.start_with?("no ", "undo ") && !/\b(?:key|authentication-keyid) \d+\b/.match?(command)
          raise "Unkeyed association before authentication disable"
        end
        model = @platform == "hillstone" ? StoneosNtpState.new(@text) : ComwareNtpState.new(@text, platform: @platform, capacity: @capacity)
        @text = model.apply([ command ]).configuration
      end
    end
    verify_references! if @text.lines.filter_map { |line| line.chomp if [ positive, negative ].include?(line.chomp) }.last == positive
    self
  end

  def configuration = @text

  private

  def verify_references!
    if @platform == "hillstone"
      material = @text.scan(/^ntp authentication-key (\d+) md5 \S+$/).flatten.map(&:to_i)
      peers = @text.lines.select { |line| line.start_with?("ntp server ") }
      ids = peers.map { |line| line[/\bkey (\d+)\b/, 1]&.to_i }
      raise "Unready authentication activation" unless ids.all? { |id| id && material.include?(id) }
    else
      material = @text.scan(/^ntp-service authentication-keyid (\d+) authentication-mode md5 cipher \S+$/).flatten.map(&:to_i)
      trusted = @text.scan(/^ntp-service reliable authentication-keyid (\d+)$/).flatten.map(&:to_i)
      peers = @text.lines.select { |line| /\Antp-service (?:ipv6 )?unicast-(?:server|peer) /.match?(line) }
      ids = peers.map { |line| line[/\bauthentication-keyid (\d+)\b/, 1]&.to_i }
      raise "Unready authentication activation" unless ids.all? { |id| id && material.include?(id) && trusted.include?(id) }
    end
  end
end

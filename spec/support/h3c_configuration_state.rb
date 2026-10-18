# frozen_string_literal: true

# 测试专用设备状态模型，与生产解析器和命令呈现器独立。
class H3cConfigurationState
  # 只模拟日志目标对象，保留所有其他配置文本及嵌套命令。
  def initialize(text, maximum_targets: 4)
    @maximum_targets = maximum_targets
    @other, @targets = [], {}
    root_indent = nil
    text.lines.each do |line|
      indent = nil
      stripped = line.strip
      if stripped.start_with?("#")
        root_indent = nil
      elsif !stripped.empty? && !stripped.match?(/\A(?:display |Current configuration|Building configuration)/)
        indent = line[/\A[ \t]*/].size
        root_indent = indent if root_indent.nil? || indent < root_indent
      end
      identity = indent && indent == root_indent ? target_identity(stripped) : nil
      if identity
        @insertion ||= @other.size
        @target_indent ||= indent
        @targets[identity] = line.chomp
      else
        @other << line
      end
    end
  end

  # 不接受任意命令，避免测试悄悄忽略生成器错误。
  def apply(commands)
    commands.each do |command|
      next if %w[system-view return].include?(command)
      identity = target_identity(command)
      raise "Unsupported test device command" unless identity

      command.start_with?("undo ") ? @targets.delete(identity) : @targets[identity] = command
      raise "Test device capacity exceeded" if @targets.size > @maximum_targets
    end
    self
  end

  # 模拟导出快照，目标位于全局视图，其他配置相对顺序不变。
  def configuration
    insertion = @insertion || @other.index { |line| line.strip == "return" } || @other.size
    [ *@other.take(insertion), *@targets.values.map { |command| "#{' ' * (@target_indent || 0)}#{command.strip}\n" }, *@other.drop(insertion) ].join
  end

  private

  # 对象身份只包含路由域和地址；端口等是可更新的属性。
  def target_identity(command)
    match = /\A(?:undo )?info-center loghost (?:vpn-instance (\S+) )?(?:ipv6 )?(\S+)(?: |\z)/.match(command)
    return unless match && !%w[source source-port].include?(match[2])

    [ match[1] ? :vpn : :public, match[1], match[2] ]
  end
end

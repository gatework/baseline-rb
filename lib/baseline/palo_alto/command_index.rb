# frozen_string_literal: true

module Baseline
  module PaloAlto
    # 按词元建立前缀索引，使账号、服务和配置文件查询不反复扫描整个导出。
    class CommandIndex
      # 深层查询扫描候选行，避免无效标量尾部扩大索引；完整词元仍保留供语法校验。
      MAX_INDEX_DEPTH = 7
      Node = Struct.new(:children, :rows)
      private_constant :MAX_INDEX_DEPTH, :Node

      # 来源顺序与重复声明均保留，标量调用者仍可选择最后一行。
      def initialize(rows)
        @root = Node.new({}, rows.dup.freeze)
        nodes = [ @root ]
        rows.each do |row|
          node = @root
          row.fetch(:tokens).take(MAX_INDEX_DEPTH).each do |token|
            node = node.children[token] ||= begin
              child = Node.new({}, [])
              nodes << child
              child
            end
            node.rows << row
          end
        end
        nodes.each { |node| node.children.freeze; node.rows.freeze; node.freeze }
        freeze
      end

      # 按完整词元匹配前缀，避免同名账号、层级或包含空格的值串扰。
      def matching_prefix(prefix)
        node = @root
        prefix.take(MAX_INDEX_DEPTH).each do |token|
          node = node.children[token]
          return [] unless node
        end
        return node.rows if prefix.size <= MAX_INDEX_DEPTH

        node.rows.select { |row| row.fetch(:tokens).take(prefix.size) == prefix }.freeze
      end

      # 索引持有词元，默认调试输出不能展开配置或凭据。
      def inspect = "#<#{self.class}>"
    end
    private_constant :CommandIndex
  end
end

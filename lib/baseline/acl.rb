# frozen_string_literal: true

require "ctx_parser/immutable"

require "ipaddr"

module Baseline
  # 按首次匹配规则分析 IPv4 来源 ACL；不支持的语法保持未知。
  class Acl
    attr_reader :name, :rules, :line, :supported

    # 冻结有序 ACL 规则及其来源、支持状态。
    def initialize(name:, rules:, line:, supported: true)
      @name, @rules, @line, @supported = CtxParser::Immutable.copy(name), CtxParser::Immutable.copy(rules), line, supported
      freeze
    end

    # 按 ACL 顺序匹配语义计算允许访问的来源范围。
    def permitted_source_networks(protocol:, port: nil)
      return unless supported && rules.any?
      selected = rules.sort_by { |rule| rule.fetch(:sequence) }.select do |rule|
        next unless [ "ip", protocol ].include?(rule.fetch(:protocol))
        if rule[:destination_port]
          return if port.nil?
          next unless rule[:destination_port] == port
        end
        true
      end
      self.class.cidrs_from_ranges(permitted_ranges(selected))
    end

    # 返回公开的数据结构，并保留状态与诊断信息。
    def to_h = { name: name, rules: rules, line: line, supported: supported }
    # 展示对象身份与状态，避免泄露原始回显或凭据。
    def inspect = "#<#{self.class} name=#{name} rules=#{rules.size} supported=#{supported}>"

    # 归一化 ACL 来源地址；不推测不支持语法的含义。
    def self.source_network(address, wildcard = nil)
      return "0.0.0.0/0" if address == "any"
      ip = IPAddr.new(address)
      raise ArgumentError, "IPv4 ACL required" unless ip.ipv4?
      if wildcard
        mask = IPAddr.new(wildcard == "0" ? "0.0.0.0" : wildcard)
        value = mask.to_i
        raise ArgumentError, "Noncontiguous wildcard" unless mask.ipv4? && (value & (value + 1)).zero?
        prefix = 32 - value.bit_length
        ip = ip.mask(prefix)
      end
      "#{ip}/#{ip.prefix}"
    end

    # 将网络前缀转换为包含首尾地址的整数区间。
    def self.ipv4_range(cidr)
      ip = IPAddr.new(cidr)
      raise ArgumentError, "IPv4 ACL required" unless ip.ipv4?
      [ ip.to_range.first.to_i, ip.to_range.last.to_i ]
    end

    # 判断所有实际来源范围是否均在允许范围内。
    def self.networks_within?(actual, expected)
      each_network_coverage(actual, expected) { |_index, covered| return false unless covered }
      true
    end

    # 批量返回未被批准范围完整覆盖的原始网段，保持报告的输入顺序。
    def self.unapproved_networks(actual, expected)
      indexes = []
      each_network_coverage(actual, expected) { |index, covered| indexes << index unless covered }
      indexes.sort.map { |index| actual.fetch(index) }
    end

    # 批准区间只解析、合并一次；实际网段按起点顺序与其线性比较。
    def self.each_network_coverage(actual, expected)
      approved = merge_ranges(expected.map { |cidr| ipv4_range(cidr) })
      networks = actual.each_with_index.map { |cidr, index| [ ipv4_range(cidr), index ] }.sort_by(&:first)
      approved_index = 0
      networks.each do |(first, last), source_index|
        approved_index += 1 while approved_index < approved.size && approved[approved_index].last < first
        candidate = approved[approved_index]
        yield source_index, candidate && candidate.first <= first && candidate.last >= last
      end
    end
    private_class_method :each_network_coverage

    # 将地址区间转换为数量最少的网络前缀。
    def self.cidrs_from_ranges(ranges)
      merge_ranges(ranges).flat_map do |first, last|
        networks = []
        while first <= last
          aligned = first.zero? ? 32 : (first & -first).bit_length - 1
          bits = [ aligned, (last - first + 1).bit_length - 1 ].min
          networks << "#{IPAddr.new(first, Socket::AF_INET)}/#{32 - bits}"
          first += 1 << bits
        end
        networks
      end
    end

    # 合并相邻或重叠区间，使覆盖比较只需顺序扫描，不反复切割整个集合。
    def self.merge_ranges(ranges)
      ranges.sort.each_with_object([]) do |(first, last), result|
        if result.any? && first <= result.last.last + 1
          result.last[1] = [ result.last.last, last ].max
        else
          result << [ first, last ]
        end
      end
    end
    private_class_method :merge_ranges

    private

    # 按地址边界扫描一次；每个区间由最先匹配的生效规则决定。
    def permitted_ranges(selected)
      boundaries = Hash.new { |entries, address| entries[address] = [] }
      selected.each_with_index do |rule, priority|
        first, last = self.class.ipv4_range(rule.fetch(:source))
        boundaries[first] << [ priority, true ]
        # 将闭区间终点转为下一地址的失效事件，统一处理相邻和重叠网段。
        boundaries[last + 1] << [ priority, false ]
      end
      active, priorities, permitted = [], [], []
      boundaries.keys.sort.each_cons(2) do |first, following|
        boundaries.fetch(first).each do |priority, enabled|
          active[priority] = enabled
          push_priority(priorities, priority) if enabled
        end
        # 堆顶始终是配置顺序最靠前的生效规则，保持 ACL 首次匹配语义。
        pop_priority(priorities) while priorities.any? && !active[priorities.first]
        if priorities.any? && selected.fetch(priorities.first).fetch(:action) == "permit"
          permitted << [ first, following - 1 ]
        end
      end
      permitted
    end

    # 使用二叉最小堆维护规则优先级，避免反复排序生效规则。
    def push_priority(heap, priority)
      index = heap.size
      heap << priority
      while index.positive?
        parent = (index - 1) / 2
        break if heap[parent] <= priority
        heap[index] = heap[parent]
        index = parent
      end
      heap[index] = priority
    end

    # 移除已失效的堆顶规则；其他失效规则在升至堆顶时再清理。
    def pop_priority(heap)
      last = heap.pop
      return if heap.empty?

      index = 0
      while (child = index * 2 + 1) < heap.size
        child += 1 if child + 1 < heap.size && heap[child + 1] < heap[child]
        break if last <= heap[child]
        heap[index] = heap[child]
        index = child
      end
      heap[index] = last
    end
  end
end

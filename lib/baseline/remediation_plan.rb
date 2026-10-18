# frozen_string_literal: true

require "json"
require "ctx_parser/immutable"
require_relative "report"

module Baseline
  # 审计、变更意图及命令共同组成审核产物，任何受阻项都保留在整体状态中。
  class RemediationPlan
    REASONS = Report::REASONS.merge(
      remediation_unmodeled: "当前尚未实现此项修正配置，需补齐对应处理能力",
      credential_rotation_required: "需要批准的新凭据及人工轮换，普通方案不包含秘密值",
      unsupported_setting: "该厂商或当前设置组合尚无已验证的命令实现",
      invalid_command_parameter: "批准参数不符合厂商命令语法或包含非法字符",
      unresolved_prerequisites: "相关配置存在依赖，需先核对所列条件",
      approved_scope_required: "需要明确批准对象作用域，不能从现有错误配置推导",
      approved_targets_required: "需要批准的目标对象，不能根据最低数量编造地址",
      structured_policy_unresolved: "更精确的对象基线尚未解决，不能回退生成较粗的配置",
      resource_unresolved: "配置对象证据尚未完整解析，不能据此增删",
      policy_conflict: "同一领域的数量、地址或对象基线互相冲突",
      capacity_confirmation_required: "新增目标前需要确认设备目标容量，不能假定有空余槽位",
      capacity_exceeded: "批准的最终目标数量超出已确认容量",
      capacity_evidence_conflict: "当前对象数量与提供的容量证据不一致",
      ntp_authentication_dependency: "时间认证已启用或被基线要求，新增关联需已核验的认证材料与可信引用",
      vty_scope_unresolved: "VTY 范围不完整、交叠或协议证据未解决，不能逐范围修改",
      vty_authentication_dependency: "待修改范围缺少明确的兼容账户认证；不能假定认证继承不受协议命令影响",
      approved_access_limits_required: "需要 management.sources 的批准来源上限，不能从设备当前配置推导",
      access_policy_unresolved: "管理访问的相关批准值尚未解决，不能绕过未知约束",
      access_endpoint_unresolved: "端点、范围、ACL 引用或有效来源尚未完整解析，不能逐范围重绑",
      access_protocol_dependency: "同一 VTY 范围的协议来源差异尚无已验证的基本 ACL 呈现",
      approved_access_targets_required: "首次建立或进一步收紧需要明确批准的端点允许来源",
      approved_acl_identity_required: "需要为待修改端点批准全新的专用 ACL 标识",
      acl_identity_in_use: "批准的 ACL 标识已在输入中出现，不能证明它是全新标识，拒绝覆盖或意外激活其他引用",
      acl_reference_evidence_required: "缺少与本次完整配置绑定的新 ACL 标识占用检查",
      access_vrf_scope_required: "IOS 首次绑定需明确批准 vrf_also，不能从来源网段推导 VRF 可达范围",
      access_vrf_scope_conflict: "批准的 VRF 范围与现有绑定不同；来源收紧不能改变原有 VRF 可达范围",
      access_target_expands_existing: "批准的操作目标会扩大当前有效许可，当前收紧方案拒绝放宽",
      access_intersection_empty: "现有许可与批准上限没有交集；拒绝全部来源需显式批准空目标",
      approved_protocols_required: "仅支持明确收紧到 SSH；其他传输目标需显式批准协议"
    ).freeze
    Check = Data.define(:id, :status, :reason, :operation_ids, :requirements, :details) do
      # 检查结果不持有调用方可变参数。
      def initialize(details: {}, **attributes)
        super(**CtxParser::Immutable.copy(attributes.merge(details: details)))
      end

      # 保留机器原因码，同时为审核者解释当前受阻条件。
      def explanation = reason ? RemediationPlan::REASONS.fetch(reason, reason.to_s) : status == :planned ? "已生成待审核变更" : "无需变更"
    end
    attr_reader :audit, :checks, :operations, :steps

    # 所有数据都是独立快照；此对象不执行配置命令。
    def initialize(audit:, checks:, operations:, steps:, renderer:)
      order = { prepare: -1, create: 0, update: 1, remove: 2, verify: 3 }
      @audit, @checks = audit, checks.dup.freeze
      @operations = operations.each_with_index.sort_by { |operation, index| [ order.fetch(operation.phase), index ] }.map(&:first).freeze
      @steps = steps.each_with_index.sort_by { |step, index| [ order.fetch(step.phase), index ] }.map(&:first).freeze
      @commands = renderer.configuration_commands(@steps).freeze
      freeze
    end

    # 有命令不代表所有指标已解决；未知或未支持项不能被隐藏。
    def status
      blocked = checks.any? { |check| check.status == :blocked }
      return steps.empty? ? :blocked : :partial if blocked
      steps.empty? ? :noop : :ready
    end

    # 每个非空命令块均需人工审核，不能当作自动执行许可。
    def requires_review? = steps.any?
    # 返回独立命令块；不包含 save、commit 或实际执行结果。
    def configuration_commands = @commands

    # 公开结构保留指纹、逐项结果和可审核操作。
    def to_h
      { status: status, requires_review: requires_review?, configuration_sha256: audit.configuration.sha256,
        policy_sha256: audit.policy_sha256, audit: audit.to_h, checks: checks.map(&:to_h),
        operations: operations.map(&:to_h), steps: steps.map(&:to_h), configuration_commands: configuration_commands }
    end

    # 参数值由审计结构导出，文字部分仅呈现单行命令及稳定原因码。
    def to_text
      output = [ "baseline remediation: #{status}; 配置命令需人工审核后执行", "配置 SHA256: #{audit.configuration.sha256}; 策略 SHA256: #{audit.policy_sha256}" ]
      checks.each do |check|
        output << "  [#{check.status}] #{check.id}#{check.reason ? " (#{check.reason})" : ''}"
        output << "    #{check.explanation}"
        output << "    规划依据: #{JSON.generate(check.details)}" if check.details.any?
        output << "    所需条件: #{check.requirements.join(', ')}" if check.requirements.any?
      end
      if operations.any?
        risk = operations.max_by { |operation| %w[low medium high critical].index(operation.risk) }.risk
        output << "操作最高风险: #{risk}"
      end
      output.concat([ "配置命令:", *configuration_commands ]) if configuration_commands.any?
      output.join("\n")
    end

    # 普通调试只展示状态及数量。
    def inspect = "#<#{self.class} status=#{status} checks=#{checks.size} operations=#{operations.size}>"
  end
end

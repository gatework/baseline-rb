# Baseline Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** 对设备配置和批准参数进行准确偏离检查，并生成供人工审核的厂商修正方案。

**Architecture:** 保持 Audit 的纯离线接口。Parser 同时产生归一化事实和有作用域的资源；Planner 比较资源及批准参数，厂商 Renderer 呈现操作，Plan 保留所有受阻规则及来源指纹。

**Tech Stack:** Ruby >=4.0.6、RSpec、CtxParser、RuboCop。

**Spec:** docs/superpowers/specs/2026-10-18-baseline-remediation-design.md

## Global Constraints

- 人工审核后执行，不连接设备、不自动保存或提交设备配置。
- ctx_parser gemspec 继续不设版本约束。
- 不导入真实配置、身份及凭据；fixtures 使用合成样本。
- 作用域、对象身份、部分输入、未知事实不能因命令生成而丢失。
- 保留旧 Audit/Policy/Report 契约；厂商协议差异不可用通用字符串拼接替代。

## Review Focus

- 同命令前缀的独立控制项不能计为服务器（Task 1）。
- 同地址不同 VRF、类别、profile 的对象不能互相删除（Task 2/4）。
- 已通过子规则不能被其他修正操作破坏（Task 3/5）。
- 参数中的控制符及命令注入必须拒绝（Task 3/4）。
- 有命令又有 unknown 的方案只能标为 partial（Task 3）。

### Task 1: 修复现有审计事实

**Files:** lib/baseline/comware/parser.rb、lib/baseline/huawei/parser.rb、spec/comware_command_boundaries_spec.rb。
**Interfaces:** 仍使用 Audit#call 和 Evidence#fact；修正已有事实，不添加生成 API。

- [x] 添加 failing specs：ACL deny-log 正反命令不污染绑定；source-port 不增加服务器数量且不污染源接口；Huawei domain 提取正确；分写接口与连续接口归一化一致；合法同族坏语法保持 unknown。
- [x] `bundle exec rspec spec/comware_command_boundaries_spec.rb`：确认期望断言失败。
- [x] 使用命令词边界及厂商目标模式修正提取，接口复用已有选项解析契约。
- [x] 运行聚焦 specs 及 bundle exec rake，必须全部通过；真实备份重跑验证187份ACL问题消失。
- [x] 提交修复及证据，更新本计划。

### Task 2: 资源与结构化批准参数

**Files:** 新增 lib/baseline/configuration_resource.rb、lib/baseline/resource_schema.rb；修改 FactBuilder/Evidence/Rule/Policy 和各厂商 Parser；新增 spec/configuration_resources_spec.rb、spec/resource_policy_spec.rb。
**Interfaces:** ConfigurationResource#kind/#identity/#scope/#attributes/#lines/#bindings；Evidence#resources；FactBuilder#record_resource(resource)。Rule 增加 syslog.destinations/ntp.associations/tacacs.endpoints；Policy 解析 remediation 受管范围及字段。

- [ ] 红测完整身份、同地址不同作用域、字段省略、撤销/覆盖、秘密排除及深冻结。
- [ ] 先实现资源值对象和schema校验，再将各厂商现有提取改为共用资源归纳旧事实。
- [ ] 逐厂商增加合成样本及坏语法回归；结构化比较覆盖 changed/missing/unexpected，缺少受管范围不删除。
- [ ] 运行全部现有 specs，旧 API 行为除已确认缺陷外保持；提交。

### Task 3: 差异方案与领域操作

**Files:** 新增 lib/baseline/remediation.rb、remediation_plan.rb、remediation_planner.rb、configuration_operation.rb；修改 audit.rb 共享解析入口；新增 spec/remediation_plan_spec.rb。
**Interfaces:** Remediation.new(policy:).call(configuration:,platform:,complete:false,context:{}) -> RemediationPlan；Plan#audit/#operations/#checks/#status/#to_h/#to_text；Remediation.capabilities(platform:)。

- [ ] 红测每个启用规则都有结果、noop/ready/partial/blocked、输入及策略指纹、确定性、去重及诊断。
- [ ] 实现与审计同次解析的编排；逐规则域处理，不支持/缺值明确blocked，禁用和不适用不生成操作。
- [ ] 依赖与冲突检测：enabled与删除全部对象、数量与目标清单、旧/新规则冲突；未知/部分输入无变更。
- [ ] 运行 plan specs 及完整 tests；提交。

### Task 4: Syslog/NTP 厂商呈现与闭环

**Files:** 新增各厂商 command_renderer.rb 及共享 command_step.rb；新增 spec/remediation_servers_spec.rb、spec/support/configuration_state.rb。
**Interfaces:** Renderer#render(operation) -> command steps；步骤含view/command/phase，独立验证命令及人工save提示。

- [ ] 六平台红测正确目标保留、错误目标删除、正确目标新增、修改端口/VRF、source、server/peer和命名profile；测试域名及IPv6语法边界。
- [ ] 按官方命令语义实现，必需参数未提供则blocked；Hillstone删除完整类别目标、PAN-OS叶子修改。
- [ ] 独立测试状态模型应用命令后重审计，断言目标通过、无关配置不变、第二次零变更；测试注入拒绝。
- [ ] 跑全套及真实配置形态聚合验证；提交。

### Task 5: 管理、SNMP、ACL、TACACS、凭据

**Files:** 领域planner、各厂商renderer；spec/remediation_access_spec.rb、remediation_snmp_spec.rb、remediation_tacacs_spec.rb、remediation_credentials_spec.rb。
**Interfaces:** 使用 Task 2资源、Task 3操作和方案、Task 4命令步骤。

- [ ] 每领域先红测可生成及缺前提受阻；全部30条旧规则及新规则纳入能力矩阵。
- [ ] SSH/services 处理端点/版本/VTY及AAA链；不臆造密钥或开放全部接口。
- [ ] ACL按有效来源与批准上限取交集；首次建立需access_targets及专用ACL名称，先建再绑定，不覆盖共享ACL。
- [ ] SNMP处理用户组权限/版本/来源，不能删全部来绕过enabled；新秘密缺失受阻。
- [ ] TACACS保留职责/主备/引用和本地fallback；无密钥/认证链依据受阻；凭据轮换明确所缺材料。
- [ ] 跨领域组合状态变换闭环及注入/秘密导出测试；完整验证后提交。

### Task 6: 真实备份、扩展平台与交付

**Files:** script验证及benchmark、spec合成回归、README双语、CHANGELOG、docs/architecture-zh.md、examples/remediation.rb。
**Interfaces:** 全部公开入口、能力查询及方案序列化。

- [ ] 对Centec/Radware按样本产品版本和官方语法建立可证明能力；无法证明的领域保留明确unsupported，不伪装支持。
- [ ] 973份清单SHA匹配后重跑；默认策略和标记为合成的批准参数分别统计覆盖、受阻、操作数、性能P50/P95/max；输出无设备身份。
- [ ] `bundle exec rake`、`bundle exec rake build`、隔离安装加载及包内容/秘密检查通过。
- [ ] 文档明确人工审核和条件支持，公开示例实际运行通过；对全分支做独立代码审查并修复重要发现。
- [ ] 按设计逐条验收，未满足项保持目标未完成；当前不自动发版或推送。

## 执行记录

- 用户“继续”确认设计并授权实施。当前在干净功能分支 feat/baseline-remediation 直接执行，保留当前路径便于用户检查；不再引入额外工作区或重复确认。
- 前置接口检查：Task 2 resources供Task 3消费；Task 3 operation供Task 4/5呈现；Task 6验证所有层。无接口冲突。

- Task 1 complete: 368 examples / 0 failures, RuboCop55 files clean, offline example pass. 973份真实备份重跑无异常、显式命令对照无偏差、不完整输入零pass；187份management.acl_bound从unknown变fail，其他规则状态未变。
- Task 2 in progress: Syslog资源已覆盖六类现有适配器；保留VRF、Hillstone传输/端口/类别、PAN-OS profile/server叶子及安全元数据。386 examples / 0 failures，RuboCop58 files clean；973份真实备份零异常、旧规则状态不变、零显式命令偏差、不完整输入零pass。实际资源3342项，其中1项未知选项标记incomplete。NTP/TACACS资源、引用关系与结构化策略尚未完成，不能据此认定Task2完成。
- 用户补充要求全部指标完全覆盖：已新增30项显式评估验收表，每项七种状态，共219项指标契约测试（含重复观测和损坏适用条件回归）。不能将评估器测试覆盖误称为所有厂商语法或修正配置完整实现。
- NTP资源已覆盖六类现有适配器，区分server/peer、VRF、主备槽位及认证key引用。修正重复服务器计数/集合比较和异常类型范围事实错误排除检查的问题。全套616 examples / 0 failures，RuboCop60 files clean。973份真实备份重跑：零异常，较Task1无规则状态变化，显式对照无偏差，不完整输入零pass，候选秘密匹配为零。TACACS资源、引用关系、结构化策略、生成器及跨指标修正闭环仍待完成。

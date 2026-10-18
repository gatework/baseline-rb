# baseline-rb

[English](README.md) | [源码](https://github.com/gatework/baseline-rb) | [变更记录](CHANGELOG.md)

策略驱动的网络设备配置基线检查，将已采集的配置文本转为归一化事实，对照明确的批准值判定，并生成可解释的合规报告。

## 能力

- H3C、Huawei、Cisco IOS/IOS-XE、Cisco NX-OS、Hillstone、Palo Alto 配置适配。
- SNMP、NTP、Syslog、SSH、管理 ACL、服务、凭据元数据及 TACACS。
- YAML 声明式策略，可按 host/model/site/role/vendor 选择批准值。
- 来源指纹、安全判定、覆盖率及可读或结构化报告。

## 安装

要求 **Ruby 4.0.6 或更新版本**。在应用的 `Gemfile` 中添加：

```ruby
gem "baseline-rb", require: "baseline"
```

然后执行 `bundle install`；也可直接执行 `gem install baseline-rb`。Ruby 加载入口为 `baseline`，公开命名空间为 `Baseline`；gem 包名与 Ruby 命名空间分别维护。

模块运行依赖：[`ctx_parser`](https://github.com/gatework/ctx_parser)。 gemspec 声明 `ctx_parser` 依赖但不限制版本，以使用共享配置解析 API；应用应提交自己的 `Gemfile.lock`，保持部署可复现。使用本库不需要启动 Rails 或配置兄弟模块的本地路径。

发布产物和校验值见 [GitHub Releases](https://github.com/gatework/baseline-rb/releases)，已发布版本以 [RubyGems](https://rubygems.org/gems/baseline-rb) 为准。

## 离线示例

在开发检出目录安装依赖后执行：

```sh
bundle exec ruby examples/offline.rb
```

示例使用合成数据，不访问网络。完整代码见 [examples/offline.rb](examples/offline.rb)：

```ruby
require "baseline"

# 批准值独立于本例的合成配置声明。
policy = Baseline::Policy.new(
  "version" => 1,
  "checks" => { "ssh.enabled" => { "expected" => true, "severity" => "high" } }
)
report = Baseline::Audit.new(policy: policy).call(
  configuration: "sysname EXAMPLE-SWITCH\nssh server enable\nreturn\n",
  platform: :h3c,
  complete: true,
  context: { host: "192.0.2.10" }
)
puts report.to_text
# 仅检查显式选择的 SSH 配置项；不据此判断设备可达性。
```

## 公开契约与限制

`Policy.new(definition)`、`Policy.load(path)`、`Policy.default` 构造校验后的策略。`Audit.new(policy:).call(configuration:, platform:, complete: false, context: {})` 返回 `Report`，提供 `to_text`、`to_h`、`summary`、`compliant?`。[policy.yml](policy.yml) 是起点，组织批准值有意保留为空，需自行填写。

判定使用 `pass/fail/unknown/not_applicable`。缺批准值或语法不支持保持未知；部分输入可保留独立证明的违规，但不能证明合规。配置不能证明可达性、NTP 同步或认证服务器可用。

管理来源检查目前覆盖已建模的 IPv4 ACL 语义。PAN-OS 输入要求本机完整 `set` 导出，不支持 XML 或展开后的 Panorama 模板。不解密密码密文，也不凭密文证明强度；原始配置和秘密不可进入报告存储。

本库不连接设备、不采集备份、不下发修正配置、不写数据库。Motor 持久化和 `Baseline::Check` 属于宿主应用。

`Remediation.new(policy:).call(configuration:, platform:, complete: false, context: {})` 将同次审计转换为人工审核方案，提供 `audit`、`checks`、`operations`、`steps`、`configuration_commands`、`to_h` 和 `to_text`。状态为 `noop/ready/partial/blocked`；任一受阻指标都保留在方案中。`ready` 表示所选指标有完整的命令方案，不表示已经执行、保存、生效或整机合规。命令不含自动保存或提交。

当前支持 H3C/Huawei/IOS/NX-OS/PAN-OS 的 NTP/Syslog 源接口设置、H3C/Huawei/IOS 的 SSHv2 设置，以及各呈现器明确声明的服务关闭命令；服务种类及设备语法限制仍需检查。PAN-OS 使用原生接口名；存在显式服务路由源地址时，接口切换会受阻，需先核对地址依赖。H3C/Huawei/IOS/NX-OS/Hillstone 另支持日志目标增删及属性替换的部分语法。其他对象、ACL、SNMP 与认证链的完整命令生成仍在开发，未实现项会明确返回 `remediation_unmodeled`，不会当作完成。

日志对象生成限制：Huawei 使用 `domain` 和目标之后的 `vpn-instance`；IOS 传输端口修改需已知协议，重复同身份不同传输或名为 default 的 VRF 保持受阻；NX-OS 目前只生成地址、级别、facility 和 use-vrf 子集，port 扩展尚未核验；Hillstone 要求显式协议/端口/类别身份，当前支持 event/config 类别。错误选项会整体阻止该指标操作，不输出“只删除而无法新增”的部分方案。不同厂商/固件的默认值和容量不能互相套用。

H3C/Huawei/IOS/NX-OS 的 NTP 目标支持 server/peer 对象增删及已建模选项替换；旧 `ntp.servers` 只管理 server，保留 peer。`ntp.associations` 配合 `managed_scopes` 可显式管理关联类型、VRF 和选项。与日志对象相同，数量和地址检查共同约束最终集合，净新增需已确认容量。既有 key 引用可以保留，但新 key 编号不能代替认证材料证据；全局认证已启用或策略要求认证时，缺少 key 引用的新关联不会生成。认证材料建立、可信 key 配置以及认证开关完整依赖尚在开发，不会仅打开开关后声称问题已修复。未知的隐式 prefer/burst 等状态不会被当成关闭。

管理访问生成：H3C/Huawei/IOS 可按已解析且不交叠的 VTY 范围收紧入站协议到 SSH，前提是已知 SSH 启用；H3C/Huawei 还要求每个待修改范围明确配置兼容认证（scheme/aaa），仅有继承证据时受阻，避免范围级协议命令改变有效认证方式。只修改需要收紧的范围，保留登录方式及 ACL。协议限制与“关闭 SSH”批准值冲突时阻止生成。H3C/Huawei/NX-OS 可生成显式批准的 SSH 关闭命令，按高风险操作呈现；不会删除或生成密钥。启用 SSH、选择新的本地或远程认证链仍需密钥及端点/认证链证据，当前保持受阻，不能把任意 `authentication-mode` 替换当作完整认证修复。

H3C 日志目标规划会同时检查数量、地址和对象规则，拒绝冲突批准值，并保留未受管属性及其他作用域。地址清单仅在对象均为公共路由域时生成简单增删；其他作用域需使用对象规则及 `managed_scopes`。增加净目标数需要规则内 `remediation: {maximum_targets: 4}` 等已核实的设备容量参数，不能照搬示例中的容量。纯替换没有容量参数时，只使用当前对象占用量作为容量下限，必要时先删除错误目标再新增，不将该下限称为设备上限。显式 `order: remove_before_add` 可优先撤销未批准目标；规划依据和提前删除步骤会保留在方案中。容量满时的提前删除与同对象替换可能短暂中断日志输出，需人工审核。

`Remediation.capabilities(platform:)` 独立查询生成覆盖及前提，不与 `Audit.capabilities` 的解析能力混淆。运行 `bundle exec ruby -Ilib examples/remediation.rb` 查看合成示例；真实配置及凭据不得写入示例。

H3C SNMP 版本收紧仅删除未批准版本，要求当前已启用 v3、具备 authPriv 用户及已解析的组引用，并在 `snmp.versions` 规则中声明 `remediation: {existing_v3_access_verified: true}`，确认人工已验证现有 v3 管理路径。此值不能由备份推定；用户或组撤销语法尚未完整归约时保持未知并受阻。操作按高风险呈现，不删除用户、community 或 ACL，不新建 v3 用户，也不删除全部活动版本。其他厂商版本收紧及完整 SNMP 权限/认证修正仍待实现。

IPv4 管理 ACL 可为 H3C `line vty`、Huawei `user-interface vty`、IOS `line vty` 生成“先创建专用 ACL，再重绑”的方案。H3C/Huawei 使用全新 2000–2999 基本 ACL，IOS 使用全新标准 ACL：编号 1–99/1300–1999，或以字母开头且通过库词元白名单（最多253字节）的名称。必须提供 `management.sources` 批准上限，并在相关规则的 `remediation.access_targets` 中声明 `{endpoint: "line vty 0 4", acl: "2002"}`；首次绑定还需明确 `sources`。IOS 保留已有 `vrf-also`，首次绑定须另行批准布尔 `vrf_also`；不会借来源收紧改变 VRF 范围。

现有许可只收紧到与上限的交集，明确提供的来源也不能扩大当前许可。批准 ACL 标识只要在本次输入任意位置出现，就不能视为全新；这种保守检查也覆盖未建模命令、注释和横幅，数字标识会识别前导零。方案不修改旧 ACL 及其 SNMP/业务引用。交集为空需显式批准 `sources: []`；范围交叠、未解决证据或不能保留的协议/端口差异会阻止整项操作。NX-OS/防火墙、IPv6、H3C 传统 `user-interface` 和复杂 ACL 呈现仍待实现。参见[例子](examples/remediation_access.rb)。

H3C SNMP 来源修正支持全新的基本 ACL 加 `snmp-agent acl` 全局绑定，保留团体字、用户、组和各主体更严格的 ACL。`snmp.sources` 必须给出批准上限，相关规则的 `remediation.access_targets` 使用 `{endpoint: "snmp.global", acl: "2005"}`；存在未绑定主体时还必须明确 `sources`。备份没有该全局命令证据时，需要 `global_acl_supported: true` 确认固件能力；不会把所有 H3C 固件视为支持。已有全局许可不会扩大，不会仅靠开关关闭 SNMP 来通过子规则。同一设备上的管理/SNMP 目标若争用同一新 ACL，整个相关方案受阻。参见[SNMP 例子](examples/remediation_snmp_access.rb)。

SNMP 审计区分 H3C 全局/组/用户串联 ACL，使用匿名序号标识团体字，IPv6-only ACL 不算 IPv4 限制。完整且明确没有绑定的主体记为 IPv4 来源未限制，复杂或损坏声明仍为未知。H3C 同名 VACM 用户采用最后一次完整定义及凭据记录；Huawei 的分行配置保持增量处理。组视图和安全级别作为非秘密定义保留，但完整 MIB 视图权限与组修改仍待实现。

详细厂商语义、历史验证记录和 Motor 专用集成说明保留在[架构参考](docs/architecture-zh.md)。其中宿主集成代码需要 Motor，不属于独立 gem API。适配层位于 [Motor 仓库](https://github.com/gatework/motor/tree/main/backend/lib) 的 `backend/lib/baseline`、`backend/lib/vxlan` 和 `backend/lib/wireless`。

## 领域术语

`FactBuilder` 汇总配置证据，`Policy` 提供批准值，`Evaluator` 生成合规判定。`Acl#permitted_source_networks` 按有序规则、协议和目标端口计算允许的 IPv4 来源网段：`nil` 表示证据未解决，`[]` 表示没有允许来源。`FactBuilder#record_credential` 记录安全的凭据属性。部分证据可以证明确定违规，但不能证明合规。

全部 30 项指标及逐项验收边界见[指标覆盖说明](docs/baseline-metrics.md)。数量指标统计不同服务器，重复采集同一地址不能满足冗余要求。

可选规则 `syslog.destinations`、`ntp.associations`、`tacacs.endpoints` 进一步检查对象身份、作用域及明确批准的属性。`expected` 为对象数组，每项包含 `identity`、`scope` 和可选 `attributes`；`managed_scopes` 明确哪些作用域的多余对象需要判为偏离。未声明受管范围时只检查批准对象及其指定属性，不推导其他对象应被删除。未指定属性保持不受管；未经验证的设备默认值保持未知。这三项未自动加入默认策略。

```yaml
version: 1
checks:
  syslog.destinations:
    managed_scopes: [{vrf: default}]
    expected:
      - identity: {address: 192.0.2.20}
        scope: {vrf: default}
        attributes: {port: 1514}
```

对象级偏差保留 `missing`、`unexpected`、`changed`；同地址但端口错误会判为偏离。使用命名 profile 或方案的厂商应声明其实际作用域和身份。对象定义检查不能证明日志转发或认证引用链已生效。

`Evidence#resources` 提供不可变的 Syslog、NTP 和 TACACS 对象，保留厂商身份、作用域、选项及来源行，避免将去重地址误用为配置对象。每项 `ConfigurationResource#complete?` 只表示该对象语法是否被完整理解，不代表配置采集完整、引用链已生效或设备合规；未知选项不会复制进资源数据。

厂商代码按命名空间组织：`Baseline::Hillstone::Parser` 和 `Baseline::Hillstone::Document` 同放在 `baseline/hillstone/`；Palo Alto 使用相同布局。六个平台解析器复用 `Baseline::Parser`、`Comware::Parser` 或 `Cisco::Parser`。单个平台可用 `require "baseline/hillstone/parser"` 独立加载；完整评估入口仍为 `require "baseline"`。

解析辅助方法直接描述提取意图：`matching_blocks`、`configured_values`、`last_configured_value`、`configured_state` 和 `parse_acl_source_network`。SNMP 写权限规则统一为 `snmp.write_enabled`，禁止写入时配置 `expected: false`。自定义策略需迁移旧键 `snmp.read_only`；旧类名与规则键不保留兼容别名。

上下文允许字符串或符号键，但归一化后重复的键会抛出 `ArgumentError`，避免依赖插入顺序选择设备策略。

`complete: true` 表示调用方提供了完整快照。报告通过 `input_complete` 保留这项声明，与解析状态分别记录。不完整的有序 ACL 可能缺少更早的 deny，因此不能仅根据已见 permit 判断来源越界，此时保持 `unknown`。

## 跨厂商能力契约

各适配器共用管理、NTP、Syslog、SNMP、认证处理流程，输出统一的 `Evidence` / `Report`。厂商语法留在对应命名空间，跨命令权限归约由 `FactBuilder` 负责，`Evaluator` 不按厂商分支。共享 Cisco、Comware 实现时，只合并语义相同的部分。

`Baseline::Audit.capabilities(platform: :stoneos)` 返回包含全部公开规则的深冻结 Hash；各项提供 `fact`、`status`（`supported` / `partial` / `unsupported`）与 `reason`。新增事实必须显式声明适配器能力，仅新增策略规则不会自动标记为已支持。查询与审计使用相同别名，`Audit.normalize_platform(name)` 可获取规范名称。支持状态表示已实现的证据提取范围，不代表当前配置证据充分、设备实际可达或覆盖所有固件版本。

| 能力 | H3C / Huawei | IOS / NX-OS | Hillstone | Palo Alto |
| --- | --- | --- | --- | --- |
| NTP 服务器、认证、源接口 | 支持 | 支持 | 支持 | 支持 |
| Syslog 服务器、源接口 | 支持 | 支持 | 支持 | 支持 |
| SNMP 版本、写权限、v3 认证与加密 | 支持 | 支持 | 支持 | 支持 |
| IPv4 管理与 SNMP 来源范围 | 支持 | 支持 | 支持 | 支持 |
| SSH 启用状态 | 支持 | 支持 | 支持 | 支持 |
| 显式 SSH 版本、VTY 检查 | 支持 | 支持 | 尚未建模 | 尚未建模 |
| 凭据存储、可观察口令强度 | 支持 | 支持 | 支持 | 支持 |
| TACACS 服务器、密钥、登录 | 支持 | 支持 | 支持 | 支持 |
| TACACS 授权 | 支持 | 支持 | 支持 | 尚未建模 |
| TACACS 计费 | 支持 | 支持 | 尚未建模 | 尚未建模 |
| 非必要服务状态 | 支持 | 支持 | 部分 | 部分 |

Hillstone 服务状态覆盖 Telnet、HTTP、HTTPS、FTP，Palo Alto 覆盖 Telnet、HTTP、HTTPS；缺失状态保留未知。原生防火墙端点没有路由器式 VTY 事实，相关规则仍返回 `unknown` 和 `unsupported_capability` 诊断，不会自动排除或当作通过。

Hillstone SNMPv3 根据 [StoneOS CLI 手册](https://kb.hillstonenet.com/en/wp-content/uploads/2017/11/StoneOS_CLI_User_Guide_Complete_Book_5.5R5-1.pdf) 的正式组、用户语法解析 `auth-protocol`、`enc-protocol`、组写视图与 IPv4 远端主机。未知算法、IPv6 远端用户、撤销命令、无法解析的组及缺少用户证据的 v3 主机保持未知；组的安全级别要求不能替代用户实际配置的密钥证据。

## 命名与对象职责

类名表达对象生命周期，方法名表达返回结果或副作用。`FactBuilder` 累积证据，`build` 生成独立的解析结果；`Evidence` 持有用于判定的不可变证据快照；`MultilineDocument` 隔离跨行引号值；`PaloAlto::CommandIndex` 按词元前缀检索配置命令。厂商 `Parser` 与直接对应设备命令的名称保留其领域含义。

| 原名称 | 新名称 | 职责 |
| --- | --- | --- |
| `Facts`、`baseline/facts` | `FactBuilder`、`baseline/fact_builder` | 可变事实构建 |
| `Configuration`、`baseline/configuration` | `Evidence`、`baseline/evidence` | 不可变证据快照 |
| `QuotedDocument`、`baseline/quoted_document` | `MultilineDocument`、`baseline/multiline_document` | 跨行引号值的命令边界 |
| `PaloAlto::Statements#at` | `PaloAlto::CommandIndex#matching_prefix` | 返回前缀匹配的全部语句 |
| `Facts#result` | `FactBuilder#build` | 生成新的结果快照 |
| `Facts#record` / `unknown` | `FactBuilder#record_fact` / `record_unknown_fact` | 记录事实或诊断 |
| `Facts#management` / `snmp` | `FactBuilder#record_management_access` / `record_snmp_access` | 更新管理或 SNMP 证据 |
| `Facts#direct_acl` | `FactBuilder#record_source_restriction` | 记录原生来源范围，不要求命名 ACL |
| `Configuration#value` / `known?` / `scope_known?` | `Evidence#fact` / `fact_known?` / `applicability_fact_known?` | 查询事实及其证据可用性 |
| `Policy#resolve_with_source` | `Policy#resolve_with_path` | 返回批准值、原因与策略分支路径 |
| `Acl.address_range` / `network_prefixes` | `Acl.ipv4_range` / `cidrs_from_ranges` | 转换 IPv4 CIDR 与整数区间 |

内部解析流程用 `parse_*`，事实和诊断写入用 `record_*`，正则提供方法用 `*_pattern`。三态结果用 `*_state`，避免冒充布尔谓词；解析、校验方法说明解析对象。`Policy`、`Rule`、`Acl`、`Credential`、`Evaluator`、`Report`、`to_h`、`inspect` 等已有清晰含义的名称继续使用。旧名称和旧加载路径不保留别名，规则 ID、事实键和报告 JSON 沿用业务术语。

## 开发与测试

共享类按实际职责命名，平台信息放在命名空间中。直接对应设备命令的解析器保留文件名和类名。

```sh
bundle install
bundle exec rake
bundle exec ruby examples/offline.rb
bundle exec rake build
```

`bundle exec rake` 执行 RSpec、RuboCop 及离线示例。测试放在 `spec/`，沿用项目 RSpec 约定；样例采用合成或脱敏证据。新增解析格式时补充成功、不完整、不支持及非法输入回归。离线测试不代表所有设备版本均通过实机验证。

运行 `bundle exec ruby -Ilib script/benchmark.rb` 可测量合成 ACL 覆盖比较、凭据来源行查询、越界来源报告、PAN-OS 多账号解析及事实快照构建；脚本报告三次运行的中位数，请在同一机器和 Ruby 版本下比较不同修订。

使用声明的最低 Ruby 版本检查兼容性。方法用途统一使用简明中文注释；复杂实现还需说明业务规则、实现思路及关键分支。保持公开返回值与错误契约。真实回显和凭据不可进入示例、fixture、日志或发布包。

## 发布

本目录可独立维护为 [baseline-rb](https://github.com/gatework/baseline-rb) 仓库。更新 `VERSION` 和 `CHANGELOG.md`，运行上述验证与构建命令，检查包内文件，再创建 `vVERSION` 标签。

CI 在 Linux、macOS 上执行测试、lint、示例、构建和隔离安装。`main` 的 CI 通过后推送 `vVERSION` 标签，工作流将已验证的 Linux 产物发布到 RubyGems 和 GitHub Release，附带 `SHA256SUMS` 并回读下载字节。GitHub `release` environment 可配置 `RUBYGEMS_API_KEY` secret；未配置时使用 RubyGems Trusted Publishing，绑定本仓库、`release.yml` 和 `release` environment。失败时重跑失败的发布 job，以复用原 CI 产物；同版本已存在时必须校验字节一致。详见[发布说明](docs/release.md)。

先发布依赖模块。标签、构建成功或工作流文件都不等于已经发布，需单独确认 RubyGems 的实际结果。版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

MIT，见 [LICENSE](LICENSE)。

凭据审核方案在 `check.details[:credentials]` 中逐对象列出不安全存储或可观察的弱口令，保留来源行、用途、具体偏差、材料及消费者/恢复依赖。密文强度要求外部证据，不直接判弱；SNMP 认证与加密材料分别标识。此类检查仍受阻，普通方案不包含替换秘密或占位命令；能力查询继续标记秘密命令生成不支持，并解释人工材料要求。参见[凭据审核示例](examples/remediation_credentials.rb)。

Comware/VRP TACACS 密钥按替换、撤销及方案重新进入后的最终状态归纳。`check.details[:key_slots]` 分别列出 H3C 认证/授权/计费及 Huawei 共享材料，关联已知端点并提示对端、AAA 引用和恢复前提。损坏状态需补证，检查仍受阻，不生成秘密命令。当前模型描述方案密钥，不代表已支持端点私有密钥继承。参见[TACACS 材料示例](examples/remediation_tacacs.rb)。

Comware/VRP `aaa.bindings` 描述选中管理域的有序方法、TACACS 职责/组/端点引用、来源行及登录 VTY；本地后备与 `none` 分开记录，均不代表恢复访问已经可用。TACACS 使用检查复用这些证据，拒绝旧值和损坏引用。人工方案列出具体链路证据与批准前提，不自动挑选候选组或生成认证切换命令。当前覆盖选中域，尚非所有域/共享引用的完整清单。参见[AAA 审核示例](examples/remediation_authentication.rb)。

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

本库不连接设备、不采集备份、不修复配置、不写数据库。Motor 持久化和 `Baseline::Check` 属于宿主应用。

详细厂商语义、历史验证记录和 Motor 专用集成说明保留在[架构参考](docs/architecture-zh.md)。其中宿主集成代码需要 Motor，不属于独立 gem API。适配层位于 [Motor 仓库](https://github.com/gatework/motor/tree/main/backend/lib) 的 `backend/lib/baseline`、`backend/lib/vxlan` 和 `backend/lib/wireless`。

## 领域术语

`FactBuilder` 汇总配置证据，`Policy` 提供批准值，`Evaluator` 生成合规判定。`Acl#permitted_source_networks` 按有序规则、协议和目标端口计算允许的 IPv4 来源网段：`nil` 表示证据未解决，`[]` 表示没有允许来源。`FactBuilder#record_credential` 记录安全的凭据属性。部分证据可以证明确定违规，但不能证明合规。

全部 30 项指标及逐项验收边界见[指标覆盖说明](docs/baseline-metrics.md)。数量指标统计不同服务器，重复采集同一地址不能满足冗余要求。

`Evidence#resources` 提供不可变的 Syslog 配置对象和 NTP 关联，保留厂商身份、作用域、选项及来源行，避免将去重地址误用为配置对象。每项 `ConfigurationResource#complete?` 只表示该对象语法是否被完整理解，不代表配置采集完整、引用链已生效或设备合规；未知选项不会复制进资源数据。资源层正在为离线修正方案提供基础，当前尚无公开的命令生成入口。

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

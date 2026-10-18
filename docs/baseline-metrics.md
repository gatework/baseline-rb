# 基线指标覆盖与验收

指标目录以 `Baseline::Rule::DEFINITIONS` 为准。新增规则必须同步补充 `spec/all_metrics_contract_spec.rb` 中独立声明的预期值、通过事实和偏离事实。默认策略保留30项基础检查；另外3项对象级规则需显式声明批准对象，不自动启用。

| 领域 | 指标 ID | 业务判定 |
| --- | --- | --- |
| SNMP | snmp.enabled | 服务状态符合要求 |
| SNMP | snmp.versions | 实际版本不超出批准集合 |
| SNMP | snmp.write_enabled | 写权限状态符合要求 |
| SNMP | snmp.auth_priv | v3 用户具有认证及加密证据 |
| SNMP | snmp.acl_bound | 来源控制已引用 |
| SNMP | snmp.acl_restricted | 来源范围受限 |
| SNMP | snmp.sources | 有效来源不超出批准范围 |
| NTP | ntp.minimum_servers | 不同服务器数达到最低要求 |
| NTP | ntp.servers | 服务器地址集合与批准集合一致 |
| NTP | ntp.authentication | 显式认证开关符合要求 |
| NTP | ntp.source | 源接口符合批准值 |
| Syslog | syslog.minimum_servers | 不同服务器数达到最低要求 |
| Syslog | syslog.servers | 服务器地址集合与批准集合一致 |
| Syslog | syslog.source | 源接口符合批准值 |
| SSH | ssh.enabled | 服务状态符合要求 |
| SSH | ssh.versions | 实际版本不超出批准集合 |
| SSH | ssh.vty_ssh_only | 所有已建模 VTY 仅接收 SSH |
| SSH | ssh.vty_aaa | 所有已建模 VTY 使用账户认证 |
| 管理访问 | management.acl_bound | 管理端点有来源控制引用 |
| 管理访问 | management.acl_restricted | 管理来源受限 |
| 管理访问 | management.sources | 有效来源不超出批准范围 |
| 服务 | services.disabled | 批准关闭的每种服务均有关闭证据 |
| 凭据 | credentials.storage | 可观察存储属性满足安全要求 |
| 凭据 | credentials.strength | 可观察明文满足长度、字符类别及常见口令限制 |
| TACACS | tacacs.minimum_servers | 不同服务器数达到最低要求 |
| TACACS | tacacs.servers | 服务器地址集合与批准集合一致 |
| TACACS | tacacs.login | 实际管理认证链引用 TACACS |
| TACACS | tacacs.authorization | 已建模授权动作引用 TACACS |
| TACACS | tacacs.accounting | 已建模审计动作引用 TACACS |
| TACACS | tacacs.keys | 已建模服务器或职责具备所需密钥声明 |
| Syslog 对象 | syslog.destinations | 目标身份、作用域、明确批准的端口等属性及受管范围内的额外对象 |
| NTP 对象 | ntp.associations | 服务器/peer、路由域、明确批准的版本及认证key引用等属性 |
| TACACS 对象 | tacacs.endpoints | 方案/命名对象、职责/主备、路由域和明确批准的端口等属性 |

每项都有七种独立的评估回归：证据充分通过、确定偏离、事实缺失、批准值缺失、明确范围不匹配、不完整输入、带局部诊断的保留事实。服务器数量和批准集合另有重复观测回归，适用条件另有损坏事实类型回归。

上述是评估器契约的覆盖，不等于各厂商所有语法已实现。厂商解析、ACL 顺序、SNMP 权限、认证引用、凭据脱敏及部分输入有各自的专项测试。`Audit.capabilities(platform:)` 提供每个平台每项指标的 supported/partial/unsupported；运行结果仍可能因当前配置证据不足而 unknown。六个平台的同一指标目录不能省略未建模项或将其算作通过。

NTP 与 Syslog 的配置资源保留了用于后续生成的对象参数。NTP 区分 server/peer、路由域和 PAN-OS 主备槽位；`ntp.servers` 保持服务器地址集合语义，不把 peer 自动算成 server。资源的 complete 只表示对象语法被理解，不证明认证密钥可用、同步成功或当前链路可达。

`Remediation` 已提供逐项状态及部分设置命令。当前完整命令生成工作尚未完成，仍须覆盖对象及引用增删、更多厂商命令、缺参受阻原因、跨指标冲突和修正后复查。不能用本页的测试数量代替这些验收，也不能通过删除凭据或关闭整个服务来绕过其他启用指标。

开发验证：`bundle exec rake`。现有备份只用于本机聚合验证，不能作为批准参数来源，也不能复制进测试或发布包。

## H3C VTY 继承证据

Comware 的范围级 `authentication-mode` 和 `protocol inbound` 相互绑定：任一范围级非默认设置都会使两项采用范围值；不能分别从 class 补齐另一项并判通过。范围级两项均为默认或未配置时，才保留 class 设置。未显式出现的范围默认值在当前审计中保留未知，避免跨版本推定。损坏的范围撤销命令不能被 class 覆盖掩盖。

依据：[H3C Login management commands](https://www.h3c.com/en/d_202504/2410608_294551_0.htm)，`authentication-mode` / `protocol inbound` 的绑定规则。生成器额外要求 H3C/Huawei 待修改范围明确配置兼容认证；不能仅凭继承证据输出协议修正。

## H3C SNMP 版本证据与收紧

版本启用声明按集合累加，`undo snmp-agent sys-info version` 仅撤销所列版本。损坏声明、没有初始版本集合的局部撤销不能保留旧的通过值；Huawei 的固件语法单独处理。依据：[H3C SNMP command reference](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-24948/13/202601/2739237_294551_0.htm)。

H3C 的版本修正只删除未批准版本，保留现有已启用的 v3、用户及来源限制。除了 authPriv 用户和组引用证据，还须在规则的 `remediation.existing_v3_access_verified` 声明人工已验证现有 v3 管理路径；该参数只能为布尔值。用户/组撤销语法尚未完整归约时，审计保留未知并阻止生成；不能借助这项收紧声明整个 SNMP 权限或认证链已修复。

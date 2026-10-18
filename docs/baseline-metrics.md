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


## 管理 ACL 规划边界

`management.access_endpoints` 按 VTY 与传输协议保留端口、串联 ACL、有效来源和完整程度；多个 ACL 同时生效时来源取交集，不从某一层补出更宽许可。`acl.identifiers` 保留定义及别名，H3C 的 `acl.reserved_numeric_ids` / `acl.reference_uses` 另保留已识别引用中的数字标识，防止新建 ACL 意外激活悬空引用。来源证据包含参与计算的各层 ACL 行号。

命令生成目前限于 H3C `line vty`、IPv4 与全新基本 ACL 标识：现有有效来源与批准上限求交；首次建立必须另行批准实际目标。相同范围的多个传输协议只有在同一基本 ACL 能保留各自的最终许可时才可生成。创建阶段先于绑定更新，旧 ACL 和其他引用保持不动；显式空目标才能生成拒绝全部来源。此能力不代表所有业务 ACL 引用、固件默认值或 IPv6 已建模。

厂商语法依据：[H3C VTY ACL 命令](https://www.h3c.com/en/d_202504/2410608_294551_0.htm)、[H3C SSH server ACL 命令](https://wwwsg-proxy.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-29707/09/202603/2792736_294551_0.htm)。这两种访问过滤处于不同层次；串联过滤按允许集合交集建模，尚未做真实设备下发验证。


## 管理 ACL 厂商扩展与标识占用

Huawei 生成 `acl number`、`acl ... inbound`；IOS 生成命名标准 ACL 和 `access-class ... in`。IOS 的 `vrf-also` 影响可达的 VRF 范围，已有绑定保留原值，首次绑定必须批准布尔 `vrf_also`。来源范围参数不能替代 VRF 范围参数。

`Remediation` 先复制并冻结输入，再用同一快照审计和检查批准 ACL 标识的出现情况；检查只返回策略已经提供的标识，不导出任意原始配置词元。完整输入中出现该标识（含数字前导零、未建模命令、横幅或注释）时，保守拒绝作为新 ACL 使用。缺少这份占用检查的内部 planner 调用也不能生成 ACL。此检查补充定义/引用识别，不代表完整的共享对象更新/删除引用图已经完成。

语法依据：[Huawei VTY ACL 配置例子](https://support.huawei.com/enterprise/de/doc/EDOC1100212297/c947deef/example-for-configuring-an-acl-to-limit-telnet-login)、[Cisco IOS XE ACL 配置](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/security/acls/acls-configuration-guide/access-control-lists.html)、[Cisco IOS XE VTY VRF 绑定例子](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/device-access-policy.pdf)。仍需人工审核固件适配和管理连通性；没有真实设备执行证明。

IOS 标准 ACL 编号按 1–99/1300–1999 校验；命名标识要求以字母开头，使用库既有的单词元允许列表及253字节边界，不将其他协议的63字符限制套入 IOS。格式依据：[Cisco IOS XE ip access-list 命令参考](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-12/command_reference/b_1712_9500_cr/security_commands.html)。


## H3C SNMP 分层来源与声明覆盖

H3C 的用户、组及全局 ACL 会串联过滤；不能用用户 ACL 替代更严格的组 ACL。`snmp.access_endpoints` 对各主体保留 ACL 链、UDP 监听端口、有效来源和完整程度；团体字只用序号作为端点标识，不保留秘密或其摘要。`snmp.global_access` 单独记录全局过滤和命令支持证据。无任何引用且声明完整的主体按 IPv4 来源未限制处理；缺失/损坏/复杂 ACL 仍保留未知。IPv6 ACL 不可误归入 IPv4。

`snmp.group_definitions` 保留安全级别及读/写/通知视图引用，未知选项或重复 ACL 参数不能误报来源已知。视图名、组名可以与选项词同名，必须按参数位置消费。H3C 同名完整 VACM 用户以最后一次声明为准，旧认证、ACL 和凭据记录不得残留；Huawei 的分行配置保持增量语义。命令级 cipher/simple 与每个密钥的格式声明分开分析，普通报告不包含密钥。

全局来源修正创建新 ACL 后才重绑；原团体字、用户、组及共享旧 ACL 均不修改。没有全局命令证据时须明确确认固件支持；未绑定主体需批准实际来源，不能把批准上限直接当作初始允许集合。同一设备多个领域争用新 ACL 标识时按策略冲突受阻。源过滤与协议版本、MIB 权限分别检查，不将关闭 SNMP 作为其他规则的修复手段。

依据：[H3C 全局 SNMP ACL 命令](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-24948/13/202601/2739237_294551_0.htm)、[H3C SNMP 用户与组命令](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_S6520X_MS4600_CRs_R6628Pxx-10752/11/202407/2215723_294551_0.htm)。命令存在于特定设备参考中不代表所有固件支持；当前只输出人工审核方案，没有设备执行或 NMS 连通性证明。

## SNMP 启用证据边界

Comware/VRP 的 `snmp.enabled` 按命令顺序归约：独立 `snmp-agent` 和 `undo snmp-agent` 明确启停，完整且已支持的团体字、组、用户、版本及监听设置可证明隐式启用。H3C 完整全局 ACL 绑定也可提供此证据。未知或损坏的正向语句不能证明启用，也不能证明仍处于默认禁用；没有独立启用证据时返回未知。后续明确启停或有效隐式启用可消除先前的状态歧义。未出现任何声明的默认禁用只用于完整输入。

H3C 的 `calculate-password` 是不启用服务的工具命令，参数不进入报告；此例外不跨平台套用到 VRP。未建模的合法命令仍可能产生未知，需要继续补充厂商语法证据。`snmp.enabled` 描述代理功能状态，不单独证明监听可达、NMS 连通、版本或 MIB 权限合规。

依据：[H3C 启用与密码计算命令](https://www.h3c.com/en/d_201506/873135_294551_0.htm)、[Huawei SNMP 系统视图命令](https://info.support.huawei.com/enterprise/en/doc/EDOC1100459901/30eb7700/snmp-configuration-commands)、[H3C 全局 ACL 编号和命名范围](https://www.h3c.com/en/d_202507/2589658_294551_0.htm)。

## 凭据轮换与补证对象

`credentials.storage` 和 `credentials.strength` 的审核方案在 `details.credentials` 中列出需要处理的对象：配置内序号、账号/用途、来源行、具体偏差、`rotate` 或 `verify`、所需材料及依赖。序号只在当前配置指纹内有效；团体字保持匿名，不用秘密或其摘要作为身份。SNMP 的 authentication/privacy 用途在六类适配器中分别保留；Comware/VRP TACACS 密钥保留各自职责或 shared 用途。

明文/旧格式存储，以及可观察到的弱口令要求批准替换材料、厂商支持的保护格式和人工轮换过程。方案按消费者提示 NMS 同步、TACACS 对端同步、认证引用及本地后备/恢复路径验证；这些是待核实条件，不表示已建立完整引用图或已验证管理连通性。未知存储格式要求补存储证据；密文/散列的强度要求外部证据，不能因此直接断言需要轮换。规则允许相反存储目标时，不生成降级到明文的命令。

此处理不会生成带秘密或秘密占位符的命令，检查仍为 blocked；缺策略、不适用或不完整输入不会被改写为轮换授权。能力查询仍把秘密命令生成标为 unsupported，同时给出人工材料处理原因和条件。[凭据审核示例](../examples/remediation_credentials.rb) 展示对象要求和秘密排除。

## HWTACACS 密钥最终状态与材料要求

Comware/VRP 的同名方案或模板重新进入会合并声明；整组撤销在服务器、凭据及资源归纳前移除该组。每个方案密钥槽位按命令顺序归约，撤销不保留旧凭据，替换只分析最后材料；损坏声明不能回落到旧的通过值，后续完整设置可重新确定状态。局部输入缺失的槽位保持未知，不凭空构造已观察凭据。

`tacacs.key_slots` 保留组、职责、方案级来源、present/complete 及来源行，不保留秘密。现有 `tacacs.keys` 基线契约保持：H3C 检查 authentication/authorization/accounting 三类方案密钥，Huawei 检查 shared；此处尚不将端点私有密钥或其他型号继承规则等同于方案密钥，其他厂商没有自动套用此模型。

`tacacs.keys` 的 `details.key_slots` 对缺失材料列出 provision、批准密钥材料、保护存储格式、人工配置步骤及高风险；对损坏状态列出 verify 和补证要求。端点引用按组和职责关联，共享密钥关联模板全部端点；端点未解析、缺少消费者范围、对端同步、AAA 引用或本地后备访问仍列为待核实依赖，不假称认证链已经可用。没有方案时要求批准方案和端点；不会从备份发明它们。检查保持 blocked，不生成秘密、占位符或移除密钥的降级命令。参见[材料要求示例](../examples/remediation_tacacs.rb)。

语法依据：[H3C Comware 7 key/undo key 命令](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_S6520X_MS4600_CRs_R6628Pxx-10752/09/202407/2215673_294551_0.htm)、[Huawei 模板共享密钥撤销](https://info.support.huawei.com/hedex/api/pages/EDOC1100363264/AEN0403J/06/resources/command/yunshan/HWTACACS-SERVER-SHARED-KEY%28HWTACACSOM%29.html)。Comware 旧版本带秘密参数的撤销形式未按 Comware 7 处理；未知形式保留未知，不声称跨版本验证。

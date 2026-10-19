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

## StoneOS NTP 原生身份与材料

[StoneOS 5.5R6 系统管理 CLI 指南](https://kb.hillstonenet.com/en/wp-content/uploads/2018/08/StoneOS_CLI_User_Guide_System_Management_5.5R6.pdf) 给出最多三台服务器、按地址删除，以及 key/source/prefer/vrouter 参数。资源仍以地址、server 职责和当前路由域表示；解析先按全局规范地址归约最终声明和撤销，不把同地址的不同 vrouter 当作两台原生服务器。损坏的最终声明不能回退到旧配置，未知 peer 命令不能证明空库存。完整输入中未声明认证开关时，采用文档规定的关闭缺省值；部分输入不采用此缺省。prefer 未声明时，记录未显式优先的 false，不推断实际选用哪台服务器。

生成要求明确批准的目标和作用域。跨路由域迁移必须同时批准原作用域和新作用域；原生 `ntp.server` 操作将可变 vrf 放入完整前后状态，避免先新增后删除同一全局地址。省略字段保留物理服务器原配置；显式 prefer:false 可取消优先标志。按文档原生三台容量核验每步；未提供重复的整体容量值时，可使用该已知原生上限。调用方提供更小容量仍是约束，更大值不能覆盖原生上限。域名长度及 key ID 分别按文档的 127 字符与 1..65535 校验；IPv6 地址作为地址参数，不臆造其他厂商的 ipv6 关键字。

`ntp.source` 在 StoneOS 是关联字段，不能用虚构的全局命令设置。共同批准值通过明确的 `ntp.associations` 与受管作用域逐台应用；与对象显式 source 或未受管服务器的最终来源冲突时受阻。来源指标参与最终约束及操作风险计算。原来没有显式 source 的服务器仍保留审计 unknown，但完整且已解析的对象可以按明确批准值设置；同样允许在材料和对端前提满足后设置显式 key 引用。此例外只适用于 StoneOS 的 source/key_id，不绕过部分输入、损坏库存、未知绑定或其他字段。

未指定 vrouter 的作用域是 `{vrf: default}`；显式名称也为 default 的路由器使用 `{vrf: default, vrf_mode: named}`，批准对象和 `managed_scopes` 都精确匹配该标记。二者不能共用默认哨兵，不能因更新来源而丢弃显式路由限定词，也不能借默认范围删除另一上下文的服务器。NTP 原生前后状态用 `vrf_explicit` 保留这项区别；带 key 的上下文切换同样要求外部对端核验。同一作用域标记也用于 StoneOS Syslog，正向及删除命令均保留显式限定词。

`ntp.key_slots` 保存最终材料存在、算法、格式及来源行，不保留秘密。StoneOS 该语法没有独立的可信声明，显式记录 `trust_required:false`、`trusted:nil`，不能把它伪装成 Comware/VRP 的 trusted:true。`ntp.authentication_bindings` 的配置就绪状态基于已知材料、关联引用和认证开关；无法识别材料更新时，逐关联就绪也保持未知。最终 md5 材料作为明文凭据元数据参与存储/强度审计；损坏、未知、撤销和接口内声明不能提供材料。新引用、地址更换或带 key 的路由迁移需要 `ntp_peer_key_compatibility_verified:true`；不输出新密钥、占位材料或服务开关。全局认证按单独契约核验全部关联后切换。低层呈现调用必须提供规划器已核验的完整操作标识。

[公开示例](../examples/remediation_hillstone_ntp.rb) 与独立状态模型验证离线配置变换、无关原文保留及再次零变更。StoneOS 文档还说明 NTP 服务缺省关闭；服务器对象符合策略不证明服务启用、同步、接口与 vrouter 存在、对端接受或网络可达。审核后执行前仍须核对这些实际条件，既有密钥的就绪也不证明其强度或对端材料相同。

## PAN-OS NTP 主备槽位

`ntp.associations` 使用命名槽位 `primary-ntp-server` / `secondary-ntp-server`、`scope: {}` 和明确 `managed_scopes: [{}]`。不能从旧地址集合推导应使用哪个槽位。新增须提供地址及 `authenticated: false`；删除按完整槽位树定位；已有对象只修改地址叶子，保留认证子树和另一槽位。未知对象选项不能当作删除整个槽位的完整证据。

已认证槽位更换地址时须经 `ntp_peer_key_compatibility_verified: true` 记录外部核验，呈现器同时要求规划器传递已验证槽位名称。此标记不证明同步、密码强度或运行可达性。新增认证或变更认证方式/材料保持受阻；普通输出不包含已有材料。删除全部槽位不能使仍启用的认证规则丢失证据。

语法依据：[PAN-OS 11.2 配置命令层级](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy) 与 [修改配置](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/modify-the-configuration)。适用本机完整 set 导出，不涵盖 XML、Panorama 模板继承或实际设备提交验证。独立测试状态模型按路径应用命令并重新审计，覆盖保留未修改原文、认证依赖及再次零变更。

## PAN-OS Syslog 配置引用链

服务器资源可声明 `bindings` 精确集合：`syslog.device` 身份为 `kind/log_type/match`；`syslog.forwarding` 身份为 `kind/forwarding_profile/match/log_type/context/rulebase/rule`。设备日志类型覆盖已建模的 system、config、userid、iptag、globalprotect、hipmatch、correlation；规则转发日志类型覆盖 traffic、threat、wildfire、url、data、tunnel、auth、decryption。名称按原文匹配；当前 CLI 上下文使用 `context: local`，显式虚拟系统使用 `context: vsys` 并额外要求 `vsys` 身份。两者不能通过同名哨兵合并；security/default-security-rules 也分别保留。

转发 profile 只定义匹配项但未挂接规则时，不计为规则使用链。规则选用的最终 profile 生效，列表 set 引用累加。规则转发绑定的 `disabled/log_start/log_end` 是可选批准谓词；省略不比较，缺少显式事实时要求这些字段的检查返回 unknown。只证明配置引用，不证明规则命中、过滤式覆盖、日志启用默认值或实际投递。完整且已建模的空引用可与 `bindings: []` 匹配；省略 bindings 仍仅核验对象定义。

`syslog.profile_references` 保存非秘密引用，`syslog.reference_inventory_complete` 表示此库存是否完整。未知命令族、损坏列表、未解析转发目标、vsys 本地日志对象、模板/设备组或多行引用均不能证明没有使用关系。引用证据未知不把独立对象定义伪装成引用合规。过滤式、描述和动作载荷不进入公开资源；每个资源保留参与证据的行号。`syslog.reference_sets` 另按匹配项保存接收 profile 集合、全部规则/zone 消费者及来源行；即使接收集合为空，也不会丢失消费者。

语法依据：[PAN-OS 11.2 命令层级](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy) 和 [官方转发配置示例](https://docs.paloaltonetworks.com/vm-series/deployment/public-cloud/set-up-the-vm-series-firewall-on-oracle-cloud-infrastructure/oracle-cloud-infrastructure-logging)。后者的 Kafka/插件与运行验证不属于本库能力。

Zone 消费者使用 `syslog.zone`，身份为 `kind/forwarding_profile/match/log_type/context/zone`；显式 `context: vsys` 同样额外要求 `vsys`。按 `zone ... network log-setting` 的最终选择解析，不能因为没有规则消费者就证明未被使用。其他未建模消费者、本机 vsys 日志对象及本地 log-settings 命令保留未知。

共享服务器命令仅定位 `shared log-settings syslog <profile> server <name>`。更新只设置有变化的 server/transport/port/format/facility 叶子；删除只到 server，不删除整个 profile、格式、过滤式或引用。新增参数必须明确，已有未批准字段保留；端点变化要求已知协议及端口，不能拿未验证的隐式端口完成传输切换。所有命令先核验完整引用库存；普通低层呈现调用须传入规划器已核验的完整操作标识，不可默认跳过前提。

`syslog.declared_profile_references` 统计每个 profile 的配置引用声明（包括未挂接的转发定义），与实际规则/zone 使用边数分开。按批准迁移投影后仍有任何声明引用时，不能清空该 profile 的全部服务器。首次补全原悬空 profile 时须明确批准与现有使用链匹配的 bindings，不能借创建服务器隐式改写引用。引用变更按下述单独批准执行。

新增 SSL 目标或修改后仍为 SSL 的地址/端口/协议变更要求 `remediation.syslog_tls_peer_compatibility_verified: true`，表示外部已核验对端及证书配置；不从旧备份推断新对端适用性，不导出或创建证书秘密。同一 SSL 端点只更新格式/facility 时保留认证配置。该字段严格为布尔值，只用于对象规则。原生单 profile 最多四个服务器；同时服从明确批准的整体容量，中间候选树超限时先删除批准移除的对象并提高风险等级。命令仅修改候选树，不保存或提交。

原生字段、四服务器上限与 SSL 依赖依据：[PAN-OS Syslog 配置](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring)；profile/server 命令名称采用 [11.2 字段文档](https://docs.paloaltonetworks.com/ngfw/help/11-2/device/device-server-profiles-syslog) 的31字符及字母、数字、空格、连字符、下划线范围，并保持库已有首字符约束。审计名称仍沿用公共资源边界，超出已验证原生命名语法时不生成。zone 命令见 [11.2 新增命令](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-changes/new-set-commands-11-2)。本库没有实机配置、证书握手或日志到达验证。

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

H3C 每种认证/授权/计费职责的主服务器按单槽位归约，替换和无地址 `undo primary <role>` 在提取地址/资源前生效；被替换地址不能再充当冗余服务器或密钥消费者。多台 secondary 和独立职责保持分离，此单主槽位规则不跨平台套用到 Huawei。依据：[H3C 主备服务器数量与命令](https://wwwsg-proxy.h3c.com/en/Support/Resource_Center/EN/Home/Wireless/00-Public/Configure___Deploy/Configuration_Guides/H3C_AC_CG_R5426P02/13/202104/1399926_294551_0.htm)。

## 管理域的 AAA / TACACS 绑定证据

Comware/VRP 的 `aaa.bindings` 为选中的默认管理域保留三类职责的有序方法、域/方案、TACACS 组及端点引用、来源行和登录 VTY。`local_fallback` 只表示方法列表声明了本地后备；`allows_none` 单独标记不认证/不授权/不计费的退路。两者均不证明本地账号、权限或恢复通道可用。`complete` 表示此模型中的域、方法及 TACACS 使用链可解析，不证明设备连通性、密钥正确或其他 RADIUS/LDAP 服务可用。

域选择按最后声明归约，损坏语句不沿用旧选择；选中域不存在时为 unknown，不能据此证明未使用 TACACS。支持 Comware `domain name` 形式、同域/方案重新进入，以及按名称不区分大小写解析方案引用。Comware 的 login 方法撤销恢复域 default，default 撤销恢复文档中的本地方法；完整输入缺省选择 system/VRP default_admin 时仍要求对应域在模型中明确存在，不凭空补造域配置。Huawei 模式必须完整消费，撤销、未知尾部和矛盾 local/local-case 不能靠旧值或首词产生通过；计费模式限制为当前已支持的单一方法。

TACACS 标量使用检查从同一绑定证据归纳，来源包括域选择、方法、方案、实际服务器和 VTY 行。端点未完整解析时不确认其引用可用。`aaa.bindings` 保留选中管理域视角；`aaa.domain_bindings` 扩展记录已建模的全部显式域，未选中域的共享引用也不会丢弃。`aaa.domain_bindings_complete` 按职责标记完整输入下的库存确定性；显式用户的实际登录路径、其他服务提供者和其他厂商的绑定仍需分别建模，不据此自动更新/删除共享认证对象。

`tacacs.login/authorization/accounting` 和 `ssh.vty_aaa` 的审核结果可列出具体绑定、缺少的域/方法/端点/VTY 证据、当前候选服务器组以及批准链、材料和本地恢复前提。候选组不等于批准目标；普通 AAA VTY 检查不强制使用 TACACS，也可批准本地 AAA 方案。当前检查仍 blocked，能力查询仍将认证链命令生成标为 unsupported；这些人工要求不表示已有自动切换或完整 `bindings` 策略写入支持。参见[认证链审核示例](../examples/remediation_authentication.rb)。

依据：[H3C 登录方法、默认继承及有序后备](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-35328/13/202609/2929796_294551_0.htm)、[H3C 默认域选择与撤销](https://www.h3c.com/en/d_202301/1749967_294551_0.htm)、[Huawei AAA 模式和管理域选择](https://support.huawei.com/enterprise/en/doc/EDOC1100412529/c0449dc0/aaa-configuration-commands)。当前语法范围和未建模默认值仍须按设备版本核实，不代表所有固件验证通过。

## 结构化 TACACS 域绑定策略

`tacacs.endpoints` 的对象可声明 `bindings`，当前仅接受 `aaa.domain`：

```yaml
identity: {address: 192.0.2.30, role: authentication, priority: primary}
scope: {group: OPS}
bindings:
  - {kind: aaa.domain, domain: ADMIN, role: authentication, position: primary, selected: true}
```

`domain/role/position` 是完整绑定身份。`position` 表示该域方法链中的首选或后备方法，与服务器对象自身的 primary/secondary 优先级不同。域名按已支持的 Comware/VRP 语义不区分大小写；职责限 authentication/authorization/accounting，位置限 primary/fallback。可选 `selected` 要求该域是否为当前选中管理域；省略表示不比较选择状态，不等同于 false。未知字段、原始路径/命令、重复逻辑身份及非法值均拒绝。

显式 `bindings` 数组是该对象的完整期望域引用集合，报告缺失、多余及选择状态变化。`[]` 要求已知未引用；只有完整输入、相关职责的域/方法和引用库存均确定时，才提供可比较的空数组。省略 `bindings` 只核验对象定义，不修改、不清除现有引用。JSON 使用 `details.verification_scope` 明确范围，文字报告直接提示“仅对象定义，未核验使用链”。

资源 `.bindings == nil` 或对象事实中缺少 bindings 表示未知，不是未绑定。未选中域、重新进入及撤销后的关系纳入库存；匿名/损坏域和未知方法不允许证明引用集合完整。按职责记录完整程度，未知计费引用不应掩盖已解析的认证引用。其他厂商尚未建模的绑定保持 unknown；PAN-OS Syslog 的独立绑定类型见前文，NTP 尚未开放此字段。`Audit.capabilities` 的资源项通过独立 `bindings` 子项列出已支持类型及 conditional/unsupported，不改变对象定义层面的原能力含义。

绑定比较不等于引用改写。当前方案展示实际共享引用和差异，要求批准变更范围、保留或迁移关系、有序方法及本地后备，并完成厂商命令验证；不会因省略 bindings 或提供空数组自动删除共享对象。尚未生成 TACACS 绑定切换命令。域引用检查也不替代 VTY、密钥和真实后备访问验证。[完整离线示例](../examples/resource_bindings.rb) 使用独立合成前后配置演示对象存在但引用错误的失败，以及正确域引用的通过。

绑定证据补充保留不可变资源值对象，只复制新增的绑定及行号；不会为了补关系再次解析已验证的端点身份。选中域视图和全域库存由同次拥有的不可变图派生，避免重复深拷贝，调用方可变数据仍不能影响快照。`script/benchmark.rb` 增加 10/100 个合成域共享同一组的完整审计；规模只用于软件测量，不表示设备域数量上限或实际吞吐。

### 名称身份按厂商及对象类型区分

Comware HWTACACS 方案名不区分大小写：重新进入或撤销不同大小写的同名方案时，先合并/撤销同一身份，再归约主服务器与密钥；不能把大小写变体当作两台冗余服务器。Huawei HWTACACS 模板名区分大小写，定义 OPS 与引用 ops 不能借名匹配，两个不同模板也不能互相混入绑定。域名仍按其已支持的不区分大小写规则处理；Huawei 命名 AAA 方案按完整名称匹配，不从域名规则推断方案等价。对应版本如有其他名称规则，须通过明确 profile 扩展，未确认的别名不作为通过证据。

依据：[H3C 方案名称命令参考](https://wwwsg-proxy.h3c.com/en/Support/Resource_Center/HK/Switches/H3C_S5500/H3C_S5500_Series_Switches/Technical_Documents/Reference_Guides/Command_References/H3C_S5500-SI_CM%28V1.01%29/200712/211835_294551_0.htm)、[Huawei 模板名称命令参考](https://info.support.huawei.com/hedex/api/pages/EDOC1100278054/AEL11217/07/resources/dc/hwtacacs-server_template.html)、[Huawei 域及命名授权方案参考](https://support.huawei.com/enterprise/en/doc/EDOC1100412529/c0449dc0/aaa-configuration-commands)。


## Comware 7 TACACS 端点修正

H3C 现有方案的缺省路由端点支持物理主槽位替换、逐地址/端口增删备服务器，保留职责密钥及所有已解析域引用。需明确 `tacacs.endpoints` 目标及 `managed_scopes`，批准 `syntax_profile: comware7`，并由外部核实 `local_fallback_access_verified` 与 `tacacs_key_compatibility_verified`。字段未声明时保留旧槽位端口和 single-connection；全新端点使用此 profile 已确认的 TCP 49 和非共享连接缺省值。不能从配置密文证明对端密钥匹配或本地恢复访问可用。

主服务器地址替换直接设置原生槽位；取消 single-connection 需撤销后重建，因此已引用职责必须有另一个端点。备服务器撤销必须带地址及端口，不生成无参数的全量撤销。逐条验证容量和已有引用不失去最后端点；满 16 台备服务器时先增后删受阻，可明确批准先删后增。共享域引用变更、方案 VPN、私有密钥、同址多端口及文本别名迁移仍需独立实现，不能将当前子集视为完整 TACACS 修正支持。仅保留配置中的路径不代表服务器实际可达；人工执行前还需确认移除不影响正在使用的认证过程。

语法及边界依据：[H3C Comware 7 HWTACACS 命令参考](https://www.h3c.com/en/d_202206/1617723_294551_0.htm) 中的 primary/secondary authentication、authorization、accounting 章节，而非同页的 RADIUS 同名命令。通过独立测试状态模型逐条应用原生命令后重新审计，并检查无关配置及第二次零变更；未连接真实设备。


## 方案复查、人工持久化与恢复意图

`RemediationPlan#review` 与 `to_h[:review]` 提供独立的 `validation`、`persistence`、`rollback`。`to_text` 也分别列出提示，不将检查或保存命令追加进 `configuration_commands`。非空方案的检查均为 `not_executed`，保存为 `manual_only`；无变更方案不建议保存或回退。包含受阻指标时保留 contains_unresolved_checks，不能因为存在检查入口而将 partial 变成 ready。

检查入口为 H3C/Huawei 的 display current-configuration、IOS/NX-OS 的 show running-config、StoneOS 的 show configuration，以及 PAN-OS 的 show config diff / show config candidate。这些只是按目标版本人工确认的配置检查入口，不证明业务可用；还需核验时间同步、日志投递、NMS 读/通知/禁止写、管理通道或 AAA 本地后备。完整回显须在受控通道处理，不能复制进普通报告或日志。再次审计必须使用完整且适配器可解析的运行配置与同一批准策略；PAN-OS 原生候选输出不等于 set 输入，更不等于已提交配置。

保存提示仅在独立的 persistence 中提供：H3C/StoneOS 的 save、IOS/NX-OS 的 copy running-config startup-config、PAN-OS 配置视图的 commit，均需人工完成审核、验证及必要交互。Huawei 不由厂商名称猜测是否需要先 commit 再 save，commands 为空并标注 requires_target_version_commit_decision。所有提示都不执行，没有自动确认、保存、提交或重启。

rollback 只提供原操作可表达的非秘密 `inverse_operations`，每项关联 source_operation_id，风险至少 high；意图顺序反向于原操作，但不是重新做过容量与引用验证的阶段排序。所有 configuration_commands 均为空，始终要求新快照、独立批准、依赖/容量和基线重审计。回到旧状态可能重现原偏离，approved_baseline_status 保持 not_verified。无变更为 not_applicable，全部逆意图可表达也仅为 requires_replanning；认证/材料迁移、共享 ACL 删除、未建模恢复或旧值未知则记录 unavailable，整体为 manual_required。不能将这些字段解释为自动回退能力或恢复成功。

依据：[H3C 配置检查及保存](https://www.h3c.com/en/d_201906/1191106_294551_0.htm)、[Cisco IOS 配置管理](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-files-0.html)、[Cisco NX-OS 配置管理](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/mds9000/sw/6_2/configuration/guides/fundamentals/nx-os/b_Cisco_MDS_9000_Series_NX-OS_Fundamentals_Configuration_Guide/b_Cisco_MDS_9000_Series_NX-OS_Fundamentals_Configuration_Guide_Release_6_chapter_0111.html)、[StoneOS5.5R6 系统管理](https://kb.hillstonenet.com/en/wp-content/uploads/2018/08/StoneOS_CLI_User_Guide_System_Management_5.5R6.pdf)、[PAN-OS11.2 操作命令层级](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-cli-ops-command-hierarchy)。不同版本需人工核实，离线生成不构成原厂命令在所有固件上的接受证明。

## SNMP 写权限逐对象审核

`snmp.write_enabled: false` 的人工审核信息保留在 `check.details.permission_grants`。写团体字以配置指纹内序号定位，给出来源行和替换为只读的材料、NMS 同步及原视图/ACL 保留要求，不公开团体字或其摘要。组授权列出已解析的各安全级别定义、读/写/通知视图、IPv4/IPv6 ACL 和已知用户消费者；`revoke_write` 是审核意图，不是已验证厂商命令。未解析权限和孤立用户使用 `verify`，`inventory_complete: false` 与补证要求保留，已知违规不能掩盖其他未知主体。

H3C 文档分别定义组名和安全级别，以及省略读视图时的默认读权限、未配置写视图时无写权限。但这不能单独证明重复执行 group 命令会撤回原写视图，更不能推断删组再建不影响用户。缺少明确迁移批准时检查继续 blocked，保留逐对象要求；H3C/Huawei 对下述条件迁移报告 conditional。默认不批准相反的写权限扩张。依据：[H3C SNMP 组命令](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-18349/09/202404/2100798_294551_0.htm)。

### 只读组迁移

`snmp.write_enabled.remediation.group_migrations` 的每项声明 `from_group`、全新 `to_group` 和完整 `users` 名称数组。必须覆盖全部已配置写组；同名组的全部安全级别一起迁移，保留各自读/通知视图与 ACL，仅新组省略 write-view。源/目标组及用户名限本 profile 的单词元 32 字节形式，目标不能覆盖既有组或用户引用，不能以迁移顺序复用别项组名。批准值不从配置推导；写团体字仍需材料提供，存在时本次组权限事务整体受阻。

`syntax_profile` 与 `snmp_group_migration_verified: true` 必须明确给出，表示外部已核实目标版本命令、NMS/通知影响及批准的权限收紧。`vrp_v600` 的有用户组还必须提供 `snmp_user_group_transition_verified: true`：外部已核实该版本的 group-only 用户归属命令保持原有认证、加密、用户 ACL、引擎及通知关系。该标志不能由静态备份或合成状态模型自动推导。生成顺序是创建全部新只读组、迁移全部用户、最后删除全部旧安全级别；Huawei 文档明确删组可连带删除组内用户，因此不允许提前删除或原地重建。用户名保持不变，不重放材料。`comware7` 当前仅支持已确认无用户的写组；其完整用户定义可能替换材料，有用户时返回 snmp_user_material_provisioning，不套用 Huawei 的归属命令。

完整已知的主体清单、全部非秘密组定义和已启用服务是前提。远端引擎、engineid、上下文、proxy、嵌套主体、损坏用户选项、未知安全字段、孤立用户、重复同安全级别定义或用户批准不完整均受阻。`snmp.permission_scope_complete` 只表示本地配置范围已建模；不证明外部 NMS 依赖。当前 `vrp_v600` 不呈现组 IPv6 ACL 等未验证选项。任何操作无法呈现时整项不导出命令；低层呈现也需要匹配完整操作指纹及 profile。操作不包含秘密、save 或 commit。服务、版本、authPriv、读/通知与来源范围必须保留，不以删除全部 SNMP 或使用空视图来改变 write_enabled 的既有判断含义。

`available_group_slots` 为外部已确认的空闲组定义槽位数（0 至 65535），须计入隐式或动态占用；一个组的不同安全级别分别计数。新组定义全部建立前不删除旧组，空闲数不足时受阻，不通过提前删除恢复容量。静态配置只能提供已配置定义，不能证明设备还有空闲槽位。

依据：[Huawei AR5700/6700/8000 V600R024C10 SNMP 命令及删组影响](https://info.support.huawei.com/enterprise/en/doc/EDOC1100459901/30eb7700/snmp-configuration-commands)、[Huawei 组安全级别及 ACL](https://info.support.huawei.com/hedex/api/pages/EDOC1100149308/AEJ0713J/17/resources/cli/snmp-agent_group.html)。独立状态模型验证逐步顺序、材料原文保留和二次零变更；没有 Huawei 真实备份、设备下发或实际 NMS/通知测试。参见[合成迁移示例](../examples/remediation_snmp_group_migration.rb)。


## NTP 材料、可信声明与关联证据

`ntp.authentication` 检查配置开关，不能把开关通过当作完整认证或同步成功。Comware/VRP/StoneOS 在完整输入且没有开关声明时采用文档中的关闭缺省值；部分输入及损坏的最终声明保持未知。Comware/VRP `ntp.key_slots` 独立记录 key ID、算法、存储格式、材料存在性、完整性、可信状态及来源行；`ntp.authentication_bindings` 对每个 server/peer 给出引用、配置就绪性和具体缺证原因。材料替换及删除先归约，旧材料不进入凭据记录。损坏的最终声明产生未知材料；未知凭据使用 `present: nil`，不覆盖其他已确认的明文/旧格式违规。密文不用于推断强度或对端一致性。局部输入不能证明完整清单或认证就绪。

H3C profile 支持 md5 与文档中的 hmac-sha-1/256/384/512 拼写及显式 cipher/simple；VRP profile 独立支持 md5、hmac-sha256、aes-128-cmac、aes-256-cmac 和 cipher/未限定格式的明文。算法列表表示可识别语法，并非安全推荐。密钥 ACL 及未确认语法保持未知。H3C 删除密钥自动撤销可信状态；未确认的 VRP 删除联动保持未知，需要后续显式可靠声明。未知的最后认证开关语句不会回落到旧启用值。

新的批准关联可引用已有、完整、可信材料，并要求 `ntp_peer_key_compatibility_verified: true` 外部核验 ID、算法及材料。规划器传给呈现器的 `verified_ntp_key_ids` 是本次方案内的非秘密依赖证据；独立呈现不自行假定可信材料存在。不生成材料命令或可信声明；全局开关按下述独立契约规划。独立测试模型应用原生命令后核对对象审计、配置就绪图、无关文本及第二次零变更；这些不是设备/NTP 对端测试。

### 全局认证切换

H3C/Huawei/StoneOS 的 `ntp.authentication.remediation.ntp_peer_key_compatibility_verified: true` 明确表示外部已核验本次批准的全局认证状态、全部配置及潜在运行时对端的兼容性；开启和关闭都需要，空静态清单也不能代替批准。完整输入、已知当前开关和完整消费者清单是前提。存在广播、组播、参考时钟、未建模模式或接口内 NTP 配置时受阻，不把静态 server/peer 清单当成全部消费者。`ntp.authentication_consumers_complete` 仅表示已配置模式已建模，不证明运行时没有被动或动态对端。

开启前检查最终全部关联，包括端点管理范围外保留的关联：每项必须引用已知完整材料，Comware/VRP 还需显式可信。已有 StoneOS 材料没有独立可信命令，不虚构该条件。新材料、材料变更和新可信声明仍为人工前提；不生成秘密值或秘密占位符。已批准的关联变更与全局开关在同一事务内规划及呈现，任何依赖或命令失败都不导出该事务的部分命令；相关检查记录完整事务操作 ID。

H3C/Huawei/StoneOS 的完整原生关联库存允许显式批准 source 或 key_id 赋值，即使原配置没有明确字段而审计保持 resource_attribute_unresolved；不把隐式值改写为已知事实。材料、作用域及外部兼容条件仍须满足，其他未知字段或不完整库存不能通过此路径生成。

Comware/VRP 启用遵守先认证后基本关联的顺序。已有静态关联必须全部暂时撤下，开启认证后重建最终完整集合，包括未改变参数的关联。必须明确提供 `ntp_association_recreation_approved: true` 批准短暂失去全部静态时间来源及重建；这不是授予新材料或越界改变端点参数的批准。方案记录 `temporary_association_withdrawal`，风险至少为 high。有关联时还必须选择 `syntax_profile`：H3C `comware_legacy` 使用前置 VPN 与 source-interface，`comware7` 使用后置 VPN 与 source；Huawei `vrp_s_series` 使用后置 VPN、preference 与 unicast-server/peer 后的 ipv6。profile 是调用方对目标版本语法的确认，不从厂商品牌推断；其他版本及不同关键词继续需要独立 profile。无关联时无需重建批准。

StoneOS 在批准的关联增删完成后以 `activate` 阶段启用认证。所有平台关闭认证均在关联变更前以 `prepare` 阶段执行，保留材料；不隐式开启 NTP 服务。全局认证操作具有完整指纹验证及厂商阶段校验。命令只供人工审核，没有连接设备、save 或 commit。参见[合成示例](../examples/remediation_ntp_authentication_switch.rb)。

语法依据：[H3C 旧版命令](https://www.h3c.com/cn/d_202401/2040058_30005_0.htm)、[Comware 7 认证及关联](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CG-32576/17/202604/2827747_294551_0.htm)、[Huawei 认证顺序](https://info.support.huawei.com/hedex/api/pages/EDOC1100277644/AEM10221/03/resources/software/nev8r10_vrpv8r16/user/galaxy/vrp_ntp_cfg_0025.html)、[Huawei S7700 关联语法](https://support.huawei.cn/enterprise/en/doc/EDOC1100459494/cdeee8e2/configuring-ntp-operating-modes)。Huawei NTP 解析和呈现不再接受 H3C priority、前置 VPN 或 ipv6 unicast-server 作为 VRP 语法；未确认的 DNS 与 IPv6 version 选项保持未知/受阻。此项仅有官方语法与合成验证，没有 Huawei 真实备份或设备验证。

Huawei S 系列认证缺省关闭的依据为原厂 V200R023C00 Command Reference 第 3.13.10 节（第 1398 页），可查[原厂手册镜像](https://johnny-unitaz.info/mans/Huawei/Commands/S300%2C%20S500%2C%20S2700%2C%20S5700%2C%20and%20S6700%20V200R023C00%20Command%20Reference/01-03%20Device%20Management%20Commands.pdf)。

依据：[H3C 密钥及可靠声明](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Public/00-Public/Technical_Documents/Reference_Guides/Command_References/H3C_CR-28394/15/202508/2623951_294551_0.htm)、[H3C 可靠声明与密钥删除联动](https://www.h3c.com/en/d_202112/1504433_294551_0.htm)、[Huawei NTP 认证配置及算法](https://info.support.huawei.com/hedex/api/pages/EDOC1100277644/AEM10221/03/resources/software/nev8r10_vrpv8r16/user/galaxy/vrp_ntp_cfg_0025.html)。其他产品/版本需对应 profile 证据，不能从语法相近推断已覆盖。


## 服务器地址身份与数量

服务器目标统一使用 `ServerAddress` 计算地址身份：IPv6 规范为 Ruby `IPAddr#to_s` 形式，DNS ASCII 标签忽略大小写，但保留末尾点及相对/绝对名称区别，不查询 DNS。IPv4 与 IPv4 映射 IPv6 不自动合并，也不推断两个不同地址/名称是否指向同一设备。域名仅接收已支持的 ASCII 主机标签；Unicode 名称需先由应用提供有效的 ASCII IDNA 形式。URI 方括号、网段和带 zone 的字面量不是本 profile 支持的目标地址。

地址归一化覆盖配置资源的 address 身份/属性、策略解析结果、旧 ntp/syslog/tacacs.servers 集合、撤销键、厂商地址库存及操作指纹。模板/命名主备槽位等 `name` 字段、group/profile 标识、接口和 VRF 不套用 DNS 规则。相同地址在不同职责和作用域仍是不同资源，但旧最低服务器数量规则只计算不同地址，不用主备、VRF 或文本变体证明额外地址数量。字段类型或地址语法错误的外部事实返回未知，不转成空集。

已知配置按源顺序归约，同一规范身份的后续声明覆盖其资源设置；规范身份重复的结构化批准对象在输入边界拒绝，避免冲突属性被静默选择。旧地址规则仍按集合语义归并重复批准值。策略原文及配置原文不被改写，策略指纹继续绑定实际批准文档；解析后的批准值和操作身份使用规范地址。新请求若仅改变地址写法，审计通过并返回零变更；属性确有变化时只更新同一端点。无原始输入的验证错误不保留底层 IPAddr 异常中的非法文本。

依据：[RFC 5952 IPv6 文本表示](https://www.rfc-editor.org/rfc/rfc5952)、[RFC 4343 DNS 标签大小写](https://www.rfc-editor.org/rfc/rfc4343)。此处理不证明固件命令支持、目标可达、域名解析结果或服务器硬件独立性。


Cisco `tacacs.group_references` 按 `named_server` 与 `address` 区分成员；命名服务器通过完整原名查找，不能用碰巧同名的 DNS 地址代替缺失对象。地址成员按同一规则规范化，与现有已解析服务器库存对照。组重新进入保留已有成员，成员撤销使用规范身份，整组撤销清除对应成员。未识别的成员形式仅保留 unresolved/来源行，不复制可能含秘密的尾部；未选中组的未知成员不掩盖已知选中组。`tacacs.group_inventory_complete` 描述已解析的组成员清单，不能用作完整 AAA 方法链、材料、VRF 或运行可用性证明；IOS/NX-OS 其他定义生命周期与引用类型仍需对应证据和实现。此增量不启用新的绑定策略种类或原生 AAA 切换命令。

成员语法依据：[Cisco NX-OS 地址/主机名成员](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/m-configuring-tacacs.html)、[Cisco IOS XE 命名服务器引用](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-3e/sec-usr-aaa-xe-3e-book/ip6-tacacs.html)。

Cisco 命名 TACACS 定义按原名合并重新进入，整对象撤销后清除旧地址和材料；每个 IPv4/IPv6 槽位及对象 key 采用最终声明，撤销后重新创建不能继承旧证据。这不证明完整 AAA 链、其他厂商 key 生命周期或实际服务器可用。

Cisco 全局、命名对象和旧式 host 内联 key 共用材料语法校验；孤立编码标识保留未知，不能作为明文秘密。全局 key 的最终撤销生效；不同命名端点即使地址相同，也不能互相借用对象 key 证明材料存在。

## PAN-OS Syslog 接收成员迁移

`syslog.destinations.remediation.binding_migrations` 为数组，每项明确给出 `from_profile`、`to_profile` 和 `reference`。来源为 null 表示新增引用，去向为 null 表示解绑；两者不能同时为空或相同。同一来源只能有一个去向。设备日志 reference 使用上述 `syslog.device` 身份；共享转发 reference 仅包含 `kind: syslog.forwarding`、`forwarding_profile`、`match`、`log_type`，并要求 `consumers` 精确列出该匹配项的全部规则及 zone 绑定。明确的空数组只批准已知未被使用的转发匹配项；省略不等于批准。可选日志标志必须与已知事实匹配，未声明的标志保留原状。

所有迁移来源/去向 profile 必须在 `managed_scopes`；受影响且保留的目标服务器必须显式声明最终 `bindings`。现有匹配项和完整引用库存是前提，不创建过滤式、动作、转发匹配项，也不修改规则或 zone 的 profile 选择。同一匹配项的多项迁移同时计算最终集合，不能靠策略排列次序串行传递批准。原来源已经移除且去向已经存在时可重入。迁移仅用于修正不合规的目标状态，不能在所有检查已通过时单独触发变更。

原子 `syslog.reference` 操作包含经过验证的完整前后成员集合，呈现器只逐个 set 新成员、再逐个 delete 旧成员，保留其他接收者。全局步骤先创建服务器、再修改引用、最后移除服务器；容量要求提前删除仍被引用的最后一台服务器时受阻，需要可容纳迁移的批准容量。仍有声明引用却没有最终服务器的 profile 不能通过规划。每个操作同样受完整操作指纹验证约束，部分输入、未知消费者或不完整批准无命令。

[人工审核示例](../examples/remediation_palo_alto_syslog_migration.rb) 展示设备日志的纯引用迁移。命令依据 [PAN-OS 11.2 配置层级](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy) 的 send-syslog 成员列表及 [CLI 修改配置语义](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/modify-the-configuration)；CLI 删除不会自动检查其他引用，因此规划器验证完整依赖。独立状态模型只证明离线配置变换和再次审计闭环，不代表真实设备接受、提交或日志投递成功。

名称按各对象分别校验：[转发 profile](https://docs.paloaltonetworks.com/ngfw/help/11-2/objects/objects-log-forwarding) 最长 64 字符，匹配项最长 31 字符；[设备日志匹配项](https://docs.paloaltonetworks.com/ngfw/help/11-2/device/device-log-settings/select-log-forwarding-destinations) 允许名称内的句点，不能套用服务器 profile 的字符范围。合成基准将超过 64 个匹配项的场景分散到多个转发 profile，不构造超出已记录单 profile 上限的配置。

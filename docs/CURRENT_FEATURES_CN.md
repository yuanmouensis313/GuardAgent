# GuardAgent 当前已实现功能说明

> 文档日期：2026-07-22
> 当前版本：0.1.0（MVP）
> 对应需求：`docs/OPENCLAW_GUARD_AGENT_REQUIREMENTS.md`

## 1. 文档目的

本文档说明 GuardAgent 当前代码仓库已经实现的功能、主要工作流程、安全边界、验证情况以及仍需在真实 OpenClaw 环境中完成的事项。

本文所说的“已实现”，表示相关代码、配置或自动化测试已经存在于仓库中；它不等同于某一台生产主机已经正确部署。OpenClaw Gateway、消息渠道、工作区、模型提供商和操作系统权限都属于目标环境，仍需单独配置与验收。

## 2. 系统定位

GuardAgent 是运行在 OpenClaw 旁路的本地安全控制系统，主要用于控制具有真实副作用的工具调用，例如：

- 执行 Shell、PowerShell 或其他系统命令；
- 读取、写入、删除和批量修改文件；
- 访问网络、上传文件或发送消息；
- 安装插件、Skill 或其他依赖；
- 创建子智能体、后台任务和持久化任务；
- 修改 OpenClaw、GuardAgent 或操作系统安全配置。

系统采用“OpenClaw 原生安全控制 + GuardAgent 确定性策略”的分层防护模型。GuardAgent 不替代 OpenClaw 的 sandbox、tool policy、exec approvals、sender allowlist 和主机隔离，而是在这些原生控制之上增加统一事件、确定性判定、跨调用关联、审批与审计能力。

## 3. 总体架构

当前仓库由以下部分组成：

| 组件 | 目录 | 作用 |
|---|---|---|
| `guardd` | `guardd/` | 本地 Python 决策、审批、关联分析和审计服务 |
| OpenClaw 插件 | `plugins/guard-openclaw/` | 在 OpenClaw Hook 中拦截工具、消息、安装和生命周期事件 |
| 默认策略 | `policies/default.yaml` | 定义默认模式、保护路径、网络规则、预算和判定规则 |
| 策略 Schema | `policies/schemas/` | 校验 YAML 策略结构 |
| 原生安全基线 | `config/` | OpenClaw sandbox、工具权限、exec approvals 和插件配置模板 |
| 测试样例 | `fixtures/` | allow、approve、deny 三类离线测试事件 |
| 测试代码 | `tests/` | 单元、集成、对抗和性能测试 |
| 运维脚本 | `scripts/` | 初始化、备份、基准测试和安装策略辅助脚本 |

典型执行链路如下：

```text
OpenClaw 准备调用工具
        │
        ▼
guard-openclaw / before_tool_call
        │  统一事件、初步脱敏
        ▼
guardd 本地 API
        │  归一化、策略匹配、跨事件关联
        ▼
ALLOW / DENY / REQUIRE_APPROVAL / OBSERVE
        │
        ├─ ALLOW：继续执行
        ├─ DENY：阻断调用
        ├─ REQUIRE_APPROVAL：交给 OpenClaw 原生一次性审批
        └─ OBSERVE：记录建议判定，但不由 GuardAgent 阻断
        │
        ▼
after_tool_call / 生命周期 Hook
        │
        ▼
SQLite 审计与关联状态更新
```

## 4. 统一事件与决策模型

### 4.1 GuardEvent

`guardd/models/events.py` 实现了版本化的统一事件模型，当前 Schema 版本为 `1.0`。事件可以携带：

- `event_id`、事件类型和发生时间；
- Gateway、agent、session、run 和 tool call 关联标识；
- 来源渠道、发送者和本地操作者信息；
- 原始工具名称、工具类型和输入类型；
- 工具参数；
- 归一化后的命令、路径、网络目标和动作；
- 数据敏感分类；
- trace/span 信息；
- 插件和 OpenClaw 版本上下文。

插件会对 session、sender、channel 等部分标识进行本地哈希，减少原始身份信息进入审计库的范围。

### 4.2 决策模型

`guardd/models/decisions.py` 实现四种决策：

| 决策 | 含义 |
|---|---|
| `ALLOW` | 允许本次操作 |
| `DENY` | 明确拒绝本次操作 |
| `REQUIRE_APPROVAL` | 需要一次性人工审批 |
| `OBSERVE` | 仅观察记录，不由 GuardAgent 阻断 |

决策结果还包括：

- 风险等级；
- 命中的规则 ID；
- 人类可读原因和修复建议；
- 参数 digest；
- 脱敏后的参数摘要；
- 可选的安全参数改写；
- 审批 ID 和过期时间；
- Observe 模式下的 `would_decide` 建议结果。

多个规则同时匹配时使用严格优先级：

```text
DENY > REQUIRE_APPROVAL > ALLOW
```

明确的拒绝规则不会因为系统处于 Approval 模式而被降级为审批。

## 5. 三阶段运行模式

默认策略支持以下运行模式：

### 5.1 Observe

当前默认模式为 `observe`。

- 完整执行事件解析、规则匹配和关联分析；
- 对外返回 `OBSERVE`；
- 在 `would_decide` 中保存如果启用控制时应采用的结果；
- 不由 GuardAgent 主动阻断正常调用；
- OpenClaw 原生 sandbox、tool policy 和 exec approvals 仍然生效；
- `guardd` 断开时，插件内置应急策略仍然会阻止明显高危动作。

### 5.2 Approval

Approval 模式用于上线过渡：

- 低风险操作可直接允许；
- 中高风险但可以由人判断的操作要求一次性审批；
- 明确禁止的高危操作仍然直接拒绝；
- 不支持永久允许。

### 5.3 Enforce

Enforce 模式完整执行策略中的 allow、approval 和 deny 判定。项目文档要求经过 Observe 和 Approval 阶段验证后才能启用。

## 6. 命令解析与危险行为识别

`guardd/normalizers/command.py` 已实现跨平台命令归一化，包括：

- 识别 Bash、POSIX Shell、PowerShell 和常见命令输入；
- 在尊重引号的前提下拆分 `&&`、`||`、`;` 和管道；
- 提取 argv 和命令链；
- 识别重定向、管道和通配符；
- 识别变量展开和命令替换；
- 识别 `eval`、`python -c`、`node -e` 等动态执行；
- 识别 PowerShell `EncodedCommand` 和 Base64 解码执行；
- 识别嵌套 Shell；
- 识别环境变量键名；
- 对动态命令内容采用摘要审计，避免完整敏感脚本进入日志。

默认规则能够识别或控制的典型危险命令包括：

- `rm -rf /`、盘符根目录递归删除；
- 下载后直接通过管道执行；
- 编码或混淆命令执行；
- 修改防火墙、Defender、审计或执行策略；
- 创建服务、计划任务、cron、注册表自启动项；
- 使用 privileged 容器、Docker socket、host network 或 host PID；
- 动态执行解释器代码；
- 对外推送、上传和发布操作。

## 7. 文件路径安全

`guardd/normalizers/path.py` 已实现：

- 相对路径转绝对路径；
- `.`、`..` 规范化；
- Windows 与 POSIX 路径处理；
- 符号链接的真实路径解析；
- 工作区内外边界判断；
- 读、写、删除访问类型区分；
- `apply_patch` 补丁头路径提取；
- 插件上报路径与服务端重新计算路径的合并；
- GuardAgent 自身、OpenClaw 安全配置、系统敏感目录和凭据路径分类。

主要路径分组包括：

- 工作区内路径；
- GuardAgent 受保护路径；
- 敏感凭据路径；
- 系统或安全配置路径；
- 未知工作区外路径。

默认策略拒绝：

- 修改 GuardAgent 代码、策略、令牌、数据库或审计文件；
- 修改 OpenClaw 安全配置和 exec approvals；
- 读取 SSH 私钥、环境密钥、浏览器凭据等敏感路径；
- 在未授权工作区之外写入或删除文件。

Windows 真实 junction 测试在当前测试进程中因缺少创建权限被跳过；路径规范化逻辑和普通符号链接逃逸已覆盖，目标主机仍需使用具备权限的环境复测 junction。

## 8. 网络访问控制

`guardd/normalizers/network.py` 已实现：

- 从 URL 和命令中提取网络目标；
- URL query 脱敏；
- 域名规范化；
- loopback、私网、公网和直接 IP 分类；
- 域名 allowlist 与 denylist；
- 新域名识别；
- DNS 解析和解析后 IP 分类；
- DNS 缓存、TTL、并发上限和超时；
- DNS 失败、无效目标和解析到私网地址时的保守处理；
- `curl` 等命令的上传行为识别。

默认允许列表包含 OpenClaw 文档、PyPI 和 npm registry 等有限域名。直接访问公网 IP、访问拒绝域名、向未知域名写数据或上传内容会被拒绝或要求审批。

生产部署必须根据实际业务重新定义域名 allowlist，不能把默认开发依赖域名视为业务网络白名单。

## 9. 敏感数据检测与脱敏

`guardd/security.py` 和插件侧预脱敏已实现常见敏感信息检测，包括：

- API key 和常见厂商密钥格式；
- JWT；
- 私钥 PEM；
- AWS、GitHub、OpenAI、Anthropic 等常见凭据格式；
- 密码、token、cookie、authorization 等敏感字段名；
- 中国居民身份证号码；
- 银行卡号；
- 数据库连接字符串；
- 手机号码；
- 可配置的电子邮件检测；
- 用户自定义正则模式。

敏感值不会原样写入审计，而是转换成包含类型、长度和哈希摘要的标记。事件参数和工具输出默认仅保存类型、长度、摘要或截断后的脱敏结果。

插件会在数据发送给 `guardd` 之前先完成一轮本地脱敏；服务端仍会再次检测和脱敏，形成双层保护。

默认规则会阻止把任何已分类敏感数据发送到外部渠道或网络目标。

## 10. 确定性策略引擎

`guardd/policy/` 已实现 YAML 策略加载、JSON Schema 校验、digest 和确定性匹配。

当前默认策略包含 37 条基础规则，支持以下匹配维度：

- agent、session、run；
- channel、sender、本地操作者；
- 时间条件；
- 工具名、工具类型和输入类型；
- 动作类型；
- 命令正则、Shell 特征和动态执行；
- 路径分组和访问方式；
- 网络目标和域名分类；
- 参数正则；
- 数据敏感分类；
- 关联风险结果。

已经实现策略参数改写：规则可以返回收窄后的 `rewritten_params`，服务会对改写参数重新归一化、重新匹配规则并重新计算 digest，避免先按安全参数审批、执行时再换回危险参数。

策略热重载 API 已实现。新策略解析失败时不会替换内存中的最近有效策略；成功加载的策略版本会记录到审计数据库。

## 11. 跨调用关联与行为预算

`guardd/correlation.py` 已实现有界的 session/sender 行为状态，用于识别单次规则无法发现的复合风险：

- 读取敏感信息后再发送消息或上传；
- 审批被拒绝后改用编码或动态执行变体重试；
- 单位时间内工具调用过多；
- 同一动作高频重复形成循环；
- 子智能体数量超限；
- 单次批量文件数量超限；
- 单次操作字节数超限；
- 删除比例异常；
- session 和 sender 风险分数累积。

内存状态采用长度和时间窗口限制，避免无限增长。服务重启时会从最近审计事件恢复十分钟窗口内的关键关联状态，使简单重启不能直接清除调用预算和循环检测。

默认预算为：

| 项目 | 默认值 |
|---|---:|
| 每 10 分钟工具调用数 | 200 |
| 每分钟相同动作次数 | 5 |
| 子智能体数量 | 3 |
| 单次文件数量 | 100 |
| 单次字节数 | 50,000,000 |
| 删除比例 | 0.5 |

## 12. OpenClaw 插件拦截能力

`plugins/guard-openclaw/src/index.ts` 使用 OpenClaw typed plugin SDK 注册了以下 Hook：

| Hook | 当前用途 |
|---|---|
| `before_tool_call` | 工具执行前作出 allow、block、approval 或参数改写 |
| `after_tool_call` | 关联执行结果、退出码、耗时和错误 |
| `before_agent_run` | 可选的高置信度 prompt injection 输入门控 |
| `message_sending` | 消息外发前检查并可取消 |
| `reply_payload_sending` | 回复 payload 外发前检查并可取消 |
| `before_install` | 插件或其他目标安装前检查，异常时失败关闭 |
| `session_start` | 记录会话开始 |
| `session_end` | 记录会话结束 |
| `agent_end` | 记录 agent 结束 |
| `subagent_spawned` | 记录子智能体创建 |
| `subagent_ended` | 记录子智能体结束 |
| `gateway_start` | 记录 Gateway 启动并探测 `guardd` 健康状态 |
| `gateway_stop` | 记录 Gateway 停止 |

关键拦截 Hook 使用高优先级 `10000`，Hook timeout 为 500 ms；插件对 `guardd` 的请求上限被限制在 450 ms 以内，确保能在 OpenClaw Hook 超时之前返回本地应急决策。

工具调用 ID 与 GuardEvent ID 的关联表有 5,000 条上限；异步观察队列有 256 条上限，避免 OpenClaw 长期运行时内存无限增长。

## 13. 断连与超时降级

`plugins/guard-openclaw/src/emergency.ts` 实现了不依赖 `guardd` 的最小应急策略。当本地服务断开、超时或返回异常时：

- 只允许可明确验证为工作区内的只读操作；
- 拒绝工作区外写入；
- 拒绝敏感路径读取；
- 拒绝安全配置修改；
- 拒绝动态执行和 elevated 操作；
- 拒绝对外发送；
- 其他不确定操作要求 OpenClaw 原生一次性审批；
- 客户端采用指数退避，避免故障期间持续高频重连。

低风险生命周期和结果详情可以在队列饱和或降级期间丢弃。错误结果等关键观察会尝试绕过饱和的低风险队列。工具执行前的安全判定不依赖该异步队列。

## 14. 审批机制

`guardd/approvals/manager.py` 和插件共同实现：

- 审批默认 TTL 60 秒，可配置但限制在 1～600 秒；
- 只支持 `allow-once` 和 `deny`；
- 不提供 `allow-always`；
- 审批记录绑定 agent、session、sender 和参数 digest；
- digest 或身份发生变化时不能消费旧审批；
- 审批只能消费一次；
- 过期审批不能继续使用；
- 服务重启会使尚未处理的 pending 审批失效；
- 审批展示内容经过脱敏，包含工具、目标、风险、规则和原因；
- 审批操作者、结果和耗时进入 SQLite 审计。

插件使用 OpenClaw 原生 `requireApproval` 返回当前调用的审批请求，并在原生审批完成后把结果同步回 `guardd`。这是当前推荐的实际执行路径。

`guardctl approvals list/allow-once/deny` 和对应 API 也已经实现，可管理 GuardAgent 审批记录。但终端审批能否直接恢复某个正在等待的 OpenClaw 原生调用，取决于真实 Gateway 的审批生命周期，尚未在用户的实际 Gateway 中完成端到端验证。

## 15. SQLite 审计

`guardd/audit/store.py` 使用 SQLite 保存结构化审计，已经实现：

- WAL 模式；
- 5 秒 busy timeout；
- 线程内互斥访问；
- `PRAGMA integrity_check`；
- 事件 hash chain；
- 策略版本记录；
- 服务异常记录；
- critical/deny 写入失败时的应急 JSONL；
- 应急文件权限收紧尝试；
- 参数和工具输出摘要化；
- URL query 和敏感值脱敏。

当前主要数据表：

| 表 | 内容 |
|---|---|
| `events` | 统一事件和 hash chain |
| `decisions` | 决策、风险、原因、digest 和策略版本 |
| `rule_matches` | 决策命中的规则 |
| `approvals` | 审批请求和处理结果 |
| `tool_results` | 工具结果摘要、退出码和耗时 |
| `sessions` | session 生命周期 |
| `policy_versions` | 策略文档、digest 和操作者 |
| `service_incidents` | 服务异常和降级记录 |

数据库写入异常时，高风险行为不会因为审计失败而自动放行；高风险决策会转为拒绝，并在可能的情况下写入应急 JSONL。

当前已提供一致性备份脚本，并会在服务启动时按 `audit_retention_days` 清理过期审计记录；应急 JSONL 在数据库恢复后的自动去重回灌尚未完成，详见“未完成事项”。

## 16. 本地 API

`guardd/api/app.py` 基于 FastAPI 实现以下接口：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/v1/health` | 无认证健康检查 |
| GET | `/v1/status` | 服务、策略、数据库和计数状态 |
| POST | `/v1/decisions/tool` | 工具调用决策 |
| POST | `/v1/decisions/message` | 消息外发决策 |
| POST | `/v1/events/tool-result` | 记录工具结果 |
| POST | `/v1/events/session` | 记录生命周期事件 |
| GET | `/v1/events` | 查询审计事件 |
| GET | `/v1/approvals` | 查询审批 |
| GET | `/v1/approvals/{id}` | 查询单个审批 |
| POST | `/v1/approvals/{id}/allow-once` | 一次性允许 |
| POST | `/v1/approvals/{id}/deny` | 拒绝审批 |
| POST | `/v1/policy/validate` | 校验策略文本 |
| POST | `/v1/policy/simulate` | 模拟策略决策 |
| POST | `/v1/policy/reload` | 重新加载磁盘策略 |

API 安全控制包括：

- 服务只允许配置为 loopback 地址；
- 除健康检查外均要求 bearer token；
- token 从工作区外的文件加载；
- token 使用恒定时间比较；
- 检查声明的 `Content-Length`；
- 检查实际请求体大小；
- 写请求必须使用 `application/json`；
- Pydantic 校验请求 Schema；
- request ID 进入事件派生字段。

默认请求体上限为 1 MiB。

## 17. 管理 CLI

安装 Python 包后提供两个命令：

- `guardd`：启动本地服务；
- `guardctl`：管理和检查服务。

当前 CLI 功能：

| 命令 | 用途 |
|---|---|
| `guardctl status` | 查看运行模式、策略和数据库状态 |
| `guardctl events list` | 按 session、risk 和数量查询事件 |
| `guardctl approvals list` | 查看审批记录 |
| `guardctl approvals allow-once` | 标记一次性允许 |
| `guardctl approvals deny` | 拒绝审批 |
| `guardctl policy validate` | 校验策略文件 |
| `guardctl policy simulate` | 对单个事件进行模拟 |
| `guardctl policy test` | 验证单个 fixture 的期望结果 |
| `guardctl replay --session` | 使用当前策略重放 session 事件 |
| `guardctl doctor` | 检查 GuardAgent 和 OpenClaw 安全基线 |

`doctor` 会尝试检查：

- OpenClaw CLI 是否存在；
- `openclaw doctor`；
- 普通与 deep security audit；
- sandbox explain；
- exec policy；
- approvals；
- GuardAgent loopback 绑定；
- 策略和 token 文件；
- 审计状态目录是否位于受监控工作区之外。

## 18. OpenClaw 原生安全基线

仓库提供：

- `config/openclaw-security-baseline.json5`；
- `config/exec-approvals.baseline.json`；
- `scripts/openclaw_install_policy.py`。

基线模板包含或约束：

- agent 默认 sandbox；
- session 级隔离；
- 容器网络关闭和只读根文件系统；
- workspace 访问边界；
- elevated 关闭；
- Gateway、cron、session spawn 等高风险工具限制；
- exec policy 和 approvals；
- GuardAgent 插件 allow/config；
- 默认拒绝的安装策略；
- 只有精确目标、精确版本和允许 registry 才可通过的安装辅助策略。

模板已使用项目锁定的 OpenClaw 2026.7.1 开发依赖执行过 `config validate --json`，Schema 校验通过。部署占位符、插件安装和真实渠道配置仍需在目标主机完成。

## 19. 插件与 Skill 安装保护

`scripts/openclaw_install_policy.py` 实现保守的安装前判定：

- 默认拒绝全部安装；
- 仅允许显式列出的目标；
- 仅允许本地受信根目录或允许的 registry；
- npm/ClawHub 网络目标受 hostname allowlist 限制；
- 要求精确版本；
- 拒绝可变版本和不明确来源；
- 未知目标失败关闭。

插件的 `before_install` Hook 还会把安装事件提交给 `guardd`；如果 `guardd` 不可用，安装直接阻断，OpenClaw 原生 `security.installPolicy` 仍作为基础控制。

## 20. 已提供的运维能力

### 20.1 初始化

`scripts/init_guard.py` 用于创建状态目录和强随机 bearer token，并尝试收紧文件权限。

### 20.2 数据库备份

`scripts/backup_guard.py` 使用 SQLite backup API 创建事务一致的备份，输出：

- 创建时间；
- 目标路径；
- SHA-256；
- `integrity_check` 结果。

### 20.3 性能基准

`scripts/benchmark.py` 测量确定性决策延迟和并发决策延迟。

### 20.4 部署、回滚与 break-glass

`docs/DEPLOYMENT.md` 已记录：

- 环境准备；
- Observe → Approval → Enforce 上线顺序；
- OpenClaw 配置验证；
- 备份与回滚；
- SQLite 故障排查；
- 插件故障排查；
- 必须在 OpenClaw 外执行的人工 break-glass；
- 恢复后重新验证安全基线的要求。

break-glass 只停用 GuardAgent，不会自动把 OpenClaw 改成 YOLO、full access 或关闭 sandbox。

## 21. 默认规则覆盖范围

当前默认策略共有 37 条基础规则，覆盖的主要风险类别包括：

- prompt injection 高置信度输入；
- GuardAgent 自保护；
- OpenClaw 安全配置保护；
- 根目录或盘符级破坏性删除；
- 下载后立即执行；
- 编码和混淆命令；
- 服务、计划任务和 cron 持久化；
- 特权容器与 Docker socket；
- 关闭或绕过系统安全功能；
- 凭据、私钥和敏感路径访问；
- 敏感数据外发；
- 工作区外写入；
- 直接公网 IP 和拒绝域名访问；
- 文件上传和外部消息发送；
- Git push、软件安装和动态解释器；
- 浏览器表单提交；
- 进程控制；
- 子智能体创建；
- 工作区内常规读写和元数据操作；
- 健康检查、Git status/log/diff 等低风险命令。

规则清单应以 `policies/default.yaml` 为准；部署方可以在 JSON Schema 约束下调整允许域名、路径、预算和规则。

### 21.1 会话范围、数据通路与内容核查增强

仓库已按 `R_TASK_SANITIZATION_SKILL_MCP_IMPLEMENTATION_PLAN.md` 增加三组控制：

- 会话级 `R_task`：只从当前可信用户目标生成候选规则，绑定 session、agent、sender、基础策略摘要和修订号；首次启用、扩权以及 Skill/MCP 内容授权都要求摘要确认，缩权可自动生效，子会话权限取父子交集；
- 数据通路脱敏：插件在原始数据离开本地前形成 policy/execution/audit view，决策返回可验证的 transformation plan；工具结果通过同步 `tool_result_persist` 在持久化和下一轮模型读取前脱敏，并带不可信来源标签；
- Skill/MCP 内容核查：安装前、启动时和可识别的运行时 Skill 以内容摘要扫描；MCP tool/prompt/resource descriptor 在 stdio 代理中逐项检查，未放行项在到达模型前移除，真实调用继续绑定 descriptor 和 server 摘要。

三组能力都有独立的 Observe/Enforce 配置、SQLite 审计、机器 API、CLI 和本地 UI 页面。当前 MCP 兼容代理仅覆盖 stdio；SSE 和 Streamable HTTP 会由 capability API 明确报告为未保护。

## 22. 测试与验证证据

当前仓库包含：

- 40 个独立 fixture：10 个允许、11 个审批、19 个拒绝；
- Python 单元测试；
- FastAPI 集成测试；
- 对抗测试；
- 10,000 事件性能与有界状态测试；
- TypeScript 插件测试；
- OpenClaw SDK 严格类型编译；
- 插件 runtime 构建验证；
- Web 控制台 TypeScript、组件测试和生产构建验证。

当前验证范围还包括 R_task 状态机和子会话继承、Python/TypeScript pattern 一致性、双向 sanitizer、Skill/MCP 摘要失效、六类间接提示注入场景，以及使用真实子进程的 stdio MCP 代理端到端测试。具体通过/跳过数量以当次 CI 输出为准，避免在说明文档中保留过期计数。

最近一次性能基线记录为：

- TypeScript strict checking、插件 runtime build 和 Web production build 纳入最终验收命令；
- 10,000 次本地确定性决策 P50 约 0.948 ms；
- 10,000 次本地确定性决策 P95 约 1.375 ms；
- 100 并发决策 P95 约 14.994 ms；
- 实际 loopback smoke test 中 SQLite integrity 为 `ok`。

Python 测试覆盖：

- YAML Schema 和规则优先级；
- 40 个 fixture；
- 命令解析；
- Windows/POSIX 路径；
- `apply_patch` 路径；
- DNS/IP/URL 分类；
- secret redaction；
- digest；
- 审批过期和单次消费；
- 关联风险和预算；
- 重启状态恢复；
- API 鉴权和请求限制；
- 审计 hash chain；
- 安装策略；
- 性能和状态上限。

插件测试覆盖：

- allow、deny 和 requireApproval 映射；
- 参数安全改写；
- 消息取消；
- `guardd` 断连降级；
- tool result 与 session 关联；
- 插件预脱敏；
- 必需 Hook 注册和优先级；
- prompt injection 门控；
- 安装时失败关闭。

详细验证记录见 `docs/IMPLEMENTATION_STATUS.md`。

### 20.5 本地可视化控制台

仓库现已包含 `web/` 下的 React/TypeScript 前端和 `guardd/api/ui/` 下的操作者 API。生产构建由同一个只监听回环地址的 FastAPI 进程通过 `/ui/` 提供，不改变 OpenClaw 插件使用的 `/v1/*` 机器接口。

界面提供：

- 服务状态、决策/风险趋势、Top 规则和待审批总览；
- 带服务端校准倒计时的一次性审批，且只支持 `allow-once`/`deny`；
- 事件组合过滤、脱敏详情、工具结果和审计哈希；
- 会话聚合、时间线、脱敏导出和策略重放；
- YAML 策略编辑、校验、安全差异、dry-run、fixtures 回归、原子发布、历史 revision 和回滚；
- 后台 doctor 诊断、服务事故与只读运行设置。

`guardctl ui` 通过 bearer 认证创建 60 秒单次 bootstrap code。code 位于 URL fragment，浏览器消费后只获得 HttpOnly、SameSite=Strict 的短期 UI session；所有写操作还需 CSRF token 和回环 Origin 校验。bearer token 不进入浏览器 URL、localStorage 或响应内容。

UI 静态资源缺失、SSE 断线或诊断任务失败不会影响插件判定接口。SSE 断线时界面自动使用短轮询刷新审批和状态。

设置 `GUARDD_UI_ENABLED=false` 可完全停用浏览器控制面；此时 `/ui/` 返回 503、`/v1/ui/*` 不注册，但机器 API、CLI 与 OpenClaw 插件继续工作。

## 23. 当前尚未完成或尚未证明的事项

以下内容不能标记为生产完成：

### 23.1 需要继续开发

- 应急 `emergency.jsonl` 在数据库恢复后的自动去重回灌尚未实现；
- 插件异步队列饱和的专门压力测试仍需补充；
- 外部进程长期占用 SQLite 写锁后的恢复测试仍需补充；
- 终端 `guardctl allow-once` 与正在等待的 OpenClaw 原生调用之间需要真实 Gateway 联调并明确恢复语义。
- MCP SSE 和 Streamable HTTP 传输尚无 descriptor 前置代理，当前只允许把 stdio 声明为受保护传输；

### 23.2 需要真实 OpenClaw 环境验证

- 当前主机没有已配置并运行的全局 OpenClaw Gateway；
- 插件已通过 SDK 编译和模拟测试，但尚未在用户真实 Gateway 中执行完整 Hook 链；
- `tool_result_persist` 返回的消息必须在真实 Gateway 中证明是下一轮模型实际读取的内容，完成前入站通路不得在生产启用 Enforce；
- sandbox、tool policy、exec approvals 和 channel pairing 尚未在目标主机验收；
- OpenClaw 升级后的兼容性回归尚未在生产实例执行；
- Gateway 重启、插件禁用和配置变化告警需要真实实例验证；
- 消息渠道 sender allowlist 需要用户提供实际账号；
- 真实业务 workspace、网络域名 allowlist 和日常命令白名单需要用户确认。

### 23.3 需要运行时间才能证明

- 尚未完成 3～7 天 Observe 观察期；
- 尚未完成至少 24 小时稳定性运行；
- 尚未基于真实业务流量统计误报率和误放率；
- 尚未验证目标机器上的审计增长速度、备份容量和留存计划。

## 24. 当前推荐使用方式

当前最合适的使用阶段是本地或测试环境的 Observe：

1. 在受监控工作区之外创建 GuardAgent 状态目录；
2. 配置并启动 `guardd`；
3. 合并 OpenClaw 原生安全基线；
4. 安装 `guard-openclaw` 插件；
5. 保持 `defaults.mode: observe`；
6. 检查事件、`would_decide`、风险和误报；
7. 完成真实 Gateway 的安全审计和 Hook 验证；
8. 经过观察期后再切换到 Approval；
9. 只有所有部署门禁通过后才考虑 Enforce。

不建议在未完成目标环境验收时直接启用 Enforce。

## 25. 关键文件索引

| 文件或目录 | 内容 |
|---|---|
| `docs/OPENCLAW_GUARD_AGENT_REQUIREMENTS.md` | 原始技术需求 |
| `docs/DEPLOYMENT.md` | 部署、回滚和故障处理 |
| `docs/IMPLEMENTATION_STATUS.md` | 实现证据和外部验收门禁 |
| `guardd/service.py` | 核心服务编排 |
| `guardd/api/app.py` | 本地 FastAPI |
| `guardd/api/ui/` | 可视化控制台认证与操作者 API |
| `guardd/ui/static/` | 已构建的本地控制台静态资源 |
| `web/` | React/TypeScript 可视化界面源码 |
| `guardd/policy/engine.py` | 策略匹配和决策 |
| `guardd/correlation.py` | 跨调用关联和预算 |
| `guardd/task_policy/` | 会话级 R_task 生成、确认、修订和继承 |
| `guardd/sanitization/` | 版本化脱敏模式与审计模型 |
| `guardd/inspections/` | Skill/MCP 内容扫描、摘要缓存和确认 |
| `guardd/mcp_proxy.py` | stdio MCP descriptor 前置核查与结果脱敏 |
| `guardd/audit/store.py` | SQLite 审计 |
| `guardd/approvals/manager.py` | 一次性审批 |
| `guardd/normalizers/` | 命令、路径和网络归一化 |
| `plugins/guard-openclaw/src/index.ts` | OpenClaw Hook 注册和拦截 |
| `plugins/guard-openclaw/src/client.ts` | 本地 API 客户端、脱敏和队列 |
| `plugins/guard-openclaw/src/emergency.ts` | 断连应急策略 |
| `policies/default.yaml` | 当前默认策略和 37 条规则 |
| `config/openclaw-security-baseline.json5` | OpenClaw 安全配置模板 |
| `config/exec-approvals.baseline.json` | exec approvals 模板 |
| `scripts/init_guard.py` | 状态目录和 token 初始化 |
| `scripts/backup_guard.py` | SQLite 一致性备份 |
| `scripts/benchmark.py` | 决策性能基准 |

## 26. 结论

GuardAgent 当前已经具备 MVP 的主要代码能力：OpenClaw typed Hook 拦截、统一事件、命令/路径/网络归一化、确定性策略、敏感数据控制、跨调用关联、一次性审批、SQLite 审计、断连失败关闭、本地 API、管理 CLI、原生安全基线和自动化测试。

目前的主要剩余工作不在基础判定功能，而在审计维护闭环和真实 OpenClaw 部署验收。现阶段可以进入测试环境 Observe 运行，但在真实 Gateway 安全基线、渠道身份、工作区边界、网络白名单、稳定性观察和误报评估完成之前，不应宣称生产验收完成。

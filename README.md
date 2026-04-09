# Java Audit Skills

专注于 Java 代码审计的 Claude Skills 集合，提供自动化源码分析、路由提取、参数映射等功能，辅助安全研究人员和开发者进行 Java Web 应用的安全审计工作。

## 功能特性

- **自动路由识别**：自动识别 Java Web 项目中的 HTTP 路由结构
- **多框架支持**：支持 Spring MVC、Servlet、JAX-RS、Struts 2 等主流框架
- **参数结构解析**：提取 Path、Query、Body、Header、Cookie 等各类参数
- **反编译集成**：集成 Java 反编译器，支持分析已编译的 .class 和 .jar 文件
- **Burp Suite 集成**：生成可直接用于 Burp Suite Repeater 的请求模板
- **接口文档生成**：为无 API 文档的项目生成接口清单
- **路由调用链追踪**：追踪从 Controller 到 DAO 层的完整调用链，分析参数流向
- **鉴权机制审计**：识别鉴权框架实现，分析鉴权绕过和越权访问风险
- **SQL 注入审计**：识别 SQL 执行框架，检测 SQL 注入漏洞风险
- **文件上传审计**：识别文件上传入口，分析路径穿越和可执行文件上传风险
- **文件读取审计**：识别文件读取操作，分析路径遍历攻击风险
- **XXE 审计**：识别 XML 解析操作，检测外部实体注入漏洞风险
- **组件漏洞检测**：扫描第三方依赖，匹配 130+ 条 CVE 规则，生成安全报告
- **全链路审计流水线**：使用 agent team 编排多个审计 skill（含动态扩展的调用链追踪 worker），一键完成完整安全审计

## 前置要求

- **Java 运行环境**：需安装 Java（`java -version` 可用即可）
- **CFR 反编译器**：有两种获取方式：
  1. 如果已有 cfr.jar，直接指定路径使用
  2. 未指定时自动从 `https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar` 下载

详细反编译策略参见 `skills/java-shared/DECOMPILE_STRATEGY.md`

## 目录结构

```
java-audit-skills/
├── README.md                    # 项目说明文档
└── skills/                      # Skills 集合目录
    ├── README.md               # Skills 详细说明
    ├── shared/                 # 共享工具和资源
    ├── java-route-mapper/      # Java 路由与参数映射工具
    ├── java-route-tracer/      # Java 路由调用链追踪工具
    ├── java-sql-audit/         # Java SQL 注入审计工具
    ├── java-auth-audit/        # Java 鉴权机制审计工具
    ├── java-file-upload-audit/ # Java 文件上传漏洞审计工具
    ├── java-file-read-audit/   # Java 文件读取漏洞审计工具
    ├── java-xxe-audit/        # Java XXE 漏洞审计工具
    ├── java-vuln-scanner/     # Java 组件版本漏洞检测工具
    └── java-audit-pipeline/   # Java 全链路自动化安全审计流水线
```

## 可用 Skills

| Skill                | 说明                                    |
| ------------------- | --------------------------------------- |
| java-route-mapper   | Java Web 源码路由与参数映射分析工具     |
| java-route-tracer   | Java Web 源码路由多层级调用链追踪工具   |
| java-sql-audit      | Java Web 源码 SQL 注入漏洞审计工具      |
| java-auth-audit     | Java Web 源码鉴权机制审计工具           |
| java-file-upload-audit | Java Web 源码文件上传漏洞审计工具     |
| java-file-read-audit   | Java Web 源码文件读取漏洞审计工具     |
| java-xxe-audit      | Java Web 源码 XXE 漏洞审计工具         |
| java-vuln-scanner   | Java 组件版本漏洞检测工具               |
| java-audit-pipeline | Java 全链路自动化安全审计流水线（需开启 agent teams） |

详细说明请参阅 [skills/README.md](skills/README.md)

## 安装与使用

### 1. 准备 CFR 反编译器

```bash
# 方式一：手动下载 CFR
curl -L -o cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"

# 方式二：直接使用（Skill 会在需要时自动下载）
```

### 2. 配置 Skills

将 skills 目录下的内容复制到 Claude Code 的 skills 配置目录中。

### 3. 使用 Skill

在 Claude Code 中调用 skill：

**方式一：一键全链路审计（推荐）**

> **前置条件（Agent Teams）：**
> - Claude Code 版本 >= 2.1.32
> - 在 `~/.claude/settings.json` 的 `env` 中添加 `"CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"`：
>   ```json
>   {
>     "env": {
>       "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
>     }
>   }
>   ```
> - 也可通过环境变量临时启用：`export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`
> - （可选）安装 tmux 以获得分屏可视化效果，使用 `Shift+Up/Down` 切换 teammate 视图
>
> 注：Agent Teams 为 research preview 实验性功能，随 Opus 4.6（2026-02-05）发布。

```
/java-audit-pipeline /path/to/project
```

自动编排多个 agent（含动态扩展的调用链追踪 worker）完成完整审计流程：路由分析→鉴权审计→组件漏洞→交叉筛选（风险分级+漏洞汇总）→调用链追踪（分批并行）→漏洞深度分析（按 sink 类型并行，含可利用前置条件）→质量校验。

**演示效果：**

![java-audit-pipeline 运行演示](assets/WechatIMG5173.jpg)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    java-audit-pipeline 全链路流程                        │
└─────────────────────────────────────────────────────────────────────────┘

阶段1: 信息收集（并行）
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│ route-mapper      │ │ auth-audit        │ │ vuln-scanner      │
│ 全量路由+参数     │ │ 路由鉴权映射      │ │ 组件漏洞          │
└────────┬──────────┘ └────────┬──────────┘ └────────┬──────────┘
         └──────────────┬──────┴──────────────┬──────┘
                  quality-checker 逐个校验，通过后关闭
                        ↓
阶段2: 交叉分析（并行）
┌──────────────────────────┐ ┌──────────────────────────┐
│ risk-classifier          │ │ vuln-aggregator          │
│ 无鉴权路由分级（P0/P1）  │ │ 漏洞汇总（组件+鉴权绕过）│
└────────┬─────────────────┘ └────────┬─────────────────┘
         └──────────────┬──────────────┘
                  quality-checker 校验，通过后关闭
                        ↓
阶段3: 调用链追踪（分批并行）
┌─────────────────────────────────────────────────────────────────────────┐
│ route-tracer: 读取 P0+P1 高危路由，分批创建追踪任务                     │
└────────┬────────────────────────────────────────────────────────────────┘
         ↓ 动态创建 worker
┌──────────────┐ ┌──────────────┐       ┌──────────────┐
│ worker-1     │ │ worker-2     │  ...  │ worker-N     │
│ 批次1追踪    │ │ 批次2追踪    │       │ 批次N追踪    │
└────────┬─────┘ └────────┬─────┘       └────────┬─────┘
         └──────────────┬──────────────────┬──────┘
                  quality-checker 校验，通过后关闭
                        ↓
阶段4: 漏洞深度分析（按需并行）
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ sql-auditor      │ │ xxe-auditor      │ │ upload-auditor   │ │ fileread-auditor │
│ SQL注入+前置条件 │ │ XXE注入+前置条件 │ │ 文件上传+前置条件│ │ 文件读取+前置条件│
└────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
         └──────────────┬─────┴──────────────┬─────┘──────────────┘
                  仅启动有对应 sink 的 agent，quality-checker 分别校验，通过后关闭
阶段5: 汇总报告
┌─────────────────────────────────────────────────────────────────────────┐
│ quality-checker: 整合所有校验结果 → quality_report.md → 完成后关闭      │
└─────────────────────────────────────────────────────────────────────────┘
                        ↓
                {project_name}_audit/
                ├── route_mapper/
                ├── auth_audit/
                ├── vuln_report/
                ├── cross_analysis/
                │   ├── high_risk_routes.md
                │   ├── trace_batch_plan.md
                │   ├── component_vulnerabilities.md
                │   └── auth_bypass_vulnerabilities.md
                ├── route_tracer/
                ├── sql_audit/
                ├── xxe_audit/
                ├── file_upload_audit/
                ├── file_read_audit/
                ├── decompiled/
                └── quality_report.md
```

**方式二：手动逐步执行**

按需单独调用各 skill，适合只需要某项审计或自定义流程的场景。

**参数说明：**
- `/path/to/project` - Java 项目根目录，包含源码（.java）或编译文件（.class/.jar）
- `--route` - 指定要追踪的具体路由路径

```
/java-route-mapper /path/to/project
/java-route-tracer --route /api/users/login --project /path/to/project
/java-sql-audit /path/to/project
/java-auth-audit /path/to/project
/java-file-upload-audit /path/to/project
/java-file-read-audit /path/to/project
/java-xxe-audit /path/to/project
/java-vuln-scanner /path/to/project
```

**项目路径要求：**
- 源码项目：包含 `src/main/java` 等源码目录
- 编译项目：包含 `WEB-INF/classes` 或 .jar 文件
- 支持同时存在源码和编译文件的情况，优先使用源码

## 最佳实践

1. 优先使用源码，仅在必要时使用反编译
2. 记录每个路由的源文件位置便于追溯
3. 输出格式统一，便于后续处理
4. 遇到无法解析的配置时记录并跳过

## 贡献

欢迎提交 Issue 和 Pull Request 来完善项目功能。

## 许可证

本项目仅供学习和研究使用。

## TODO 待办列表

- [ ] **agent-8 交叉审计增强**：结合组件漏洞 + 调用链追踪 + OWASP Top 10 漏洞审计结果，进行深度交叉分析，识别复合型漏洞利用链

## 交流群

asdnnj32nsd@foxmail.com 需要进群把微信号发到这个邮箱，拉你进群（群已满200，只能拉人进群）

## 相关链接

- [CFR Decompiler](https://github.com/leibnitz27/cfr) - Java 反编译器
- [Claude Code](https://claude.ai/claude-code) - Claude CLI 工具

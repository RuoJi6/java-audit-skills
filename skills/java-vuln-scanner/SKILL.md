---
name: java-vuln-scanner
description: Java 组件版本漏洞检测工具。扫描 pom.xml、build.gradle 或 jar 文件中的第三方依赖，匹配已知漏洞规则（CVE）并生成漏洞检测报告。适用于：(1) Java 项目依赖安全审计，(2) 识别 Log4j、Fastjson、Shiro、Spring 等高危组件漏洞，(3) jar 包反编译后的依赖提取。支持按目录层级分组输出，支持通过 CFR 反编译 .class/.jar 文件提取依赖信息。
---

# Java 组件漏洞扫描器

扫描 Java 项目依赖中的已知漏洞，支持 130+ 条 CVE 规则，按模块分组输出，并由 AI 生成漏洞触发点检查结果。

## 工作流程

### 1. 确定扫描目标

支持的输入类型：
- `pom.xml` - Maven 项目
- `build.gradle` - Gradle 项目
- `.jar` 文件 - 从文件名或 META-INF 提取依赖信息
- 目录 - 递归扫描上述所有文件，自动按模块分组

### 2. 处理 jar/class 文件（需要反编译时）

当目标是 `.jar` 或 `.class` 文件且无法直接提取依赖信息时，使用 CFR 反编译器（详见 `java-shared/DECOMPILE_STRATEGY.md`）：

```bash
# 反编译单个文件
java -jar {CFR_JAR} /path/to/file.jar --outputdir {output_path}/decompiled

# 反编译目录
find /path/to/classes -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 3. 执行漏洞扫描

运行扫描脚本，报告自动保存到 `{项目名}_audit/vuln_report/` 目录：

```bash
python3 scripts/scan_dependencies.py <目标路径> \
  --rules references/java-vulnerability.yaml \
  --no-deps
```

参数说明：
- `<目标路径>`: pom.xml、build.gradle、jar 文件或目录
- `--rules/-r`: 漏洞规则文件路径（使用内置规则）
- `--format/-f`: 输出格式 (markdown/json)
- `--output/-o`: 指定输出路径（不指定则自动生成）
- `--depth/-d`: 模块分组深度（默认: 2）
- `--no-deps`: 不显示依赖列表（简化输出）
- `--no-save`: 仅输出到终端，不保存文件

### 4. 检查扫描结果

报告按模块分组，每个模块按严重级别分类：
- 🔴 **Critical**: 立即修复（Log4Shell、Fastjson RCE、Shiro 反序列化等）
- 🟠 **High**: 尽快修复（Spring Boot Actuator、XStream 等）
- 🟡 **Medium**: 计划修复（JDBC 驱动漏洞、Guava 等）
- 🔵 **Low**: 建议升级（过时组件）

### 5. AI 漏洞触发点分析（重要）

扫描完成后，**必须**基于扫描结果，按照 `references/OUTPUT_TEMPLATE.md` 模板填充完整报告（**单个文件**）。

#### 分析步骤

1. 读取 Python 脚本生成的扫描结果
2. **识别项目运行环境**：
   - 检查项目使用的框架：Spring MVC / Spring Boot / Struts2 / Servlet / JAX-RS 等
   - 检查容器类型：Tomcat / Jetty / Undertow / WebLogic / WildFly 等
   - 查找配置文件：`web.xml`、`struts.xml`、`application.yml`、`applicationContext.xml` 等
3. **提取路由和入口点**：
   - 扫描 Controller / Action / Servlet 类，提取 HTTP 路由映射
   - 识别文件上传、JSON/XML 解析、用户输入处理等关键入口
   - 结合 java-route-mapper 技能（如已加载）获取完整路由信息
4. 提取检测到的**唯一漏洞组件**列表（去重）
5. **按模板填充报告**，每个漏洞的详情区块必须包含：
   - 触发条件
   - 危险代码模式（java 代码块）
   - 攻击向量
   - 受影响的路由/接口
   - 代码搜索命令（bash 代码块）
   - 修复建议
6. 使用 Write 工具将完整报告写入 **单个文件**

#### 环境识别方法

根据以下特征识别项目环境（参考 java-route-mapper 技能的识别策略）：

**Web 框架识别：**

| 框架 | 识别特征 | 配置文件 | 关键依赖 |
|------|---------|---------|---------|
| Spring MVC | `@Controller`、`@RequestMapping`、`@RestController` | `dispatcher-servlet.xml`、`spring-mvc.xml` | `spring-webmvc.jar` |
| Spring Boot | `@SpringBootApplication`、Spring Boot starter | `application.properties`、`application.yml` | `spring-boot-starter-*.jar` |
| Struts 2 | `ActionSupport`、`\<action\>` 配置 | `struts.xml`、`struts-plugin.xml` | `struts2-core.jar` |
| Servlet | `HttpServlet`、`@WebServlet`、`\<servlet\>` 配置 | `web.xml` | `javax.servlet-api.jar` |
| JAX-RS | `@Path`、`@GET`、`@POST`、`@PathParam` | `web.xml`（REST servlet 映射） | `jersey-*.jar`、`cxf-rt-*.jar` |
| CXF Web Services | `@WebService`、`\<jaxws:endpoint\>` | `applicationContext.xml`、`cxf-servlet.xml` | `cxf-*.jar` |

**容器识别：**

| 容器 | 识别特征 | 配置文件 |
|------|---------|---------|
| Tomcat | `catalina.jar`、`org.apache.catalina` | `server.xml`、`context.xml` |
| Jetty | `jetty-*.jar`、`org.eclipse.jetty` | `jetty.xml`、`webdefault.xml` |
| Undertow | `undertow-*.jar`、`io.undertow` | `undertow-handlers.conf` |
| WebLogic | `weblogic.jar`、`weblogic.xml` | `weblogic.xml`、`weblogic-application.xml` |
| WildFly/JBoss | `jboss-*.jar`、`org.jboss` | `jboss-web.xml`、`standalone.xml` |

**框架组合识别：**

多框架混合项目需要分别识别并检查：
- Struts2 + Spring：检查 `struts-spring-plugin.jar` 和 Spring 配置
- Spring MVC + CXF：检查 `\<jaxws:endpoint\>` 和 `@Controller` 共存
- Servlet + Filter 链：检查 `web.xml` 中的 filter-mapping 顺序

## 漏洞规则覆盖

规则文件 `references/java-vulnerability.yaml` 包含 130+ 条规则，覆盖：

| 组件类别 | 主要漏洞 |
|---------|---------|
| Log4j | CVE-2021-44228 (Log4Shell), CVE-2021-45046 |
| Fastjson | CVE-2022-25845, CVE-2017-18349 |
| Spring | CVE-2022-22965 (Spring4Shell), CVE-2022-22963 |
| Struts2 | S2-045, S2-046, S2-057, S2-061 |
| Shiro | CVE-2016-4437, CVE-2020-11989, CVE-2020-17510 |
| Jackson | CVE-2020-36518, CVE-2019-12384 |
| XStream | CVE-2021-39144 等 15 个 CVE |
| ActiveMQ | CVE-2023-46604 |
| JDBC 驱动 | MySQL, PostgreSQL, H2, Derby 等 |

## 示例

### 完整扫描流程

```bash
# 1. 执行扫描
python3 scripts/scan_dependencies.py /path/to/webapp \
  --rules references/java-vulnerability.yaml \
  --no-deps

# 2. 输出示例:
# [INFO] 创建输出目录: webapp_audit/vuln_report
# [INFO] 报告已保存到: webapp_audit/vuln_report/webapp_vuln_report_20260204_101747.md
# 📊 扫描摘要:
#    模块数量: 4
#    依赖总数: 262
#    漏洞总数: 80
#    🔴 严重: 24

# 3. AI 自动读取报告并追加触发点检查结果
```

### 输出报告结构

> **输出约束（不可违反）：**
> 1. **输出为单个文件** — 不得拆分为多个文件
> 2. 文件命名格式: `{project_name}_vuln_report_{YYYYMMDD_HHMMSS}.md`
> 3. 必须严格按照 `references/OUTPUT_TEMPLATE.md` 模板填充输出
> 4. 不得增删章节、不得调整章节顺序

**输出模板**: [references/OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md)

```
{project_name}_audit/vuln_report/
└── {project_name}_vuln_report_{YYYYMMDD_HHMMSS}.md   ← 仅此 1 个文件
    ├── 1. 扫描概述
    ├── 2. 风险统计
    ├── 3. 组件漏洞映射表
    ├── 4. 漏洞详情（含触发条件、危险代码、攻击向量、搜索命令）
    └── 5. 审计结论
```

通用输出规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

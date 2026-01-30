# Java Audit Skills

专注于 Java 代码审计的 Claude Skills 集合，提供自动化源码分析、路由提取、参数映射等功能，辅助安全研究人员和开发者进行 Java Web 应用的安全审计工作。

## 功能特性

- **自动路由识别**：自动识别 Java Web 项目中的 HTTP 路由结构
- **多框架支持**：支持 Spring MVC、Servlet、JAX-RS、Struts 2 等主流框架
- **参数结构解析**：提取 Path、Query、Body、Header、Cookie 等各类参数
- **反编译集成**：集成 Java 反编译器，支持分析已编译的 .class 和 .jar 文件
- **Burp Suite 集成**：生成可直接用于 Burp Suite Repeater 的请求模板
- **接口文档生成**：为无 API 文档的项目生成接口清单
- **鉴权机制审计**：识别鉴权框架实现，分析鉴权绕过和越权访问风险

## 前置要求

在使用之前需要安装 [java-decompile-mcp](https://github.com/RuoJi6/java-decompile-mcp) MCP 服务，该服务提供 Java 反编译能力，用于分析已编译的 Java 文件。

## 目录结构

```
java-audit-skills/
├── README.md                    # 项目说明文档
└── skills/                      # Skills 集合目录
    ├── java-route-mapper/       # Java 路由与参数映射工具
    │   ├── SKILL.md            # Skill 定义文件
    │   ├── references/         # 框架参考资料
    │   │   ├── ANNOTATIONS.md  # 注解参考
    │   │   ├── DECOMPILE_STRATEGY.md  # 反编译策略
    │   │   ├── FRAMEWORK_PATTERNS.md  # 框架模式识别
    │   │   ├── JAXRS.md        # JAX-RS 框架参考
    │   │   ├── SERVLET.md      # Servlet 框架参考
    │   │   ├── SPRING_MVC.md   # Spring MVC 框架参考
    │   │   └── STRUTS.md       # Struts 框架参考
    │   └── scripts/            # 辅助脚本
    │       ├── detect_framework.py   # 框架检测脚本
    │       └── scan_routes.py        # 路由扫描脚本
    ├── java-auth-audit/         # Java 鉴权机制审计工具
    │   ├── SKILL.md            # Skill 定义文件
    │   └── references/         # 鉴权参考资料
    │       ├── ANNOTATION_AUTH.md   # 注解鉴权参考
    │       ├── BYPASS_PATTERNS.md  # 鉴权绕过模式
    │       ├── DECOMPILE_STRATEGY.md # 反编译策略
    │       ├── FILTER_INTERCEPTOR.md # Filter/Interceptor 拦截器
    │       ├── JWT.md            # JWT 鉴权机制
    │       ├── SESSION_AUTH.md   # Session 鉴权机制
    │       ├── SHIRO.md          # Apache Shiro 鉴权
    │       ├── SPRING_SECURITY.md # Spring Security 鉴权
    │       ├── URI_PARSING_BYPASS.md # URI 解析绕过
    │       ├── VERSION_VULNS.md  # 框架版本漏洞
    │       └── VULNERABILITY_CHECKLIST.md # 漏洞检查清单
    └── README.md               # Skills 目录说明
```

## 可用 Skills

### java-route-mapper

**Java Web 源码路由与参数映射分析工具**

适用场景：
- 无 API 文档的项目进行接口梳理
- 生成 Burp Suite 测试请求模板
- 分析源码中的可访问端点

**支持框架：**
- Spring MVC / Spring Boot
- Servlet（web.xml、@WebServlet）
- JAX-RS（@Path、@GET、@POST 等）
- Struts 2

**核心功能：**
1. 自动识别项目类型和框架
2. 扫描并提取 HTTP 路由（@Controller、@RequestMapping 等）
3. 解析参数结构（Path 变量、Query 参数、Body 参数、Header 参数、Cookie 参数）
4. 支持 .class 和 .jar 文件的反编译分析
5. 生成标准 HTTP 请求模板

**使用示例：**

```
输入: 项目源码路径
输出: 完整的路由清单和 Burp Suite 请求模板

=== [1] 用户登录 ===
位置: UserController.login (src/main/java/com/example/controller/UserController.java:45)
HTTP 方法: POST
URL 路径: /api/auth/login
参数结构:
  Body: LoginRequest (username: String, password: String)

Burp Suite 请求模板:
---
POST /api/auth/login HTTP/1.1
Host: {{host}}
Content-Type: application/json

{"username": "{{username}}", "password": "{{password}}"}
---
```

### java-auth-audit

**Java Web 源码鉴权机制审计工具**

适用场景：
- 识别项目中使用的鉴权框架和实现方式
- 发现鉴权绕过漏洞
- 分析越权访问风险
- 审计权限校验逻辑

**支持框架：**
- Spring Security
- Apache Shiro
- JWT 鉴权
- Session 鉴权
- Filter/Interceptor 拦截器
- 自定义鉴权实现

**核心功能：**
1. 自动识别鉴权框架类型和版本
2. 提取鉴权配置和拦截规则
3. 分析鉴权绕过模式（URL 解析绕过、权限校验绕过等）
4. 识别越权访问风险（IDOR、水平/垂直越权）
5. 检测框架版本已知漏洞
6. 支持 .class 和 .jar 文件的反编译分析

**使用示例：**

```
输入: 项目源码路径
输出: 鉴权机制分析报告、漏洞发现清单

=== 鉴权框架识别 ===
框架: Spring Security
版本: 5.7.2

=== 鉴权配置 ===
SecurityFilterChain: /api/public/** = permitAll()
SecurityFilterChain: /api/admin/** = hasRole('ADMIN')

=== 潜在漏洞 ===
[高危] URI 解析绕过漏洞
  位置: SecurityConfig.java:45
  说明: 使用 regexMatcher() 可能导致 /admin/. 接口绕过鉴权

[高危] IDOR 越权漏洞
  位置: UserController.getUserById (UserController.java:78)
  说明: /api/user/{id} 接口缺少所有权校验，可能访问其他用户数据
```

## 安装与使用

### 1. 安装 MCP Java Decompiler

```bash
# 按照 java-decompile-mcp 仓库说明进行安装
# https://github.com/RuoJi6/java-decompile-mcp
```

### 2. 配置 Skills

将 skills 目录下的内容复制到 Claude Code 的 skills 配置目录中。

### 3. 使用 Skill

在 Claude Code 中调用 skill：

```
/java-route-mapper /path/to/java/project
/java-auth-audit /path/to/java/project
```

建议先使用 java-route-mapper 提取所有路由，再使用 java-auth-audit 分析鉴权机制，结合使用可完整审计项目的接口和权限控制。

## 最佳实践

1. 优先使用源码，仅在必要时使用反编译
2. 记录每个路由的源文件位置便于追溯
3. 输出格式统一，便于后续处理
4. 遇到无法解析的配置时记录并跳过

## 贡献

欢迎提交 Issue 和 Pull Request 来完善项目功能。

## 许可证

本项目仅供学习和研究使用。

## 交流群

![](assets/image-20260123114132975.png)

## 相关链接

- [java-decompile-mcp](https://github.com/RuoJi6/java-decompile-mcp) - Java 反编译 MCP 服务
- [Claude Code](https://claude.ai/claude-code) - Claude CLI 工具

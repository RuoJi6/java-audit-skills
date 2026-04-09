---
name: java-auth-audit
description: Java Web 源码鉴权机制审计工具。从源码中识别所有鉴权实现，检测鉴权绕过漏洞和越权访问缺陷。适用于：(1) 识别鉴权框架和实现方式，(2) 发现鉴权绕过漏洞，(3) 检测越权访问缺陷，(4) 审计权限校验逻辑。支持 Shiro、Spring Security、JWT、Filter/Interceptor、自定义鉴权等。**支持反编译 .class/.jar 文件提取鉴权逻辑**。结合 java-route-mapper 使用可实现完整的路由+鉴权审计。
---

# Java 鉴权机制审计工具

扫描 Java Web 项目源码，识别鉴权机制实现，检测鉴权绕过漏洞和越权访问缺陷。

---

## 漏洞分级标准

**详见 [SEVERITY_RATING.md](../java-shared/SEVERITY_RATING.md)**

- 漏洞编号格式: `{C/H/M/L}-AUTH-{序号}`
- 严重等级 = f(可达性 R, 影响范围 I, 利用复杂度 C)
- Score = R × 0.40 + I × 0.35 + C × 0.25，映射 CVSS 3.1

---

## 检测范围边界

**本技能检测范围仅包含以下类型：**
- 鉴权绕过漏洞（Bypass）
- 越权访问缺陷（Privilege Escalation）
- 会话管理缺陷（Session Fixation / Hijacking）
- 已知组件漏洞（CVE）

**以下不属于本技能检测范围（即使在通常意义上也属于"安全问题"）：**
- ❌ 代码质量问题（命名不规范、逻辑冗余、性能问题等）
- ❌ 通用安全漏洞（SQL 注入、XSS、CSRF 等，使用专项技能）
- ❌ 架构设计建议（缺少限流、日志审计、加密强度等）
- ❌ 业务逻辑合理性（接口是否应该公开等业务决策）

---

## 核心要求

**此技能必须完整检查所有鉴权相关代码，不允许省略。**

- ✅ 识别所有鉴权入口点（Filter/Interceptor/注解）
- ✅ 分析每个路由的鉴权状态
- ✅ 检测所有潜在的鉴权绕过模式
- ✅ 为每个漏洞点提供验证 PoC
- ❌ 禁止省略任何鉴权配置
- ❌ 禁止跳过反编译步骤

---

## 工作流程

### 1. 项目分析初始化

```
输入: 项目源码路径
      可选: 已知框架信息、关注的路径
```

**初始化步骤：**

1. 识别项目类型（源码/编译后/混合）
2. 识别鉴权框架（通过配置文件和特征类）
3. 确定是否需要反编译

### 2. 鉴权框架识别

| 框架 | 识别特征 | 配置文件 | 参考资料 |
|------|----------|----------|----------|
| Shiro | `shiro.ini`, `@RequiresAuthentication`, `SecurityUtils` | `shiro.ini`, `shiro-spring.xml` | [SHIRO.md](references/SHIRO.md) |
| Spring Security | `@EnableWebSecurity`, `SecurityFilterChain`, `@PreAuthorize` | `SecurityConfig.java` | [SPRING_SECURITY.md](references/SPRING_SECURITY.md) |
| JWT | `io.jsonwebtoken`, `JwtParser`, `Bearer Token` | - | [JWT.md](references/JWT.md) |
| Filter | `implements Filter`, `doFilter()` | `web.xml` | [FILTER_INTERCEPTOR.md](references/FILTER_INTERCEPTOR.md) |
| Interceptor | `implements HandlerInterceptor`, `preHandle()` | `WebMvcConfig` | [FILTER_INTERCEPTOR.md](references/FILTER_INTERCEPTOR.md) |
| 注解鉴权 | `@RequiresRoles`, `@PreAuthorize`, 自定义注解 | - | [ANNOTATION_AUTH.md](references/ANNOTATION_AUTH.md) |

### 2.1 组件版本检测（CRITICAL）

**必须检测鉴权相关组件的版本，识别已知漏洞。**

详细漏洞版本参见 [VERSION_VULNS.md](references/VERSION_VULNS.md)

#### 版本识别方法

**方法 1: JAR 文件名识别**

```bash
# 扫描 WEB-INF/lib 目录
ls WEB-INF/lib/ | grep -E "shiro|spring-security|jwt|pac4j"

# 常见命名格式
shiro-core-1.4.0.jar          → Shiro 1.4.0
spring-security-core-5.7.3.jar → Spring Security 5.7.3
jjwt-0.9.1.jar                → JJWT 0.9.1
pac4j-core-4.0.0.jar          → PAC4J 4.0.0
```

**方法 2: pom.xml 解析**

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.4.0</version>  <!-- 提取版本号 -->
</dependency>
```

**方法 3: MANIFEST.MF 解析**

```bash
# 解压 JAR 查看 MANIFEST.MF
unzip -p shiro-core-1.4.0.jar META-INF/MANIFEST.MF

# 关键字段
Implementation-Version: 1.4.0
Bundle-Version: 1.4.0
```

**方法 4: JAR 内 pom.properties**

```bash
# 查看 JAR 内的 Maven 属性文件
unzip -p shiro-core.jar META-INF/maven/org.apache.shiro/shiro-core/pom.properties

# 内容示例
version=1.4.0
groupId=org.apache.shiro
artifactId=shiro-core
```

#### 高危组件版本速查

| 组件 | 漏洞版本 | CVE | 风险 | 备注 |
|------|----------|-----|------|------|
| Shiro | < 1.5.2 | CVE-2020-1957 | 路径绕过 | 需配合 Spring |
| Shiro | < 1.5.3 | CVE-2020-11989 | 鉴权绕过 | 需配合 Spring |
| Shiro | < 1.6.0 | CVE-2020-13933 | 认证绕过 | - |
| Shiro | < 1.7.1 | CVE-2020-17523 | 认证绕过 | 需 Spring 集成 |
| Shiro | < 1.8.0 | CVE-2021-41303 | 路径绕过 | - |
| Shiro | < 1.9.1 | CVE-2022-32532 | RegEx 绕过 | 使用正则匹配时 |
| Shiro | < 1.11.0 | CVE-2023-22602 | 路径绕过 | Spring Boot 2.6+ |
| Spring Security | < 5.7.5 | CVE-2022-31692 | 授权绕过 | - |
| Spring Security | < 5.4.11 / < 5.5.7 / < 5.6.4 | CVE-2022-22978 | RegEx 绕过 | 换行符绕过 |
| PAC4J | < 4.0.0 | CVE-2021-44878 | 认证绕过 | - |
| JJWT | < 0.10.0 | - | 弱密钥风险 | - |

#### 版本检测输出格式

```markdown
## 组件版本分析

### 检测到的鉴权组件

| 组件 | 当前版本 | 最新版本 | 风险状态 |
|------|----------|----------|----------|
| shiro-core | 1.4.0 | 1.13.0 | ❌ 存在已知漏洞 |
| spring-security-core | 5.7.3 | 6.2.0 | ⚠️ 必须升级 |
| jjwt | 0.11.2 | 0.12.3 | ✅ 安全 |

### 已知漏洞详情

=== [CVE-2020-11989] Shiro 路径绕过 ===
影响版本: < 1.5.3
当前版本: 1.4.0
风险等级: 高

漏洞描述:
- Spring 框架下 Shiro 路径匹配存在绕过
- 攻击者可通过特殊路径绕过鉴权

验证 PoC:
\```http
GET /admin/page%2f HTTP/1.1
Host: {{host}}
\```

修复建议:
- 升级 Shiro 到 1.5.3 或更高版本
```

### 3. 反编译阶段（CRITICAL）

**当源码不可用时，必须使用 CFR 反编译器反编译鉴权相关类。**

详细策略参见 [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md)

#### 3.1 反编译工具调用

```bash
# 反编译单个鉴权类
java -jar {CFR_JAR} /path/to/AuthFilter.class --outputdir {output_path}/decompiled

# 反编译鉴权相关目录
find /path/to/WEB-INF/classes/com/example/security -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译多个指定文件
java -jar {CFR_JAR} /path/to/AuthFilter.class /path/to/SecurityConfig.class /path/to/PermissionInterceptor.class --outputdir {output_path}/decompiled
```

#### 3.2 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| Filter | `*Filter.class`, `*AuthFilter.class` | 提取 doFilter 鉴权逻辑 |
| Interceptor | `*Interceptor.class` | 提取 preHandle 权限校验 |
| Shiro 配置 | `ShiroConfig.class`, `*Realm.class` | 提取 filterChainDefinitionMap |
| Spring Security | `*SecurityConfig*.class` | 提取 authorizeRequests 配置 |
| 自定义注解 | `*Permission*.class`, `*Auth*.class` | 提取注解处理逻辑 |
| 权限工具类 | `*PermissionUtil*.class`, `*SecurityUtil*.class` | 提取权限校验方法 |

#### 3.3 反编译结果分析要点

```java
// 反编译后重点关注：
public class AuthFilter implements Filter {
    
    // 1. 白名单路径 - 可能过宽
    private static final String[] EXCLUDE_PATHS = {"/login", "/public"};
    
    // 2. 路径匹配逻辑 - 可能存在绕过
    private boolean isExcluded(String path) {
        return path.startsWith("/public");  // startsWith 可被绕过
    }
    
    // 3. 鉴权校验逻辑 - 可能存在缺陷
    if (session.getAttribute("user") == null) {
        // 仅检查是否登录，未检查角色
    }
}
```

### 4. 鉴权配置分析

#### 4.1 Shiro 配置解析

```ini
# shiro.ini
[urls]
/login = anon
/logout = logout
/admin/** = authc, roles[admin]
/api/** = authc
```

**提取内容：**
- 公开路径: `/login`
- 需要认证: `/api/**`
- 需要角色: `/admin/**` → `admin`

#### 4.2 Spring Security 配置解析

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
);
```

**提取内容：**
- 公开路径: `/public/**`
- 需要角色: `/admin/**` → `ADMIN`
- 默认策略: 需要认证

#### 4.3 Filter 配置解析

```xml
<!-- web.xml -->
<filter-mapping>
    <filter-name>AuthFilter</filter-name>
    <url-pattern>/api/*</url-pattern>
</filter-mapping>
```

**分析要点：**
- Filter 覆盖范围
- 未覆盖的路径（潜在风险）

### 5. 路由-鉴权映射

结合路由信息（可使用 java-route-mapper 技能），分析每个接口的鉴权状态：

| 状态 | 含义 | 风险 |
|------|------|------|
| ✅ 公开 | 明确配置为公开访问 | 无（需确认是否应该公开） |
| ✅ 受保护 | 有完整的鉴权保护 | 无 |
| ⚠️ 仅认证 | 只检查登录状态，无角色校验 | 中（可能越权） |
| ❌ 无鉴权 | 未发现任何鉴权机制 | 高 |
| ❓ 不确定 | 鉴权逻辑复杂，需人工确认 | 待定 |

### 6. 漏洞检测

详细检测模式参见 [BYPASS_PATTERNS.md](references/BYPASS_PATTERNS.md)

#### 6.1 鉴权绕过检测

##### 6.1.1 URI获取方法差异绕过（CRITICAL）

**这是最常见的鉴权绕过根因，必须优先检测！**

详细原理参见 [URI_PARSING_BYPASS.md](references/URI_PARSING_BYPASS.md)

**检测要点：** 识别鉴权代码使用的 URI 获取方法

| 获取方法 | 是否安全 | 绕过风险 |
|----------|----------|----------|
| `request.getRequestURI()` | ❌ 不安全 | 可被 `;`、编码、`../` 绕过 |
| `request.getRequestURL()` | ❌ 不安全 | 同上 |
| `request.getServletPath()` | ✅ 相对安全 | 已处理特殊字符 |
| `UrlPathHelper.getPathWithinApplication()` | ✅ 推荐 | Spring 标准方法 |
| `HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE` | ✅ 最安全 | 强关联Controller路由 |

**高危代码模式检测：**

```java
// ❌ 危险：直接使用 getRequestURI 做鉴权判断
String uri = request.getRequestURI();
if (uri.endsWith(".js") || uri.endsWith(".css")) {
    chain.doFilter(request, response); // 可被 /admin;.js 绕过
}

// ❌ 危险：使用 contains/endsWith 做白名单匹配
if (uri.contains("/public/") || uri.startsWith("/static/")) {
    return true; // 可被 /public/../admin 绕过
}
```

**绕过原理：**

```
请求: GET /api/admin;.js

鉴权Filter使用: request.getRequestURI() → 返回 /api/admin;.js → 匹配.js后缀 → 放行
路由匹配使用: request.getServletPath() → 返回 /api/admin → 路由到Controller

结果: 鉴权判断为静态资源放行，但实际路由到 /api/admin 接口
```

##### 6.1.2 分号路径参数绕过（;.js 系列）

| 绕过模式 | Payload示例 | 原理 |
|----------|-------------|------|
| 分号+静态后缀 | `/admin;.js`, `/admin;.css`, `/admin;.png` | Tomcat删除分号后内容，白名单匹配后缀 |
| 分号+路径穿越 | `/public;/../admin` | 分号截断+目录穿越组合 |
| 分号+URL编码 | `/admin%3b.js` | 编码后的分号 |
| 分号+参数 | `/admin;bypass=true` | 路径矩阵参数 |
| 前置分号 | `/;/admin` | 某些解析器的特殊处理 |

**验证 PoC：**

```http
# 分号后缀绕过（最常见）
GET /center/api/users;.js HTTP/1.1
Host: {{host}}

# 分号+多种后缀
GET /center/api/users;.css HTTP/1.1
GET /center/api/users;.png HTTP/1.1
GET /center/api/users;.html HTTP/1.1

# 分号+URL编码组合
GET /center/api/users%3b.js HTTP/1.1
Host: {{host}}

# 分号+路径穿越
GET /public;/../admin/users HTTP/1.1
Host: {{host}}
```

##### 6.1.3 路径规范化差异绕过

| 绕过模式 | 检测方法 | 风险 |
|----------|----------|------|
| 路径穿越 | `/admin/../public`, `/public/../admin` | 高 |
| 双斜杠 | `//admin`, `/api//users` | 高 |
| 点斜杠 | `/./admin`, `/api/./users` | 高 |
| URL编码斜杠 | `/admin%2fusers`, `%2fadmin` | 高 |
| 双重编码 | `/admin%252fusers` | 高 |
| 大小写绕过 | `/ADMIN` vs `/admin` | 中 |
| 后缀绕过 | `/admin.action` 无鉴权但 `/admin` 有鉴权 | 高 |
| 尾部斜杠 | `/admin/` vs `/admin` | 中 |
| 参数污染 | `?role=admin` 覆盖用户角色 | 高 |
| 空字节 | `/admin%00.jpg` | 高 |

##### 6.1.4 数据流分析（CRITICAL - 避免误报）

**发现可疑代码模式后，必须进行数据流分析，避免误报！**

**问题背景：** 仅凭模式匹配（如发现 `contains()` 匹配）就报告漏洞是不够的。必须追踪变量的完整使用链，判断绕过是否真正有效。

**数据流分析步骤：**

```
步骤1: 识别可疑模式
  └── 发现 isIgnoreUrl() 使用 contains() 匹配

步骤2: 追踪变量使用链
  └── uri 变量在白名单匹配后如何使用？
      ├── 仅用于白名单判断 → 需继续分析后续逻辑
      └── 还用于权限检查 → 分析权限检查如何处理 uri

步骤3: 分析后续代码逻辑
  └── 例如 getActionPrefix(uri) 取最后一段
      → 路径穿越不影响最终权限判断
      → 绕过无效！

步骤4: 得出结论
  └── 白名单可被绕过，但权限检查仍有效
      → 降低风险等级或标注"需验证"
```

**必须回答的问题：**

| 问题 | 分析要点 |
|------|----------|
| 变量如何被后续使用？ | 追踪 uri 在匹配后的所有使用点 |
| 绕过后执行什么逻辑？ | 分析 if/else 各分支的完整代码 |
| 是否有二次校验？ | 检查后续是否有其他安全检查 |
| 路径穿越是否影响最终结果？ | 分析路径处理函数（如取最后一段） |

**示例：错误分析 vs 正确分析**

```java
// 被审计的代码
if (this.isIgnoreUrl(uri)) {
    chain.doFilter(request, response);  // 白名单放行
} else {
    if (privileges.contains(getActionPrefix(uri))) {  // 权限检查
        chain.doFilter(request, response);
    }
}

// getActionPrefix() 实现
public static String getActionPrefix(String uri) {
    String[] components = uri.split("/");
    return components[components.length - 1];  // 取最后一段！
}
```

| 分析方式 | 结论 | 正确性 |
|----------|------|--------|
| ❌ 模式匹配 | `contains()` 可被路径穿越绕过 → 报告高危漏洞 | 错误 |
| ✅ 数据流分析 | 路径穿越后 `getActionPrefix()` 仍取最后一段，权限检查不受影响 → 绕过无效 | 正确 |

##### 6.1.5 多层鉴权架构分析（CRITICAL）

**必须识别完整的鉴权架构，分析绕过单层后是否还有其他层拦截！**

**典型多层鉴权架构：**

```
请求 → Filter层 → Interceptor层 → Action层
         │              │              │
         │              │              └── 业务逻辑中的权限检查
         │              └── Session检查、权限校验
         └── 登录检查、白名单、CSRF防护
```

**分析要点：**

| 层级 | 常见职责 | 绕过影响 |
|------|----------|----------|
| Filter层 | 登录检查、白名单、CSRF | 绕过可能导致未授权访问 |
| Interceptor层 | Session检查、细粒度权限 | 绕过可能导致越权 |
| Action层 | 业务权限校验 | 绕过可能导致数据泄露 |

**必须区分的鉴权类型：**

| 类型 | 检查内容 | 示例代码 | 绕过后果 |
|------|----------|----------|----------|
| 登录检查 | Session 是否有效 | `session.getAttribute("user") != null` | 未授权访问 |
| 权限检查 | 用户是否有特定权限 | `privileges.contains(actionPrefix)` | 越权访问 |
| 白名单检查 | 路径是否在白名单 | `isIgnoreUrl(uri)` | 需看后续逻辑 |

**关键判断：obj != null 的语义**

```java
// 常见模式
Object obj = session.getAttribute("user");
if (obj != null) {
    // 已登录用户 → 执行权限检查
    if (isIgnoreUrl(uri)) {
        chain.doFilter(...);  // 白名单：跳过细粒度权限检查
    } else {
        checkPermission(uri);  // 权限检查
    }
} else {
    // 未登录用户 → 放行给后续组件（可能有Interceptor拦截）
    chain.doFilter(...);
}
```

**分析要点：**
- `obj != null` 表示"用户已登录"
- 白名单绕过只影响"已登录用户的权限检查"
- 未登录用户放行后，后续 Interceptor 可能会拦截

**多层分析检查清单：**

- [ ] 识别所有鉴权层（Filter/Interceptor/Action）
- [ ] 分析每层的职责（登录检查/权限检查/业务校验）
- [ ] 判断绕过单层后是否有其他层拦截
- [ ] 区分"绕过登录检查"和"绕过权限检查"
- [ ] 分析 `obj != null` 或类似条件的业务含义

#### 6.2 越权访问检测

| 越权类型 | 检测方法 | 风险 |
|----------|----------|------|
| 水平越权 | 接口使用用户可控 ID，无归属校验 | 高 |
| 垂直越权 | 普通用户可访问管理接口 | 高 |
| 未授权访问 | 接口完全无鉴权 | 高 |

#### 6.3 会话管理检测

| 问题 | 检测方法 | 风险 |
|------|----------|------|
| Session 固定 | 登录前后 Session ID 不变 | 中 |
| 会话超时过长 | Session timeout > 30min | 低 |
| Cookie 不安全 | 缺少 HttpOnly/Secure 标志 | 中 |

### 7. 报告生成（CRITICAL - 必须生成三个文件）

**必须生成以下三个文件，缺一不可：**

```
{project_name}_audit/auth_audit/
├── {project_name}_auth_audit_{timestamp}.md      # 主报告（漏洞分析）
├── {project_name}_auth_mapping_{timestamp}.md    # 路由-鉴权映射表
└── {project_name}_auth_README_{timestamp}.md     # 审计说明文档
```

#### 7.1 三个文件的职责划分（避免内容重复）

| 文件 | 核心职责 | 包含内容 | 不应包含 |
|------|----------|----------|----------|
| 主报告 | 漏洞分析 | 漏洞详情、数据流分析、PoC、修复措施 | 完整路由列表 |
| 映射表 | 路由清单 | 所有路由的鉴权状态表格 | 漏洞详细分析 |
| 说明文档 | 审计元信息 | 方法论、工具、局限性、验证指南 | 具体漏洞内容 |

#### 7.2 报告生成子步骤（必须按顺序执行）

```
步骤 7.1: 生成主报告
  └── 创建 {project_name}_auth_audit_{timestamp}.md
      ├── 鉴权框架识别
      ├── 鉴权架构概览
      ├── 风险统计
      ├── 高危/中危/低危风险详情
      └── 修复建议总结

步骤 7.2: 生成映射表
  └── 创建 {project_name}_auth_mapping_{timestamp}.md
      ├── 按模块分组的路由表格
      ├── 鉴权状态说明
      └── 风险统计汇总

步骤 7.3: 生成审计说明文档
  └── 创建 {project_name}_auth_README_{timestamp}.md
      ├── 审计概述（目标、范围、时间）
      ├── 审计方法和工具
      ├── 审计局限性
      ├── 验证方法说明
      └── 下一步建议

步骤 7.4: 验证报告完整性（CRITICAL）
  └── 检查三个文件是否都存在
      ├── [ ] 主报告文件存在
      ├── [ ] 映射表文件存在
      └── [ ] 说明文档文件存在
```

#### 7.3 文件完整性验证命令

```bash
# 验证三个文件都已生成
ls -la {project_name}_audit/auth_audit/

# 预期输出应包含：
# {project_name}_auth_audit_{timestamp}.md
# {project_name}_auth_mapping_{timestamp}.md
# {project_name}_auth_README_{timestamp}.md
```

**如果任何文件缺失，必须立即补充！**

---

## 输出格式

**必须生成 3 个文件，严格按照 references/ 目录中的填充式模板生成。**

| 文件 | 模板 | 命名格式 | 职责 |
|------|------|---------|------|
| 主报告 | [OUTPUT_TEMPLATE_MAIN.md](references/OUTPUT_TEMPLATE_MAIN.md) | `{project_name}_auth_audit_{YYYYMMDD_HHMMSS}.md` | 漏洞分析和修复建议 |
| 映射表 | [OUTPUT_TEMPLATE_MAPPING.md](references/OUTPUT_TEMPLATE_MAPPING.md) | `{project_name}_auth_mapping_{YYYYMMDD_HHMMSS}.md` | 完整路由-鉴权对应关系 |
| 说明文档 | [OUTPUT_TEMPLATE_README.md](references/OUTPUT_TEMPLATE_README.md) | `{project_name}_auth_README_{YYYYMMDD_HHMMSS}.md` | 审计方法论和局限性 |

**关键规则：**
- 必须生成 3 个文件（不是 1 个也不是 2 个）
- 主报告不包含完整路由列表（放映射表中）
- 映射表不包含漏洞详细分析（放主报告中）
- README 不包含具体漏洞内容
- 三个文件间互相引用链接必须正确
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

---

## 验证检查清单

**在标记审计完成前，必须执行以下检查：**

### 架构分析检查
- [ ] 识别完整的鉴权架构（Filter/Interceptor/Action 各层）
- [ ] 分析每层的职责（登录检查/权限检查/业务校验）
- [ ] 绘制鉴权架构图

### 代码分析检查
- [ ] 所有 Filter/Interceptor 已分析
- [ ] 所有鉴权配置已解析
- [ ] 每个路由都有鉴权状态标注

### 漏洞检测检查
- [ ] 所有绕过模式已检测
- [ ] **对每个可疑模式执行了数据流分析**
- [ ] **区分了"已验证"和"待验证"漏洞**
- [ ] **分析了绕过后是否有其他层拦截**

### 报告质量检查
- [ ] 高危风险都有前置条件分析
- [ ] 高危风险都有数据流分析
- [ ] 高危风险都有实际影响说明
- [ ] 高危风险都有验证 PoC（区分登录/未登录场景）

### 文件完整性检查（CRITICAL - 三文件验证）
- [ ] **主报告文件已生成**: `{project_name}_audit/auth_audit/{project_name}_auth_audit_{timestamp}.md`
- [ ] **映射表文件已生成**: `{project_name}_audit/auth_audit/{project_name}_auth_mapping_{timestamp}.md`
- [ ] **说明文档已生成**: `{project_name}_audit/auth_audit/{project_name}_auth_README_{timestamp}.md`
- [ ] 三个文件内容不重复（职责划分正确）
- [ ] 文件间相互引用链接正确

**⚠️ 如果任何文件缺失，必须立即补充后再标记完成！**

---

## 验证建议

**PoC 验证时必须区分以下场景：**

### 场景矩阵

| 场景 | Cookie状态 | 测试目的 |
|------|------------|----------|
| 未登录访问 | 无Cookie | 测试是否可完全绕过鉴权 |
| 过期Session访问 | 带无效Cookie | 测试Session校验是否有效 |
| 普通用户访问 | 带普通用户Cookie | 测试是否可越权到管理功能 |
| 管理员访问 | 带管理员Cookie | 对照组，确认接口正常工作 |

### 验证步骤

```
步骤1: 获取有效 Cookie
  └── 登录普通用户账号，获取 JSESSIONID

步骤2: 未登录状态测试
  └── 不带任何 Cookie 发送绕过请求
      ├── 成功 → 严重漏洞：完全绕过鉴权
      └── 失败（302/401/403）→ 继续步骤3

步骤3: 已登录状态测试
  └── 带普通用户 Cookie 发送绕过请求
      ├── 成功访问管理功能 → 高危：越权访问
      └── 失败 → 绕过无效或仅影响特定场景

步骤4: 分析结果
  └── 根据测试结果调整漏洞等级和描述
```

### PoC 模板

**未登录测试模板：**
```http
GET /admin/cascade_/../admin/deleteUser.action HTTP/1.1
Host: {{host}}
# 注意：不带任何 Cookie
```

**已登录测试模板：**
```http
GET /admin/cascade_/../admin/deleteUser.action HTTP/1.1
Host: {{host}}
Cookie: JSESSIONID={{valid_session}}
# 使用普通用户的 Session
```

### 结果判断标准

| 响应 | 未登录状态含义 | 已登录状态含义 |
|------|----------------|----------------|
| 200 + 业务数据 | ❌ 严重：完全绕过 | ❌ 高危：越权访问 |
| 200 + 空/错误 | 可能部分绕过 | 可能部分绕过 |
| 302 跳转登录 | 鉴权有效 | 不适用 |
| 401/403 | 鉴权有效 | 权限校验有效 |
| 500 错误 | 需分析错误原因 | 需分析错误原因 |

---

## 与 java-route-mapper 协作

```
java-route-mapper              java-auth-audit-opencode
     │                                   │
     │  提取所有 HTTP 路由                │  分析每个路由的鉴权状态
     │  生成 Burp Suite 模板             │  检测鉴权绕过漏洞
     │                                   │
     └─────────────┬─────────────────────┘
                   │
                   ▼
           完整的路由 + 鉴权审计报告
```

**推荐流程：**

1. 先使用 java-route-mapper 提取所有路由
2. 使用本技能分析每个路由的鉴权状态
3. 合并生成完整的安全审计报告

---

## 故障排除

| 问题 | 解决方案 |
|------|----------|
| 无法识别鉴权框架 | 检查 pom.xml 依赖，查找自定义 Filter |
| 反编译失败 | 检查 Java 版本，尝试单文件反编译 |
| 鉴权逻辑复杂 | 标记为"需人工确认"，提供代码位置 |
| 路由信息不完整 | 先运行 java-route-mapper |

---

## 参考资料

- [OUTPUT_TEMPLATE_MAIN.md](references/OUTPUT_TEMPLATE_MAIN.md) - 主报告填充式模板
- [OUTPUT_TEMPLATE_MAPPING.md](references/OUTPUT_TEMPLATE_MAPPING.md) - 映射表填充式模板
- [OUTPUT_TEMPLATE_README.md](references/OUTPUT_TEMPLATE_README.md) - 说明文档填充式模板
- [SHIRO.md](references/SHIRO.md) - Apache Shiro 鉴权审计
- [SPRING_SECURITY.md](references/SPRING_SECURITY.md) - Spring Security 鉴权审计
- [JWT.md](references/JWT.md) - JWT Token 鉴权审计
- [FILTER_INTERCEPTOR.md](references/FILTER_INTERCEPTOR.md) - Filter/Interceptor 鉴权审计
- [ANNOTATION_AUTH.md](references/ANNOTATION_AUTH.md) - 注解式鉴权审计
- [SESSION_AUTH.md](references/SESSION_AUTH.md) - Session 会话鉴权审计
- [BYPASS_PATTERNS.md](references/BYPASS_PATTERNS.md) - 鉴权绕过模式
- [URI_PARSING_BYPASS.md](references/URI_PARSING_BYPASS.md) - URI解析差异导致的鉴权绕过
- [VULNERABILITY_CHECKLIST.md](references/VULNERABILITY_CHECKLIST.md) - 漏洞检查清单
- [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md) - 反编译策略指南

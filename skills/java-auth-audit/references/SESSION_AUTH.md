# Session 会话鉴权审计

## 目录

- [概述](#概述)
- [Session 管理分析](#session-管理分析)
- [Cookie 安全审计](#cookie-安全审计)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 概述

Session 是 Web 应用中最常见的状态管理机制，用于在无状态的 HTTP 协议上维护用户登录状态。

### Session 工作流程

```
1. 用户登录成功
2. 服务器创建 Session，存储用户信息
3. 服务器返回 Session ID (通常通过 Cookie)
4. 后续请求携带 Session ID
5. 服务器根据 Session ID 识别用户
```

---

## Session 管理分析

### Session 创建审计

```java
// 登录接口
@PostMapping("/login")
public Result login(String username, String password, HttpServletRequest request) {
    User user = userService.authenticate(username, password);
    
    if (user != null) {
        // ⚠️ 检查点 1: Session 固定攻击防护
        // 登录前后是否更换 Session ID?
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();  // 销毁旧 Session
        }
        
        HttpSession session = request.getSession(true);  // 创建新 Session
        
        // ⚠️ 检查点 2: Session 中存储的信息
        session.setAttribute("user", user);  // 是否存储敏感信息?
        session.setAttribute("userId", user.getId());
        session.setAttribute("role", user.getRole());
        
        // ⚠️ 检查点 3: Session 超时设置
        session.setMaxInactiveInterval(1800);  // 30 分钟
        
        return Result.success();
    }
    
    return Result.fail("Invalid credentials");
}
```

### Session 验证审计

```java
// Filter 中的 Session 验证
public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
    HttpServletRequest request = (HttpServletRequest) req;
    
    // ⚠️ 检查点 1: Session 获取方式
    HttpSession session = request.getSession(false);  // 不创建新 Session
    
    if (session == null) {
        // 未登录
        redirectToLogin(resp);
        return;
    }
    
    // ⚠️ 检查点 2: 用户信息获取
    Object user = session.getAttribute("user");
    if (user == null) {
        redirectToLogin(resp);
        return;
    }
    
    // ⚠️ 检查点 3: 用户状态实时检查
    // 是否检查用户是否仍然有效（未被禁用/删除）?
    // User currentUser = userService.findById(((User)user).getId());
    // if (currentUser == null || currentUser.isDisabled()) { ... }
    
    // ⚠️ 检查点 4: 角色/权限检查
    // 是否仅验证登录状态，未验证权限?
    
    chain.doFilter(req, resp);
}
```

### Session 销毁审计

```java
// 登出接口
@PostMapping("/logout")
public Result logout(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    
    if (session != null) {
        // ⚠️ 检查点: 是否正确销毁 Session
        session.invalidate();
    }
    
    return Result.success();
}
```

---

## Cookie 安全审计

### Cookie 属性

| 属性 | 说明 | 安全建议 |
|------|------|----------|
| HttpOnly | 禁止 JavaScript 访问 | 必须启用 |
| Secure | 仅 HTTPS 传输 | 生产环境必须启用 |
| SameSite | 跨站请求限制 | Strict 或 Lax |
| Path | Cookie 作用路径 | 限制到必要路径 |
| Domain | Cookie 作用域 | 不要设置为顶级域 |
| Max-Age/Expires | 过期时间 | 合理设置 |

### Spring Boot 配置

```properties
# application.properties
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict
server.servlet.session.timeout=30m
```

```java
// 代码配置
@Configuration
public class SessionConfig {
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig config = servletContext.getSessionCookieConfig();
            config.setHttpOnly(true);
            config.setSecure(true);
            // config.setSameSite("Strict");  // Servlet 4.0+
        };
    }
}
```

### web.xml 配置

```xml
<session-config>
    <session-timeout>30</session-timeout>
    <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
    </cookie-config>
</session-config>
```

---

## 常见漏洞模式

### 1. Session 固定攻击

```java
// ⚠️ 漏洞代码: 登录后未更换 Session ID
@PostMapping("/login")
public Result login(String username, String password, HttpServletRequest request) {
    User user = authenticate(username, password);
    if (user != null) {
        HttpSession session = request.getSession();  // 可能复用攻击者预设的 Session
        session.setAttribute("user", user);
        return Result.success();
    }
    return Result.fail();
}

// 攻击流程:
// 1. 攻击者访问网站获取 Session ID: JSESSIONID=abc123
// 2. 攻击者诱导受害者使用该 Session ID 登录
// 3. 受害者登录成功，Session ID 不变
// 4. 攻击者使用 abc123 访问，获得受害者权限
```

**修复方案：**
```java
@PostMapping("/login")
public Result login(String username, String password, HttpServletRequest request) {
    User user = authenticate(username, password);
    if (user != null) {
        // 销毁旧 Session
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }
        // 创建新 Session
        HttpSession session = request.getSession(true);
        session.setAttribute("user", user);
        return Result.success();
    }
    return Result.fail();
}
```

### 2. Session 超时过长

```java
// ⚠️ 问题: Session 永不过期或过期时间过长
session.setMaxInactiveInterval(-1);  // 永不过期
session.setMaxInactiveInterval(86400 * 7);  // 7 天

// 风险:
// - Session 劫持后风险窗口过大
// - 服务器内存压力
```

### 3. Cookie 缺少安全属性

```java
// ⚠️ 问题: 手动设置 Cookie 时缺少安全属性
Cookie cookie = new Cookie("sessionId", sessionId);
// 缺少 HttpOnly
// 缺少 Secure
// 缺少 SameSite
response.addCookie(cookie);

// 正确做法:
Cookie cookie = new Cookie("sessionId", sessionId);
cookie.setHttpOnly(true);
cookie.setSecure(true);
cookie.setPath("/");
cookie.setMaxAge(1800);
response.addCookie(cookie);
```

### 4. Session 数据未加密

```java
// ⚠️ 问题: Session 中存储敏感信息
session.setAttribute("password", user.getPassword());  // 不应存储密码
session.setAttribute("creditCard", user.getCreditCard());  // 不应存储卡号

// 正确做法: 只存储必要的非敏感信息
session.setAttribute("userId", user.getId());
session.setAttribute("username", user.getUsername());
```

### 5. 并发 Session 控制缺失

```java
// ⚠️ 问题: 同一用户可以多处登录
// 可能导致:
// - 账户被盗用不易发现
// - 权限被滥用

// Spring Security 配置:
http.sessionManagement()
    .maximumSessions(1)  // 限制并发登录数
    .expiredUrl("/login?expired")
    .maxSessionsPreventsLogin(true);  // 阻止新登录
```

### 6. 未验证用户状态

```java
// ⚠️ 问题: 仅验证 Session，未验证用户当前状态
HttpSession session = request.getSession(false);
User user = (User) session.getAttribute("user");
// 直接使用 user，未检查用户是否已被禁用

// 正确做法:
User currentUser = userService.findById(user.getId());
if (currentUser == null || currentUser.isDisabled()) {
    session.invalidate();
    throw new UnauthorizedException("User is disabled");
}
```

### 7. Session 劫持

```java
// 攻击方式:
// 1. 窃取 Cookie (XSS, 网络嗅探)
// 2. 使用窃取的 Session ID 冒充用户

// 防护措施:
// 1. HttpOnly Cookie
// 2. HTTPS
// 3. Session 绑定 IP/User-Agent
// 4. 敏感操作二次验证

// IP 绑定示例:
@PostMapping("/login")
public Result login(..., HttpServletRequest request) {
    // ...
    session.setAttribute("clientIp", request.getRemoteAddr());
}

// 验证时:
String sessionIp = (String) session.getAttribute("clientIp");
String currentIp = request.getRemoteAddr();
if (!sessionIp.equals(currentIp)) {
    session.invalidate();
    throw new SecurityException("Session IP mismatch");
}
```

---

## 审计检查清单

### Session 配置

- [ ] Session 超时时间是否合理 (建议 15-30 分钟)
- [ ] 是否配置了并发 Session 控制
- [ ] 是否使用安全的 Session ID 生成器

### Session 生命周期

- [ ] 登录后是否更换 Session ID
- [ ] 登出时是否销毁 Session
- [ ] 是否清理 Session 中的敏感数据

### Cookie 安全

- [ ] HttpOnly 是否启用
- [ ] Secure 是否启用 (HTTPS)
- [ ] SameSite 是否配置
- [ ] Cookie 路径是否限制

### 状态验证

- [ ] 是否实时验证用户状态
- [ ] 是否有 Session 劫持防护
- [ ] 敏感操作是否需要二次验证

---

## 输出示例

```markdown
=== [SESS-001] Session 固定攻击风险 ===
风险等级: 高
位置: LoginController.login (LoginController.java:45)

问题描述:
- 登录成功后未更换 Session ID
- 存在 Session 固定攻击风险

当前代码:
HttpSession session = request.getSession();
session.setAttribute("user", user);

建议修复:
HttpSession oldSession = request.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();
}
HttpSession session = request.getSession(true);
session.setAttribute("user", user);

---

=== [SESS-002] Cookie 缺少 HttpOnly 属性 ===
风险等级: 中
位置: web.xml / application.properties

问题描述:
- Session Cookie 未设置 HttpOnly 属性
- JavaScript 可以访问 Cookie
- 增加 XSS 攻击窃取 Session 的风险

建议修复:
# application.properties
server.servlet.session.cookie.http-only=true

---

=== [SESS-003] Session 超时时间过长 ===
风险等级: 低
位置: web.xml:25

问题描述:
- Session 超时时间设置为 24 小时
- 风险窗口过大

当前配置:
<session-timeout>1440</session-timeout>

建议修复:
- 将超时时间缩短到 30 分钟
- 或实现滑动过期机制
```

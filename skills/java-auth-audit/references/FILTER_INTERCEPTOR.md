# Filter/Interceptor 鉴权审计

## 目录

- [概述](#概述)
- [Filter 审计](#filter-审计)
- [Interceptor 审计](#interceptor-审计)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 概述

### Filter vs Interceptor

| 特性 | Filter | Interceptor |
|------|--------|-------------|
| 规范 | Servlet 规范 | Spring MVC |
| 执行时机 | DispatcherServlet 之前 | Handler 之前/之后 |
| 配置位置 | web.xml / @WebFilter | WebMvcConfigurer |
| 访问能力 | ServletRequest/Response | HttpServletRequest + Handler |

### 执行顺序

```
请求 → Filter1 → Filter2 → DispatcherServlet → Interceptor1 → Interceptor2 → Controller
```

---

## Filter 审计

### 配置识别

#### web.xml 配置

```xml
<filter>
    <filter-name>authFilter</filter-name>
    <filter-class>com.example.filter.AuthFilter</filter-class>
    <init-param>
        <param-name>excludePaths</param-name>
        <param-value>/login,/public</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>authFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

#### 注解配置

```java
@WebFilter(
    filterName = "authFilter",
    urlPatterns = "/*",
    initParams = {
        @WebInitParam(name = "excludePaths", value = "/login,/public")
    }
)
public class AuthFilter implements Filter { }
```

### Filter 代码审计

```java
public class AuthFilter implements Filter {
    
    private Set<String> excludePaths = new HashSet<>();
    
    @Override
    public void init(FilterConfig config) {
        // ⚠️ 检查点 1: 初始化参数
        String excludes = config.getInitParameter("excludePaths");
        if (excludes != null) {
            excludePaths.addAll(Arrays.asList(excludes.split(",")));
        }
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;
        
        // ⚠️ 检查点 2: 路径获取方式
        String path = request.getRequestURI();  // 包含 context path
        // 或
        String path = request.getServletPath();  // 不包含 context path
        
        // ⚠️ 检查点 3: 路径规范化
        // 是否处理了 ../、//、; 等特殊字符?
        
        // ⚠️ 检查点 4: 白名单匹配逻辑
        if (isExcluded(path)) {
            chain.doFilter(req, resp);
            return;
        }
        
        // ⚠️ 检查点 5: 鉴权逻辑
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.sendRedirect("/login");
            return;
        }
        
        Object user = session.getAttribute("user");
        if (user == null) {
            response.sendRedirect("/login");
            return;
        }
        
        // ⚠️ 检查点 6: 是否有角色/权限校验
        // 仅检查登录状态，无权限控制
        
        chain.doFilter(req, resp);
    }
    
    // ⚠️ 检查点 7: 白名单匹配实现
    private boolean isExcluded(String path) {
        // 常见问题实现
        for (String exclude : excludePaths) {
            if (path.startsWith(exclude)) {  // startsWith 可被绕过
                return true;
            }
            if (path.contains(exclude)) {  // contains 更危险
                return true;
            }
        }
        return false;
    }
}
```

### 安全的 Filter 实现

```java
public class SecureAuthFilter implements Filter {
    
    private List<Pattern> excludePatterns = new ArrayList<>();
    
    @Override
    public void init(FilterConfig config) {
        // 使用正则表达式匹配
        excludePatterns.add(Pattern.compile("^/login$"));
        excludePatterns.add(Pattern.compile("^/public/.*"));
        excludePatterns.add(Pattern.compile("^/static/.*"));
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest) req;
        
        // 路径规范化
        String path = normalizePath(request.getRequestURI());
        
        // 移除 context path
        String contextPath = request.getContextPath();
        if (path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        
        // 精确匹配
        if (isExcluded(path)) {
            chain.doFilter(req, resp);
            return;
        }
        
        // 鉴权逻辑...
    }
    
    private String normalizePath(String path) {
        // 1. URL 解码
        path = URLDecoder.decode(path, StandardCharsets.UTF_8);
        // 2. 移除 .. 和 .
        path = URI.create(path).normalize().getPath();
        // 3. 移除重复斜杠
        path = path.replaceAll("/+", "/");
        // 4. 移除尾部斜杠
        if (path.endsWith("/") && path.length() > 1) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }
    
    private boolean isExcluded(String path) {
        for (Pattern pattern : excludePatterns) {
            if (pattern.matcher(path).matches()) {
                return true;
            }
        }
        return false;
    }
}
```

---

## Interceptor 审计

### 配置识别

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthInterceptor())
            .addPathPatterns("/**")           // 拦截所有
            .excludePathPatterns(             // 排除路径
                "/login",
                "/public/**",
                "/static/**"
            );
    }
}
```

### Interceptor 代码审计

```java
public class AuthInterceptor implements HandlerInterceptor {
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        
        // ⚠️ 检查点 1: handler 类型检查
        if (!(handler instanceof HandlerMethod)) {
            return true;  // 静态资源直接放行
        }
        
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        
        // ⚠️ 检查点 2: 注解检查
        // 检查方法或类上是否有免登录注解
        if (handlerMethod.hasMethodAnnotation(Anonymous.class) ||
            handlerMethod.getBeanType().isAnnotationPresent(Anonymous.class)) {
            return true;
        }
        
        // ⚠️ 检查点 3: Token 获取
        String token = request.getHeader("Authorization");
        if (token == null || token.isEmpty()) {
            response.setStatus(401);
            return false;
        }
        
        // ⚠️ 检查点 4: Token 验证
        try {
            Claims claims = jwtUtil.parseToken(token);
            request.setAttribute("userId", claims.getSubject());
            request.setAttribute("userRole", claims.get("role"));
        } catch (Exception e) {
            response.setStatus(401);
            return false;
        }
        
        // ⚠️ 检查点 5: 权限校验
        RequiresRole requiresRole = handlerMethod.getMethodAnnotation(RequiresRole.class);
        if (requiresRole != null) {
            String userRole = (String) request.getAttribute("userRole");
            if (!requiresRole.value().equals(userRole)) {
                response.setStatus(403);
                return false;
            }
        }
        
        return true;
    }
}
```

---

## 常见漏洞模式

### 1. 路径匹配绕过

```java
// ⚠️ 问题: startsWith 匹配
if (path.startsWith("/public")) {
    return true;  // 放行
}

// 绕过方式:
// /publicXXX  - 不应该放行但被放行
// /public/../admin  - 路径穿越
```

### 2. 大小写绕过

```java
// ⚠️ 问题: 区分大小写匹配
excludePaths.add("/admin");

// 绕过方式:
// /Admin, /ADMIN, /aDmIn
```

### 3. URL 编码绕过

```java
// ⚠️ 问题: 未解码 URL
String path = request.getRequestURI();  // 可能包含编码字符

// 绕过方式:
// /admin → /%61dmin (a 的 URL 编码)
// /admin → /admin%2f../public
```

### 4. 路径穿越绕过

```java
// ⚠️ 问题: 未规范化路径
if (path.startsWith("/public")) {
    return true;
}

// 绕过方式:
// /public/../admin
// /public/./../../admin
```

### 5. 分号参数绕过

```java
// ⚠️ Tomcat 特性: 分号后的内容被视为路径参数
// /admin;jsessionid=xxx → 匹配 /admin
// /admin;.js → 可能绕过某些检查
```

### 6. 双斜杠绕过

```java
// ⚠️ 问题: 未处理双斜杠
if (path.equals("/admin")) {
    // 需要认证
}

// 绕过方式:
// //admin
// /./admin
```

### 7. Filter 顺序问题

```xml
<!-- ⚠️ 顺序错误 -->
<filter-mapping>
    <filter-name>loggingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
<filter-mapping>
    <filter-name>authFilter</filter-name>
    <url-pattern>/api/*</url-pattern>  <!-- 只保护 /api -->
</filter-mapping>

<!-- /admin 未被 authFilter 保护! -->
```

### 8. Interceptor 不拦截静态资源

```java
// ⚠️ 问题: 静态资源 handler 被直接放行
if (!(handler instanceof HandlerMethod)) {
    return true;  // 静态资源放行
}

// 如果 /admin/config.json 被配置为静态资源，将绕过鉴权
```

---

## 审计检查清单

### Filter 审计

- [ ] 检查 url-pattern 覆盖范围
- [ ] 检查白名单路径是否过宽
- [ ] 检查路径匹配算法（startsWith/contains/equals）
- [ ] 检查是否处理 URL 编码
- [ ] 检查是否处理路径穿越
- [ ] 检查是否处理大小写
- [ ] 检查 Filter 执行顺序

### Interceptor 审计

- [ ] 检查 addPathPatterns 和 excludePathPatterns
- [ ] 检查静态资源处理逻辑
- [ ] 检查注解处理逻辑
- [ ] 检查 Interceptor 执行顺序

### 通用检查

- [ ] 是否有默认拒绝逻辑
- [ ] 异常情况下是否放行
- [ ] 是否验证用户角色/权限
- [ ] 是否验证用户状态

---

## 输出示例

```markdown
=== [FI-001] 路径匹配绕过风险 ===
风险等级: 高
位置: AuthFilter.java:45

问题描述:
- 使用 startsWith("/public") 进行白名单匹配
- 可通过 /publicXXX 绕过鉴权
- 可通过 /public/../admin 访问受保护资源

当前代码:
if (path.startsWith("/public")) {
    return true;
}

验证 PoC:
\```http
GET /public/../admin/users HTTP/1.1
Host: {{host}}
\```

建议修复:
- 使用正则表达式精确匹配: ^/public(/.*)?$
- 在匹配前规范化路径

---

=== [FI-002] URL 编码绕过风险 ===
风险等级: 高
位置: AuthFilter.java:30

问题描述:
- 直接使用 request.getRequestURI() 获取路径
- 未进行 URL 解码
- 可通过 URL 编码绕过路径检查

验证 PoC:
\```http
GET /%61dmin/users HTTP/1.1
Host: {{host}}
\```

建议修复:
- 使用 URLDecoder.decode() 解码路径
- 或使用 request.getServletPath()
```

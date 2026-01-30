# 鉴权审计反编译策略指南

## 目录

- [何时反编译](#何时反编译)
- [反编译工具使用](#反编译工具使用)
- [鉴权类识别与定位](#鉴权类识别与定位)
- [反编译结果分析](#反编译结果分析)
- [常见问题](#常见问题)

---

## 何时反编译

### 必须反编译的场景

1. **项目只有编译后的字节码**
   - WAR/JAR 包部署，无源码
   - 第三方依赖中的鉴权组件

2. **鉴权类定义在 .class 文件中**
   - 自定义 Filter/Interceptor
   - 自定义 Realm/Provider
   - 权限注解处理器

3. **需要分析鉴权逻辑细节**
   - 路径匹配算法
   - 权限校验逻辑
   - 白名单/黑名单实现

### 不需要反编译的场景

1. 源码已存在且可读取
2. 标准框架类（Shiro/Spring Security 核心类）
3. 配置文件可直接读取（shiro.ini, SecurityConfig.java）

---

## 反编译工具使用

### MCP Java Decompiler 调用方式

#### 单个文件反编译

```python
# 反编译单个 Filter/Interceptor 类
mcp__java-decompile-mcp__decompile_file(
    file_path="/path/to/WEB-INF/classes/com/example/filter/AuthFilter.class",
    output_dir="/path/to/decompiled",
    save_to_file=True  # 推荐，直接保存到文件系统
)
```

#### 目录反编译

```python
# 递归反编译整个 security 包
mcp__java-decompile-mcp__decompile_directory(
    directory_path="/path/to/WEB-INF/classes/com/example/security",
    output_dir="/path/to/decompiled",
    recursive=True,
    save_to_file=True,
    show_progress=True,
    max_workers=4  # 并发线程数
)
```

#### 批量文件反编译

```python
# 反编译多个指定的鉴权相关类
mcp__java-decompile-mcp__decompile_files(
    file_paths=[
        "/path/to/AuthFilter.class",
        "/path/to/SecurityConfig.class",
        "/path/to/PermissionInterceptor.class",
        "/path/to/CustomRealm.class",
        "/path/to/JwtTokenFilter.class"
    ],
    output_dir="/path/to/decompiled",
    save_to_file=True,
    max_workers=4
)
```

#### 检查 Java 环境

```python
# 检查 Java 版本（反编译需要）
mcp__java-decompile-mcp__get_java_version()

# 检查 CFR 反编译器状态
mcp__java-decompile-mcp__check_cfr_status()

# 如需下载 CFR
mcp__java-decompile-mcp__download_cfr_tool(
    target_dir="/path/to/tools"
)
```

---

## 鉴权类识别与定位

### 按框架定位

#### Shiro 相关类

```bash
# 查找 Shiro 相关类
find . -name "*.class" | xargs strings | grep -l "org.apache.shiro"

# 常见类名模式
*Realm.class           # 自定义 Realm
*ShiroConfig*.class    # Shiro 配置
*ShiroFilter*.class    # Shiro Filter
```

**反编译目标：**
```python
shiro_classes = [
    "*Realm.class",
    "*ShiroConfig*.class",
    "*ShiroFilter*.class",
    "*Permission*.class"
]
```

#### Spring Security 相关类

```bash
# 查找 Spring Security 相关类
find . -name "*Security*.class" -o -name "*Auth*.class"

# 常见类名模式
*SecurityConfig*.class      # Security 配置
*WebSecurityConfigurer*.class
*AuthenticationProvider*.class
*UserDetailsService*.class
```

**反编译目标：**
```python
spring_security_classes = [
    "*SecurityConfig*.class",
    "*AuthProvider*.class",
    "*UserDetails*.class",
    "*AccessDecision*.class"
]
```

#### Filter/Interceptor 类

```bash
# 从 web.xml 中提取 Filter 类名
grep -A2 "<filter-class>" web.xml

# 常见类名模式
*Filter.class
*AuthFilter.class
*LoginFilter.class
*TokenFilter.class
*Interceptor.class
*AuthInterceptor.class
```

**反编译目标：**
```python
filter_interceptor_classes = [
    "*Filter.class",
    "*Interceptor.class",
    "*Handler.class"
]
```

#### JWT 相关类

```bash
# 查找 JWT 相关类
find . -name "*Jwt*.class" -o -name "*Token*.class"

# 常见类名模式
*JwtUtil*.class
*JwtFilter*.class
*TokenProvider*.class
*JwtAuthenticationFilter*.class
```

### 按配置文件定位

#### 从 web.xml 定位

```xml
<filter>
    <filter-name>authFilter</filter-name>
    <filter-class>com.example.filter.AuthFilter</filter-class>
</filter>
```

**提取类路径：** `com.example.filter.AuthFilter`
**对应 class 文件：** `WEB-INF/classes/com/example/filter/AuthFilter.class`

#### 从 Spring 配置定位

```xml
<bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
    <property name="filterChainDefinitions">
        <value>
            /login = anon
            /** = authc
        </value>
    </property>
</bean>
```

#### 从注解扫描定位

```bash
# 搜索包含鉴权注解的类
grep -r "@RequiresAuthentication\|@PreAuthorize\|@Secured" --include="*.java"
grep -r "implements Filter\|implements HandlerInterceptor" --include="*.java"
```

---

## 反编译结果分析

### Filter 类分析要点

```java
// 反编译后的 AuthFilter 示例
public class AuthFilter implements Filter {
    
    // ⚠️ 关注点 1: 白名单路径
    private static final String[] EXCLUDE_PATHS = {
        "/login",
        "/public",
        "/static",
        "/api/health"
    };
    
    // ⚠️ 关注点 2: 初始化参数
    @Override
    public void init(FilterConfig config) {
        String excludes = config.getInitParameter("excludes");
        // 可能从配置读取额外的白名单
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest) req;
        String path = request.getRequestURI();
        
        // ⚠️ 关注点 3: 路径匹配逻辑
        if (isExcluded(path)) {
            chain.doFilter(req, resp);  // 直接放行
            return;
        }
        
        // ⚠️ 关注点 4: 鉴权校验逻辑
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            ((HttpServletResponse) resp).sendRedirect("/login");
            return;
        }
        
        // ⚠️ 关注点 5: 权限校验（可能缺失）
        // 仅检查登录状态，未检查角色/权限
        
        chain.doFilter(req, resp);
    }
    
    // ⚠️ 关注点 6: 路径匹配实现
    private boolean isExcluded(String path) {
        for (String exclude : EXCLUDE_PATHS) {
            // 潜在绕过: startsWith 可被路径穿越绕过
            if (path.startsWith(exclude)) {
                return true;
            }
        }
        return false;
    }
}
```

**提取信息：**

| 信息类型 | 内容 | 风险评估 |
|----------|------|----------|
| 白名单路径 | `/login`, `/public`, `/static`, `/api/health` | 检查是否过宽 |
| 匹配方式 | `startsWith` | 可能被绕过 |
| 鉴权方式 | Session 校验 | 仅认证，无授权 |
| 缺失检查 | 无角色/权限校验 | 可能越权 |

### Interceptor 类分析要点

```java
// 反编译后的 AuthInterceptor 示例
public class AuthInterceptor implements HandlerInterceptor {
    
    // ⚠️ 关注点 1: 排除路径
    private List<String> excludePaths = Arrays.asList(
        "/login", "/register", "/captcha"
    );
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) {
        String path = request.getServletPath();
        
        // ⚠️ 关注点 2: 排除逻辑
        if (excludePaths.contains(path)) {
            return true;  // 放行
        }
        
        // ⚠️ 关注点 3: Token 校验
        String token = request.getHeader("Authorization");
        if (token == null || !token.startsWith("Bearer ")) {
            response.setStatus(401);
            return false;
        }
        
        // ⚠️ 关注点 4: Token 解析
        try {
            String jwt = token.substring(7);
            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)  // 硬编码密钥?
                .parseClaimsJws(jwt)
                .getBody();
            
            // ⚠️ 关注点 5: 用户信息存储
            request.setAttribute("userId", claims.getSubject());
            return true;
        } catch (Exception e) {
            response.setStatus(401);
            return false;
        }
    }
}
```

**提取信息：**

| 信息类型 | 内容 | 风险评估 |
|----------|------|----------|
| 排除路径 | `/login`, `/register`, `/captcha` | 精确匹配，较安全 |
| 鉴权方式 | JWT Token | 需检查密钥管理 |
| Token 位置 | Authorization Header | 标准做法 |
| 潜在问题 | 硬编码密钥 | 高风险 |

### Shiro Realm 分析要点

```java
// 反编译后的 CustomRealm 示例
public class CustomRealm extends AuthorizingRealm {
    
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        
        // ⚠️ 关注点 1: 权限获取逻辑
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        
        // 从数据库获取角色
        Set<String> roles = userService.getRoles(username);
        info.setRoles(roles);
        
        // ⚠️ 关注点 2: 权限硬编码?
        if ("admin".equals(username)) {
            info.addStringPermission("*");  // 超级权限
        }
        
        return info;
    }
    
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        String username = (String) token.getPrincipal();
        
        // ⚠️ 关注点 3: 密码校验
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException();
        }
        
        // ⚠️ 关注点 4: 密码存储方式
        return new SimpleAuthenticationInfo(
            username,
            user.getPassword(),  // 检查是否加密
            ByteSource.Util.bytes(user.getSalt()),  // 是否有盐
            getName()
        );
    }
}
```

---

## 反编译策略

### 策略 1: 最小化反编译（推荐）

```python
# 只反编译与鉴权直接相关的类

# 步骤 1: 从配置文件识别入口类
entry_classes = parse_web_xml_filters() + parse_spring_interceptors()

# 步骤 2: 反编译入口类
for cls in entry_classes:
    decompile_file(cls)

# 步骤 3: 分析依赖，反编译权限相关的依赖类
dependencies = extract_auth_dependencies(entry_classes)
for dep in dependencies:
    if is_auth_related(dep):
        decompile_file(dep)
```

### 策略 2: 层级反编译

```python
# 第一层: 反编译 Filter/Interceptor
layer1 = ["*Filter.class", "*Interceptor.class"]
decompile_by_pattern(layer1)

# 第二层: 反编译 Security 配置
layer2 = ["*SecurityConfig*.class", "*ShiroConfig*.class"]
decompile_by_pattern(layer2)

# 第三层: 反编译 Realm/Provider
layer3 = ["*Realm.class", "*Provider.class", "*UserDetails*.class"]
decompile_by_pattern(layer3)

# 第四层: 反编译工具类
layer4 = ["*Util*.class", "*Helper*.class"]
decompile_by_pattern(layer4)
```

### 策略 3: 按包反编译

```python
# 当鉴权类集中在特定包下
auth_packages = [
    "com/example/security",
    "com/example/filter",
    "com/example/interceptor",
    "com/example/auth"
]

for pkg in auth_packages:
    mcp__java-decompile-mcp__decompile_directory(
        directory_path=f"/WEB-INF/classes/{pkg}",
        recursive=True
    )
```

---

## 常见问题

### 问题 1: 反编译失败

**可能原因：**
- Java 版本不匹配
- 代码被混淆
- class 文件损坏

**解决方案：**
```python
# 检查 Java 版本
mcp__java-decompile-mcp__get_java_version()

# 检查 CFR 状态
mcp__java-decompile-mcp__check_cfr_status()

# 如果需要，下载 CFR
mcp__java-decompile-mcp__download_cfr_tool()
```

### 问题 2: 变量名被混淆

**表现：**
```java
// 混淆后
public void a(String b, String c) {
    if (d.e(b)) { f.g(c); }
}
```

**解决方案：**
- 通过方法签名和调用上下文推断功能
- 关注注解信息（通常不被混淆）
- 分析字符串常量

### 问题 3: 泛型信息丢失

**表现：**
```java
// 原始
List<User> users = getUsers();

// 反编译后
List users = getUsers();
```

**影响：**
- 不影响鉴权逻辑分析
- 可通过使用上下文推断类型

### 问题 4: Lambda 表达式

**表现：**
```java
// 反编译后可能显示为匿名类
new Predicate() {
    public boolean test(Object o) {
        return ((User)o).isAdmin();
    }
}
```

**解决方案：**
- Lambda 不影响鉴权逻辑分析
- 关注谓词条件本身

---

## 反编译结果记录

输出时必须标注反编译来源：

```markdown
=== [AUTH-001] 未授权访问 ===
风险等级: 高
位置: AdminController.deleteUser (AdminController.java:45)
来源: **反编译 WEB-INF/classes/com/example/controller/AdminController.class**

问题描述:
- 该接口无任何鉴权注解
- Filter 配置未覆盖此路径
```

---

## 性能优化

### 批量操作

```python
# 一次性反编译多个文件，减少启动开销
mcp__java-decompile-mcp__decompile_files(
    file_paths=all_auth_classes,
    max_workers=4
)
```

### 并行处理

```python
# 使用多线程加速
mcp__java-decompile-mcp__decompile_directory(
    directory_path=auth_package,
    max_workers=4  # 根据 CPU 核心数调整
)
```

### 缓存利用

- 反编译结果默认保存到 `decompiled` 目录
- 再次分析时可直接读取已反编译的文件
- 避免重复反编译相同的类

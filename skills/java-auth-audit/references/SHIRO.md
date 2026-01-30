# Apache Shiro 鉴权审计

## 目录

- [框架识别](#框架识别)
- [配置文件分析](#配置文件分析)
- [核心组件审计](#核心组件审计)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 框架识别

### 识别特征

| 特征类型 | 特征内容 |
|----------|----------|
| Maven 依赖 | `org.apache.shiro:shiro-core`, `shiro-spring`, `shiro-web` |
| 配置文件 | `shiro.ini`, `shiro-spring.xml`, `ShiroConfig.java` |
| 注解 | `@RequiresAuthentication`, `@RequiresRoles`, `@RequiresPermissions` |
| 核心类 | `SecurityUtils`, `Subject`, `SecurityManager` |

### 版本检测

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.9.0</version>  <!-- 检查版本，低版本有已知漏洞 -->
</dependency>
```

**已知漏洞版本：**
- < 1.5.2: CVE-2020-1957 (路径绕过，需配合 Spring)
- < 1.5.3: CVE-2020-11989 (路径绕过，需配合 Spring)
- < 1.6.0: CVE-2020-13933 (认证绕过)
- < 1.7.1: CVE-2020-17523 (认证绕过，需 Spring 集成)
- < 1.8.0: CVE-2021-41303 (路径绕过)
- < 1.9.1: CVE-2022-32532 (RegexRequestMatcher 绕过)

---

## 配置文件分析

### shiro.ini 格式

```ini
[main]
# 定义 Realm
myRealm = com.example.security.MyRealm
securityManager.realms = $myRealm

# 定义 Filter
authc = org.apache.shiro.web.filter.authc.FormAuthenticationFilter
authc.loginUrl = /login

[urls]
# 路径 = 过滤器链
/login = anon
/logout = logout
/static/** = anon
/api/public/** = anon
/admin/** = authc, roles[admin]
/user/** = authc, roles[user]
/** = authc
```

**提取内容：**

| 路径模式 | 过滤器 | 鉴权要求 |
|----------|--------|----------|
| `/login` | anon | 公开访问 |
| `/static/**` | anon | 公开访问 |
| `/admin/**` | authc, roles[admin] | 需要 admin 角色 |
| `/**` | authc | 需要认证 |

### Spring 配置格式

```java
@Configuration
public class ShiroConfig {
    
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean filter = new ShiroFilterFactoryBean();
        filter.setSecurityManager(securityManager);
        filter.setLoginUrl("/login");
        filter.setUnauthorizedUrl("/403");
        
        // ⚠️ 审计重点: filterChainDefinitionMap
        Map<String, String> filterChain = new LinkedHashMap<>();
        filterChain.put("/login", "anon");
        filterChain.put("/static/**", "anon");
        filterChain.put("/api/public/**", "anon");
        filterChain.put("/admin/**", "authc, roles[admin]");
        filterChain.put("/**", "authc");  // 默认规则
        
        filter.setFilterChainDefinitionMap(filterChain);
        return filter;
    }
}
```

### XML 配置格式

```xml
<bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
    <property name="securityManager" ref="securityManager"/>
    <property name="loginUrl" value="/login"/>
    <property name="filterChainDefinitions">
        <value>
            /login = anon
            /static/** = anon
            /admin/** = authc, roles[admin]
            /** = authc
        </value>
    </property>
</bean>
```

---

## 核心组件审计

### Realm 审计

```java
public class CustomRealm extends AuthorizingRealm {
    
    // 授权方法 - 检查权限分配逻辑
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        
        // ⚠️ 检查点 1: 角色获取逻辑
        Set<String> roles = userService.getRoles(username);
        info.setRoles(roles);
        
        // ⚠️ 检查点 2: 是否有硬编码权限
        if ("admin".equals(username)) {
            info.addStringPermission("*");  // 危险: 超级权限
        }
        
        // ⚠️ 检查点 3: 权限获取逻辑
        Set<String> permissions = userService.getPermissions(username);
        info.setStringPermissions(permissions);
        
        return info;
    }
    
    // 认证方法 - 检查密码校验逻辑
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        String username = (String) token.getPrincipal();
        User user = userService.findByUsername(username);
        
        // ⚠️ 检查点 4: 账户状态检查
        if (user == null) {
            throw new UnknownAccountException();
        }
        if (user.isLocked()) {
            throw new LockedAccountException();
        }
        
        // ⚠️ 检查点 5: 密码存储方式
        return new SimpleAuthenticationInfo(
            username,
            user.getPassword(),  // 是否加密?
            ByteSource.Util.bytes(user.getSalt()),  // 是否有盐?
            getName()
        );
    }
}
```

**Realm 审计要点：**

| 检查项 | 风险 | 建议 |
|--------|------|------|
| 硬编码权限 | 高 | 从数据库动态获取 |
| 密码明文存储 | 高 | 使用加密存储 |
| 无账户锁定 | 中 | 添加锁定机制 |
| 权限缓存不当 | 中 | 权限变更时清除缓存 |

### Filter 审计

```java
// 常用 Shiro Filter
anon        // AnonymousFilter - 匿名访问
authc       // FormAuthenticationFilter - 表单认证
authcBasic  // BasicHttpAuthenticationFilter - HTTP Basic
logout      // LogoutFilter - 登出
roles[xxx]  // RolesAuthorizationFilter - 角色校验
perms[xxx]  // PermissionsAuthorizationFilter - 权限校验
user        // UserFilter - 已登录或记住我
ssl         // SslFilter - 要求 HTTPS
```

### 自定义 Filter 审计

```java
public class CustomAuthFilter extends AccessControlFilter {
    
    @Override
    protected boolean isAccessAllowed(ServletRequest request, 
                                      ServletResponse response, 
                                      Object mappedValue) {
        // ⚠️ 检查访问控制逻辑
        Subject subject = getSubject(request, response);
        
        // 检查是否登录
        if (!subject.isAuthenticated()) {
            return false;
        }
        
        // ⚠️ 检查角色校验逻辑
        String[] roles = (String[]) mappedValue;
        for (String role : roles) {
            if (subject.hasRole(role)) {
                return true;
            }
        }
        return false;
    }
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, 
                                     ServletResponse response) {
        // ⚠️ 检查拒绝处理逻辑
        HttpServletResponse resp = (HttpServletResponse) response;
        resp.setStatus(403);
        return false;
    }
}
```

---

## 常见漏洞模式

### 1. 路径绕过 (CVE-2020-11989)

**漏洞条件：**
- Shiro < 1.5.3
- Spring 框架
- 路径包含 `/`

**绕过方式：**
```
配置: /admin/** = authc
绕过: /admin/page%2f  (URL编码的/)
```

### 2. 路径规范化绕过

**漏洞模式：**
```java
// 配置
filterChain.put("/admin/**", "authc");

// 绕过尝试
/admin/../admin/page    // 路径穿越
//admin/page            // 双斜杠
/admin;jsessionid=xxx   // 分号参数
/admin/./page           // 点号
```

### 3. 过滤器顺序问题

```java
// ⚠️ 错误顺序 - 先匹配到 /** 导致 /admin 无保护
filterChain.put("/**", "anon");
filterChain.put("/admin/**", "authc");

// ✅ 正确顺序 - 具体路径在前
filterChain.put("/admin/**", "authc");
filterChain.put("/**", "anon");
```

### 4. 默认规则缺失

```java
// ⚠️ 危险: 无默认规则，未配置的路径可匿名访问
filterChain.put("/login", "anon");
filterChain.put("/admin/**", "authc");
// 缺少: filterChain.put("/**", "authc");

// /api/secret 可匿名访问!
```

### 5. 记住我反序列化 (CVE-2016-4437)

**漏洞条件：**
- 使用默认的 RememberMe Cookie 密钥
- 或密钥泄露

**检查点：**
```java
// 检查是否使用默认密钥
CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
rememberMeManager.setCipherKey(Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));  // 默认密钥!
```

---

## 审计检查清单

### 配置审计

- [ ] 检查 Shiro 版本，是否有已知漏洞
- [ ] 检查 filterChainDefinitionMap 顺序是否正确
- [ ] 检查是否有默认拒绝规则 (`/** = authc`)
- [ ] 检查 anon 路径是否过宽
- [ ] 检查 RememberMe 密钥是否为默认值

### 代码审计

- [ ] 检查 Realm 中是否有硬编码权限
- [ ] 检查密码是否加密存储
- [ ] 检查是否有账户锁定机制
- [ ] 检查自定义 Filter 的逻辑是否正确
- [ ] 检查权限缓存是否及时更新

### 绕过测试

- [ ] 测试路径穿越绕过
- [ ] 测试 URL 编码绕过
- [ ] 测试大小写绕过
- [ ] 测试分号参数绕过
- [ ] 测试双斜杠绕过

---

## 输出示例

```markdown
=== [SHIRO-001] Shiro 版本存在已知漏洞 ===
风险等级: 高
位置: pom.xml
版本: 1.4.0

问题描述:
- 当前 Shiro 版本 1.4.0 存在多个已知漏洞
- CVE-2020-11989: 路径绕过漏洞
- CVE-2016-4437: RememberMe 反序列化漏洞

建议修复:
- 升级到 Shiro 1.10.0 或更高版本

---

=== [SHIRO-002] 过滤器链顺序错误 ===
风险等级: 高
位置: ShiroConfig.java:45

问题描述:
- `/**` 规则在 `/admin/**` 之前
- 导致 /admin 路径可匿名访问

当前配置:
filterChain.put("/**", "anon");
filterChain.put("/admin/**", "authc");

建议修复:
filterChain.put("/admin/**", "authc");
filterChain.put("/**", "anon");
```

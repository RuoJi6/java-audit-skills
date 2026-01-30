# Spring Security 鉴权审计

## 目录

- [框架识别](#框架识别)
- [配置分析](#配置分析)
- [核心组件审计](#核心组件审计)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 框架识别

### 识别特征

| 特征类型 | 特征内容 |
|----------|----------|
| Maven 依赖 | `spring-boot-starter-security`, `spring-security-core` |
| 注解 | `@EnableWebSecurity`, `@PreAuthorize`, `@Secured` |
| 配置类 | `WebSecurityConfigurerAdapter`, `SecurityFilterChain` |
| 核心类 | `SecurityContextHolder`, `Authentication`, `UserDetails` |

### 版本检测

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    <version>2.7.0</version>
</dependency>
```

---

## 配置分析

### Spring Security 5.x+ 配置 (推荐方式)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ⚠️ 检查点 1: CSRF 配置
            .csrf(csrf -> csrf.disable())  // 危险: 禁用 CSRF
            
            // ⚠️ 检查点 2: 路径权限配置
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/api/health").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()  // 默认需要认证
            )
            
            // ⚠️ 检查点 3: 登录配置
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            
            // ⚠️ 检查点 4: Session 管理
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
            );
            
        return http.build();
    }
}
```

### 旧版配置 (WebSecurityConfigurerAdapter)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
                .permitAll();
    }
}
```

### 路径匹配器分析

| 匹配器 | 说明 | 示例 |
|--------|------|------|
| `antMatchers` | Ant 风格匹配 | `/admin/**`, `/user/*` |
| `mvcMatchers` | MVC 风格匹配（推荐） | `/admin/**` |
| `regexMatchers` | 正则表达式匹配 | `"/api/v[0-9]+/.*"` |
| `requestMatchers` | 通用匹配器 (5.8+) | `/admin/**` |

**重要：** `antMatchers` 和 `mvcMatchers` 的行为不同：
```java
// antMatchers("/admin") 只匹配 /admin
// mvcMatchers("/admin") 匹配 /admin 和 /admin/
```

---

## 核心组件审计

### UserDetailsService 审计

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        
        // ⚠️ 检查点 1: 用户不存在处理
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        
        // ⚠️ 检查点 2: 账户状态检查
        boolean enabled = user.isEnabled();
        boolean accountNonExpired = !user.isExpired();
        boolean credentialsNonExpired = !user.isPasswordExpired();
        boolean accountNonLocked = !user.isLocked();
        
        // ⚠️ 检查点 3: 权限获取
        List<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
            .collect(Collectors.toList());
        
        return new org.springframework.security.core.userdetails.User(
            username,
            user.getPassword(),
            enabled,
            accountNonExpired,
            credentialsNonExpired,
            accountNonLocked,
            authorities
        );
    }
}
```

### PasswordEncoder 审计

```java
@Bean
public PasswordEncoder passwordEncoder() {
    // ⚠️ 危险配置
    return NoOpPasswordEncoder.getInstance();  // 明文密码!
    
    // ✅ 推荐配置
    return new BCryptPasswordEncoder();
}
```

### 方法级安全审计

```java
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,   // 启用 @PreAuthorize, @PostAuthorize
    securedEnabled = true,   // 启用 @Secured
    jsr250Enabled = true     // 启用 @RolesAllowed
)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
}
```

---

## 常见漏洞模式

### 1. 路径匹配不一致

```java
// ⚠️ 问题: antMatchers 不匹配尾部斜杠
http.authorizeRequests()
    .antMatchers("/admin").hasRole("ADMIN")  // 只保护 /admin
    .anyRequest().permitAll();

// /admin/ 可绕过!

// ✅ 修复: 使用 mvcMatchers 或匹配两种形式
.mvcMatchers("/admin").hasRole("ADMIN")
// 或
.antMatchers("/admin", "/admin/").hasRole("ADMIN")
```

### 2. 顺序错误

```java
// ⚠️ 错误: permitAll 在前，后续规则无效
http.authorizeRequests()
    .anyRequest().permitAll()           // 匹配所有
    .antMatchers("/admin/**").hasRole("ADMIN");  // 永远不会执行

// ✅ 正确: 具体规则在前
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().permitAll();
```

### 3. CSRF 禁用风险

```java
// ⚠️ 危险: 完全禁用 CSRF
http.csrf().disable();

// ✅ 仅对 API 禁用
http.csrf()
    .ignoringAntMatchers("/api/**")
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
```

### 4. 不安全的 CORS 配置

```java
// ⚠️ 危险: 允许所有来源
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOrigin("*");  // 危险!
    config.addAllowedMethod("*");
    config.addAllowedHeader("*");
    config.setAllowCredentials(true);  // 与 * 冲突
    // ...
}
```

### 5. 权限表达式漏洞

```java
// ⚠️ 危险: 用户可控的权限表达式
@PreAuthorize("#userId == authentication.principal.id")
public User getUser(@PathVariable Long userId) {
    // 如果 userId 来自用户输入且未验证，可能被绕过
}

// ⚠️ SpEL 注入风险
@PreAuthorize("hasPermission(#input, 'read')")
public void process(String input) {
    // input 可能包含恶意 SpEL 表达式
}
```

### 6. 记住我功能风险

```java
// ⚠️ 使用简单的 Token 存储
http.rememberMe()
    .key("weakKey123")  // 弱密钥
    .tokenValiditySeconds(86400 * 30);  // 30天有效期过长
```

---

## 审计检查清单

### 配置审计

- [ ] 检查是否有默认拒绝规则 (`anyRequest().authenticated()`)
- [ ] 检查路径匹配器类型（antMatchers vs mvcMatchers）
- [ ] 检查规则顺序是否正确
- [ ] 检查 CSRF 配置是否合理
- [ ] 检查 CORS 配置是否过于宽松
- [ ] 检查 Session 管理配置

### 密码安全

- [ ] 检查 PasswordEncoder 是否安全
- [ ] 检查是否禁用了 NoOpPasswordEncoder
- [ ] 检查密码策略是否足够强

### 方法级安全

- [ ] 检查 @PreAuthorize 表达式是否安全
- [ ] 检查是否有 SpEL 注入风险
- [ ] 检查敏感方法是否都有权限注解

### 认证机制

- [ ] 检查登录失败处理
- [ ] 检查账户锁定机制
- [ ] 检查记住我功能安全性

---

## 输出示例

```markdown
=== [SS-001] 路径匹配不一致 ===
风险等级: 高
位置: SecurityConfig.java:32

问题描述:
- 使用 antMatchers("/admin") 保护管理路径
- antMatchers 不匹配尾部斜杠
- /admin/ 可绕过权限控制

验证 PoC:
\```http
GET /admin/ HTTP/1.1
Host: {{host}}
\```

建议修复:
- 使用 mvcMatchers("/admin") 替代
- 或同时匹配: antMatchers("/admin", "/admin/**")

---

=== [SS-002] CSRF 保护被禁用 ===
风险等级: 中
位置: SecurityConfig.java:25

问题描述:
- CSRF 保护被完全禁用
- 存在跨站请求伪造风险

当前配置:
http.csrf().disable();

建议修复:
- 仅对无状态 API 禁用 CSRF
- 对表单提交保持 CSRF 保护
```

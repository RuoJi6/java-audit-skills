# 注解式鉴权审计

## 目录

- [概述](#概述)
- [Shiro 注解](#shiro-注解)
- [Spring Security 注解](#spring-security-注解)
- [自定义注解](#自定义注解)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 概述

注解式鉴权通过在方法或类上添加注解来声明权限要求，是一种细粒度的访问控制方式。

### 优势

- 权限声明与业务代码紧密结合
- 易于理解和维护
- 编译时可检查

### 风险

- 注解遗漏导致未授权访问
- 注解配置错误
- AOP 代理失效导致注解不生效

---

## Shiro 注解

### 注解类型

| 注解 | 作用 | 示例 |
|------|------|------|
| `@RequiresAuthentication` | 需要登录 | 任意已登录用户 |
| `@RequiresUser` | 需要登录或记住我 | 包含 RememberMe |
| `@RequiresGuest` | 需要未登录 | 游客访问 |
| `@RequiresRoles` | 需要角色 | `@RequiresRoles("admin")` |
| `@RequiresPermissions` | 需要权限 | `@RequiresPermissions("user:delete")` |

### 使用示例

```java
@RestController
@RequestMapping("/admin")
@RequiresRoles("admin")  // 类级别：所有方法需要 admin 角色
public class AdminController {
    
    @GetMapping("/users")
    public List<User> listUsers() {
        // 继承类级别的 @RequiresRoles("admin")
    }
    
    @DeleteMapping("/users/{id}")
    @RequiresPermissions("user:delete")  // 方法级别：额外需要删除权限
    public void deleteUser(@PathVariable Long id) {
    }
    
    // ⚠️ 风险：无额外注解，仅需 admin 角色
    @PostMapping("/config")
    public void updateConfig() {
    }
}
```

### 逻辑组合

```java
// AND 逻辑：需要同时满足
@RequiresRoles(value = {"admin", "manager"}, logical = Logical.AND)

// OR 逻辑：满足其一即可
@RequiresRoles(value = {"admin", "manager"}, logical = Logical.OR)

// 多权限 AND
@RequiresPermissions(value = {"user:read", "user:write"}, logical = Logical.AND)
```

---

## Spring Security 注解

### 启用注解

```java
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,    // 启用 @PreAuthorize, @PostAuthorize
    securedEnabled = true,    // 启用 @Secured
    jsr250Enabled = true      // 启用 @RolesAllowed
)
public class MethodSecurityConfig { }
```

### 注解类型

| 注解 | 作用 | 表达式支持 |
|------|------|------------|
| `@PreAuthorize` | 方法执行前检查 | SpEL |
| `@PostAuthorize` | 方法执行后检查 | SpEL |
| `@PreFilter` | 过滤输入集合 | SpEL |
| `@PostFilter` | 过滤输出集合 | SpEL |
| `@Secured` | 角色检查 | 无 |
| `@RolesAllowed` | JSR-250 角色检查 | 无 |

### 使用示例

```java
@RestController
@RequestMapping("/api")
public class UserController {
    
    // 简单角色检查
    @Secured("ROLE_ADMIN")
    @GetMapping("/admin/users")
    public List<User> listUsers() { }
    
    // SpEL 表达式
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    @GetMapping("/users")
    public List<User> getUsers() { }
    
    // 参数级别的权限检查
    @PreAuthorize("#userId == authentication.principal.id or hasRole('ADMIN')")
    @GetMapping("/users/{userId}")
    public User getUser(@PathVariable Long userId) { }
    
    // 返回值检查
    @PostAuthorize("returnObject.owner == authentication.principal.username")
    @GetMapping("/documents/{id}")
    public Document getDocument(@PathVariable Long id) { }
    
    // 集合过滤
    @PostFilter("filterObject.owner == authentication.principal.username")
    @GetMapping("/my-documents")
    public List<Document> getMyDocuments() { }
}
```

### SpEL 表达式

| 表达式 | 说明 |
|--------|------|
| `hasRole('ADMIN')` | 有 ROLE_ADMIN 角色 |
| `hasAnyRole('ADMIN', 'USER')` | 有任一角色 |
| `hasAuthority('user:read')` | 有指定权限 |
| `isAuthenticated()` | 已认证 |
| `isAnonymous()` | 匿名用户 |
| `#paramName` | 方法参数 |
| `returnObject` | 返回值 |
| `authentication` | 认证对象 |
| `principal` | 当前用户 |

---

## 自定义注解

### 定义注解

```java
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    String value();
    boolean requireAll() default true;
}

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Anonymous {
    // 标记为匿名访问
}
```

### 注解处理器

```java
@Aspect
@Component
public class PermissionAspect {
    
    @Around("@annotation(requiresPermission)")
    public Object checkPermission(ProceedingJoinPoint pjp, 
                                  RequiresPermission requiresPermission) throws Throwable {
        
        // ⚠️ 检查点 1: 获取当前用户
        User currentUser = SecurityContext.getCurrentUser();
        if (currentUser == null) {
            throw new UnauthorizedException("Not logged in");
        }
        
        // ⚠️ 检查点 2: 权限检查逻辑
        String requiredPermission = requiresPermission.value();
        if (!currentUser.hasPermission(requiredPermission)) {
            throw new ForbiddenException("No permission: " + requiredPermission);
        }
        
        return pjp.proceed();
    }
}
```

### 审计要点

```java
// ⚠️ 问题 1: AOP 代理失效
@Service
public class UserService {
    
    @RequiresPermission("user:delete")
    public void deleteUser(Long id) { }
    
    public void batchDelete(List<Long> ids) {
        for (Long id : ids) {
            this.deleteUser(id);  // ⚠️ 内部调用，AOP 不生效!
        }
    }
}

// ⚠️ 问题 2: 注解未被扫描
// 确保 @EnableAspectJAutoProxy 已启用
// 确保切面类被 Spring 管理

// ⚠️ 问题 3: 顺序问题
// 确保权限切面在事务切面之前执行
@Order(1)  // 优先级
public class PermissionAspect { }
```

---

## 常见漏洞模式

### 1. 注解遗漏

```java
@RestController
@RequestMapping("/admin")
public class AdminController {
    
    @RequiresRoles("admin")
    @GetMapping("/users")
    public List<User> listUsers() { }
    
    // ⚠️ 忘记添加注解
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        // 无权限控制!
    }
}
```

### 2. 类级别注解被覆盖

```java
@RestController
@RequiresAuthentication  // 类级别：需要登录
public class ApiController {
    
    @Anonymous  // ⚠️ 如果处理不当，可能覆盖类级别注解
    @GetMapping("/public")
    public String publicApi() { }
    
    @GetMapping("/private")
    public String privateApi() { }  // 是否继承类级别注解?
}
```

### 3. SpEL 注入

```java
// ⚠️ 危险：用户输入可能影响 SpEL 表达式
@PreAuthorize("hasPermission(#input, 'read')")
public void process(String input) {
    // 如果 input 包含 SpEL 语法，可能被注入
}
```

### 4. 内部调用绕过

```java
@Service
public class OrderService {
    
    @PreAuthorize("hasRole('ADMIN')")
    public void cancelOrder(Long orderId) {
        // 权限检查
    }
    
    public void processRefund(Long orderId) {
        // ...
        this.cancelOrder(orderId);  // ⚠️ 内部调用，AOP 不生效
    }
}
```

### 5. 权限表达式错误

```java
// ⚠️ 逻辑错误：AND 写成 OR
@PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")  // 应该是 and
public void superAdminOnly() { }

// ⚠️ 角色名错误
@Secured("ADMIN")  // 缺少 ROLE_ 前缀
@Secured("ROLE_ADMIN")  // 正确
```

### 6. 私有方法注解无效

```java
@Service
public class UserService {
    
    @PreAuthorize("hasRole('ADMIN')")
    private void internalMethod() {
        // ⚠️ 私有方法上的注解可能不生效
    }
}
```

---

## 审计检查清单

### 注解覆盖检查

- [ ] 所有敏感接口是否都有权限注解
- [ ] 类级别注解是否正确继承
- [ ] 是否存在未保护的公开方法

### 注解配置检查

- [ ] @EnableGlobalMethodSecurity 是否正确配置
- [ ] SpEL 表达式是否正确
- [ ] 角色名是否正确（ROLE_ 前缀）

### AOP 代理检查

- [ ] 切面是否正确扫描
- [ ] 内部调用是否绕过代理
- [ ] 切面执行顺序是否正确

### 自定义注解检查

- [ ] 注解处理器逻辑是否正确
- [ ] 异常处理是否安全
- [ ] 是否有绕过风险

---

## 输出示例

```markdown
=== [ANN-001] 敏感接口缺少权限注解 ===
风险等级: 高
位置: AdminController.deleteUser (AdminController.java:45)
路由: DELETE /admin/users/{id}

问题描述:
- 该删除接口无权限注解保护
- 类级别也无默认权限控制
- 可能导致未授权删除用户

建议修复:
- 添加 @RequiresRoles("admin") 或 @PreAuthorize("hasRole('ADMIN')")
- 或在类级别添加默认权限注解

---

=== [ANN-002] 内部调用绕过权限检查 ===
风险等级: 中
位置: OrderService.processRefund (OrderService.java:78)

问题描述:
- processRefund 方法内部调用 cancelOrder
- cancelOrder 有 @PreAuthorize 注解
- 内部调用不经过 AOP 代理，权限检查被绕过

代码:
public void processRefund(Long orderId) {
    this.cancelOrder(orderId);  // 内部调用
}

@PreAuthorize("hasRole('ADMIN')")
public void cancelOrder(Long orderId) { }

建议修复:
- 注入自身代理: @Autowired private OrderService self;
- 使用 self.cancelOrder(orderId);
- 或提取到单独的服务类
```

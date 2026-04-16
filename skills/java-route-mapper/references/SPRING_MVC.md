# Spring MVC 路由分析

## 目录

- [项目识别](#项目识别)
- [配置文件](#配置文件)
- [路由注解](#路由注解)
- [参数注解](#参数注解)
- [路径解析规则](#路径解析规则)
- [常见模式](#常见模式)

---

## 项目识别

**特征文件：**
```
pom.xml - 检查 spring-webmvc、spring-boot-starter-web 依赖
application.properties / application.yml - Spring Boot 配置
web.xml - 传统 Spring MVC 配置
[servlet-name]-servlet.xml - Spring MVC 配置文件
```

**特征注解：**
```
@Controller / @RestController
@Configuration / @SpringBootApplication
@EnableWebMvc
```

---

## 配置文件

### application.properties / application.yml

**关键配置：**

```properties
# 上下文路径
server.servlet.context-path=/api
server.contextPath=/api

# 端口
server.port=8080
```

```yaml
server:
  servlet:
    context-path: /api
  port: 8080
```

**提取要点：**
- `context-path` 需要添加到所有路由前缀
- 默认 context-path 为 `/`

### WebMvcConfigurer 配置

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/old", "/new");
    }
}
```

**提取要点：**
- 检查 `addViewControllers` 方法中的直接路由映射
- 检查 `addResourceHandlers` 中的静态资源路径

---

## 路由注解

### 类级别 @RequestMapping

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    // 所有方法的路径前缀为 /api/users
}
```

**路径组合规则：**
```
完整路径 = context-path + 类级别路径 + 方法级别路径
例：/api + /users + /{id} = /api/users/{id}
```

### 方法级别注解

| 注解 | HTTP 方法 | 用途 |
|------|-----------|------|
| `@GetMapping` | GET | 查询资源 |
| `@PostMapping` | POST | 创建资源 |
| `@PutMapping` | PUT | 更新资源（全量） |
| `@PatchMapping` | PATCH | 更新资源（部分） |
| `@DeleteMapping` | DELETE | 删除资源 |
| `@RequestMapping(method = ...)` | 自定义 | 通用方法声明 |

### @RequestMapping 属性

```java
@RequestMapping(
    value = "/path",           // 路径
    method = RequestMethod.POST, // HTTP 方法
    params = "action=save",    // 请求参数条件
    headers = "X-Requested-With=XMLHttpRequest", // 请求头条件
    consumes = "application/json",  // 请求 Content-Type
    produces = "application/json"   // 响应 Content-Type
)
```

**提取要点：**
- `params` 和 `headers` 条件需要在参数结构中体现
- `consumes` 确定请求 Content-Type

---

## 参数注解

### 路径变量 @PathVariable

```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id) { }

@GetMapping("/users/{userId}/posts/{postId}")
public Post getPost(@PathVariable Long userId, @PathVariable Long postId) { }

// 自定义变量名
@GetMapping("/users/{id}")
public User getUser(@PathVariable("userId") Long id) { }
```

**提取规则：**
- 路径中的 `{variable}` 标记
- 参数名与变量名对应
- 记录参数类型

### 查询参数 @RequestParam

```java
@GetMapping("/search")
public List<User> search(
    @RequestParam String keyword,
    @RequestParam(defaultValue = "0") int page,
    @RequestParam(required = false) String sort
) { }
```

**提取规则：**
- 参数名：注解 value 或方法参数名
- 是否必需：`required` 属性（默认 true）
- 默认值：`defaultValue` 属性
- 参数类型：影响格式验证

### 请求体 @RequestBody

```java
@PostMapping("/users")
public User create(@RequestBody UserDto userDto) { }

@PostMapping("/data")
public void processData(@RequestBody Map<String, Object> data) { }

// 指定 Content-Type
@PostMapping(value = "/users", consumes = "application/json")
public User create(@RequestBody UserDto userDto) { }
```

**提取规则：**
- 参数类型决定 Body 结构
- 需要进一步分析 POJO 类的字段
- `consumes` 确定请求 Content-Type

### 请求头 @RequestHeader

```java
@GetMapping("/data")
public Data getData(@RequestHeader("Authorization") String auth) { }

// 带默认值
@GetMapping("/data")
public Data getData(
    @RequestHeader(value = "User-Agent", defaultValue = "Unknown") String userAgent
) { }
```

### Cookie @CookieValue

```java
@GetMapping("/profile")
public Profile getProfile(@CookieValue("JSESSIONID") String sessionId) { }
```

### 表单参数 @RequestParam (multipart)

```java
@PostMapping("/upload")
public String upload(
    @RequestParam("file") MultipartFile file,
    @RequestParam("description") String description
) { }
```

**参数格式：**
```
Content-Type: multipart/form-data
参数: file (MultipartFile), description (String)
```

---

## 路径解析规则

### Ant 风格路径匹配

```java
@GetMapping("/files/*")
public String file() { }  // 匹配 /files/abc

@GetMapping("/files/**")
public String files() { }  // 匹配 /files/abc, /files/abc/def

@GetMapping("/{path:[a-z]+}")
public String path() { }  // 正则表达式匹配
```

### 路径变量编码

```java
@GetMapping("/files/{filename:.*}")
public Resource getFile(@PathVariable String filename) { }
```

---

## 常见模式

### RESTful CRUD

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping
    public List<User> list() { }

    @GetMapping("/{id}")
    public User get(@PathVariable Long id) { }

    @PostMapping
    public User create(@RequestBody UserDto dto) { }

    @PutMapping("/{id}")
    public User update(@PathVariable Long id, @RequestBody UserDto dto) { }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { }
}
```

### 分页查询

```java
@GetMapping("/users")
public Page<User> list(
    @RequestParam(defaultValue = "0") int page,
    @RequestParam(defaultValue = "10") int size,
    @RequestParam(defaultValue = "id,desc") String[] sort
) { }
```

### 多条件查询

```java
@GetMapping("/search")
public List<User> search(
    @RequestParam(required = false) String name,
    @RequestParam(required = false) String email,
    @RequestParam(required = false) Integer minAge,
    @RequestParam(required = false) Integer maxAge
) { }
```

---

## 静态资源

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }
}
```

**提取要点：**
- 静态资源路径也需要记录
- 存在目录遍历漏洞，需记录该路径

---

## 拦截器和过滤器

```java
@Component
public class AuthInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, ...) {
        String path = request.getRequestURI();
        // 检查路径是否需要认证
    }
}
```

**提取要点：**
- 拦截器限制路径访问，需记录拦截规则
- 记录受限路径列表

---

## Spring Security 路径配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        );
    }
}
```

**提取要点：**
- 记录公开访问的路径
- 记录需要特定角色的路径

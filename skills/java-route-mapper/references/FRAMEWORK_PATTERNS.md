# 通用框架识别模式

## 目录

- [识别策略](#识别策略)
- [配置文件特征](#配置文件特征)
- [注解特征](#注解特征)
- [包结构特征](#包结构特征)
- [依赖特征](#依赖特征)
- [自定义框架分析](#自定义框架分析)

---

## 识别策略

### 优先级顺序

1. **配置文件** - 最可靠的识别方式
2. **注解特征** - 快速识别框架类型
3. **依赖声明** - Maven/Gradle 依赖
4. **包结构** - 目录组织方式

### 多框架共存

```bash
# 检查是否同时存在多个框架配置
find . -name "web.xml" -o -name "struts.xml" -o -name "applicationContext.xml"
find . -type f -name "*.java" | xargs grep -l "@Controller\|@Path\|@WebServlet"
```

---

## 配置文件特征

### Spring 家族

| 文件 | 框架 | 特征内容 |
|------|------|---------|
| `application.properties` | Spring Boot | `server.port=`, `server.context-path=` |
| `application.yml` | Spring Boot | YAML 格式配置 |
| `web.xml` | Spring MVC | `ContextLoaderListener`, `DispatcherServlet` |
| `[servlet]-servlet.xml` | Spring MVC | `<mvc:annotation-driven/>` |
| `applicationContext.xml` | Spring | Bean 定义 |

### JAX-RS

| 文件 | 框架 | 特征内容 |
|------|------|---------|
| `web.xml` | Jersey | `ServletContainer`, `jersey.config.server.provider.packages` |
| `web.xml` | RESTEasy | `resteasy.scan`, `resteasy.servlet.mapping.prefix` |
| `web.xml` | CXF | `CXFServlet` |

### 其他框架

| 文件 | 框架 | 特征内容 |
|------|------|---------|
| `struts.xml` | Struts 2 | `<package>`, `<action>`, `struts-default` |
| `faces-config.xml` | JSF | `<faces-config>`, `<navigation-rule>` |
| `web.xml` | Servlet | `<servlet>`, `<servlet-mapping>` |

---

## 注解特征

### Spring MVC

```java
@Controller
@RestController
@RequestMapping
@GetMapping / @PostMapping / @PutMapping / @DeleteMapping
@RequestParam / @PathVariable / @RequestBody
@Autowired
```

### JAX-RS

```java
@Path
@GET / @POST / @PUT / @DELETE
@QueryParam / @PathParam / @FormParam
@Consumes / @Produces
```

### Servlet 3.0+

```java
@WebServlet
@WebFilter
@WebListener
```

### Struts 2

```java
Action (interface)
ActionSupport (class)
@Namespace (Struts Convention Plugin)
```

---

## 包结构特征

### Spring Boot

```
src/main/java/
├── com/example/
│   ├── Application.java          // @SpringBootApplication
│   ├── controller/               // @Controller
│   ├── service/                  // @Service
│   ├── repository/               // @Repository
│   └── model/                    // Entity/DTO
```

### 传统分层架构

```
src/main/java/
├── com/example/
│   ├── action/                   // Struts Action
│   ├── servlet/                  // Servlet
│   ├── resource/                 // JAX-RS Resource
│   ├── controller/               // Spring Controller
│   ├── service/
│   └── dao/
```

---

## 依赖特征

### Maven pom.xml

```xml
<!-- Spring Boot -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
</parent>

<!-- Spring MVC -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
</dependency>

<!-- JAX-RS: Jersey -->
<dependency>
    <groupId>org.glassfish.jersey.containers</groupId>
    <artifactId>jersey-container-servlet</artifactId>
</dependency>

<!-- JAX-RS: RESTEasy -->
<dependency>
    <groupId>org.jboss.resteasy</groupId>
    <artifactId>resteasy-jaxrs</artifactId>
</dependency>

<!-- Struts 2 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
</dependency>
```

### Gradle build.gradle

```groovy
// Spring Boot
implementation 'org.springframework.boot:spring-boot-starter-web'

// Spring MVC
implementation 'org.springframework:spring-webmvc'

// JAX-RS
implementation 'org.glassfish.jersey.containers:jersey-container-servlet'

// Struts 2
implementation 'org.apache.struts:struts2-core'
```

---

## 自定义框架分析

### 自定义 MVC 框架特征

```java
// 自定义注解
@WebRoute("/users")
@Controller
public class UserController { }

// 自定义分发器
public class DispatcherServlet extends HttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
        // 分析路由分发逻辑
    }
}
```

### 识别策略

1. **找到入口点** - 通常是 Filter 或 Servlet
2. **提取路由表** - 路由存储与查找规则
3. **提取参数绑定规则** - 参数名、类型、来源
4. **提取响应类型** - 响应格式与 Content-Type

### 常见模式

**反射驱动：**
```java
// 扫描特定包的类
Reflections reflections = new Reflections("com.example.controller");
Set<Class<?>> controllers = reflections.getTypesAnnotatedWith(Controller.class);
```

**配置驱动：**
```java
// 读取配置文件构建路由表
Properties routes = new Properties();
routes.load(getClass().getResourceAsStream("/routes.properties"));
```

**约定驱动：**
```java
// 类名 → 路径
// UserController → /user
// 方法名 → HTTP 方法
// list() → GET /user
```

---

## 识别脚本

```bash
#!/bin/bash
# framework_detect.sh - 快速识别 Java Web 框架

PROJECT_DIR=$1

echo "检测框架类型..."

# 检查配置文件
if [ -f "$PROJECT_DIR/pom.xml" ]; then
    echo "发现 Maven 项目"
    grep -q "spring-boot-starter" "$PROJECT_DIR/pom.xml" && echo "→ Spring Boot"
    grep -q "spring-webmvc" "$PROJECT_DIR/pom.xml" && echo "→ Spring MVC"
    grep -q "jersey" "$PROJECT_DIR/pom.xml" && echo "→ Jersey (JAX-RS)"
    grep -q "resteasy" "$PROJECT_DIR/pom.xml" && echo "→ RESTEasy (JAX-RS)"
    grep -q "struts2-core" "$PROJECT_DIR/pom.xml" && echo "→ Struts 2"
fi

# 检查注解使用
find "$PROJECT_DIR" -name "*.java" -type f | head -20 | xargs grep -l "@Controller" && echo "使用 @Controller 注解"
find "$PROJECT_DIR" -name "*.java" -type f | head -20 | xargs grep -l "@Path" && echo "使用 JAX-RS 注解"
find "$PROJECT_DIR" -name "*.java" -type f | head -20 | xargs grep -l "@WebServlet" && echo "使用 Servlet 注解"

# 检查配置文件
[ -f "$PROJECT_DIR/src/main/resources/application.yml" ] && echo "→ Spring Boot 配置"
[ -f "$PROJECT_DIR/src/main/webapp/WEB-INF/web.xml" ] && echo "→ 传统 Web 应用"
[ -f "$PROJECT_DIR/src/main/resources/struts.xml" ] && echo "→ Struts 2 配置"
```

---

## 混合框架场景

### Spring + Struts 2

```xml
<!-- web.xml -->
<filter>
    <filter-name>struts2</filter-name>
    <filter-class>org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>struts2</filter-name>
    <url-pattern>/struts/*</url-pattern>
</filter-mapping>

<servlet>
    <servlet-name>spring</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>spring</servlet-name>
    <url-pattern>/spring/*</url-pattern>
</servlet-mapping>
```

**分析要点：**
- 分别记录不同框架的路径前缀
- 注意路径冲突

---

## 未知框架处理

当无法识别框架时：

1. **记录所有 HTTP 入口点**（Servlet、Filter）
2. **分析请求分发逻辑**
3. **提取路由表构建规则**
4. **手动构建路由和参数映射**

**最小可行输出：**
- URL 模式
- HTTP 方法
- 已知参数名

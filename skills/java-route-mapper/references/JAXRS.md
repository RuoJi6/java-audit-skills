# JAX-RS 路由分析

## 目录

- [项目识别](#项目识别)
- [路由注解](#路由注解)
- [参数注解](#参数注解)
- [常见实现](#常见实现)
- [常见模式](#常见模式)

---

## 项目识别

**主流实现：**
- **Jersey**: `org.glassfish.jersey` 包
- **RESTEasy**: `org.jboss.resteasy` 包
- **CXF**: `org.apache.cxf` 包

**特征注解：**
```java
import javax.ws.rs.*;  // JAX-RS 2.x
import jakarta.ws.rs.*; // JAX-RS 3.x (Jakarta EE)
```

**特征类：**
```java
@Path("/api")
@ApplicationPath("/api")
```

---

## 路由注解

### @Path - 路径定义

```java
@Path("/users")
public class UserResource {

    @GET
    @Path("/{id}")
    public User getUser(@PathParam("id") Long id) { }
}
```

**路径组合：**
```
完整路径 = @ApplicationPath + 类级别 @Path + 方法级别 @Path
例：/api + /users + /{id} = /api/users/{id}
```

### HTTP 方法注解

| 注解 | HTTP 方法 | 说明 |
|------|-----------|------|
| `@GET` | GET | 查询资源 |
| `@POST` | POST | 创建资源 |
| `@PUT` | PUT | 更新资源 |
| `@DELETE` | DELETE | 删除资源 |
| `@PATCH` | PATCH | 部分更新 |
| `@HEAD` | HEAD | 获取头信息 |
| `@OPTIONS` | OPTIONS | 获取支持的方法 |

### @Path 模板

```java
@Path("/users/{id}")
public User getUser(@PathParam("id") String id) { }

@Path("/users/{id: \\d+}")  // 正则限制：仅数字
public User getUser(@PathParam("id") Long id) { }

@Path("/files/{path:.*}")   // 捕获剩余路径
public Resource getFile(@PathParam("path") String path) { }
```

---

## 参数注解

### @PathParam - 路径变量

```java
@GET
@Path("/users/{id}")
public User getUser(@PathParam("id") Long id) { }

@GET
@Path("/users/{userId}/posts/{postId}")
public Post getPost(
    @PathParam("userId") Long userId,
    @PathParam("postId") Long postId
) { }
```

### @QueryParam - 查询参数

```java
@GET
@Path("/search")
public List<User> search(
    @QueryParam("q") String query,
    @QueryParam("page") @DefaultValue("0") int page,
    @QueryParam("size") @DefaultValue("10") int size
) { }

// 多值参数
@GET
@Path("/filter")
public List<User> filter(@QueryParam("tags") List<String> tags) { }
```

### @FormParam - 表单参数

```java
@POST
@Path("/login")
public Response login(
    @FormParam("username") String username,
    @FormParam("password") String password
) { }
```

**参数格式：**
```
Content-Type: application/x-www-form-urlencoded
参数: username (String), password (String)
```

### @HeaderParam - 请求头

```java
@GET
@Path("/data")
public Response getData(@HeaderParam("Authorization") String auth) { }

@GET
@Path("/data")
public Response getData(
    @HeaderParam("User-Agent") @DefaultValue("Unknown") String userAgent
) { }
```

### @CookieParam - Cookie

```java
@GET
@Path("/profile")
public Profile getProfile(@CookieParam("JSESSIONID") String sessionId) { }
```

### @MatrixParam - 矩阵参数

```java
@GET
@Path("/users")
public User getUser(@MatrixParam("id") Long id) { }
```

**矩阵参数格式：** `/users;id=123;name=test`

### @BeanParam - 参数封装

```java
public class UserParams {
    @FormParam("username")
    private String username;

    @FormParam("password")
    private String password;

    @HeaderParam("X-Client-ID")
    private String clientId;
}

@POST
@Path("/login")
public Response login(@BeanParam UserParams params) { }
```

**提取要点：**
- 需要进一步分析 Bean 类的字段
- 可以混合多种参数来源

### 请求体 @Consumes

```java
@POST
@Path("/users")
@Consumes(MediaType.APPLICATION_JSON)
public User create(UserDto userDto) { }

// 方法参数自动绑定
@POST
@Path("/users")
public User create(@RequestBody UserDto userDto) { }
```

---

## 常见实现

### Jersey 配置

```java
@ApplicationPath("/api")
public class ApplicationConfig extends ResourceConfig {
    public ApplicationConfig() {
        packages("com.example.resource");
        register(JacksonFeature.class);
    }
}
```

**web.xml 配置：**
```xml
<servlet>
    <servlet-name>Jersey</servlet-name>
    <servlet-class>org.glassfish.jersey.servlet.ServletContainer</servlet-class>
    <init-param>
        <param-name>jersey.config.server.provider.packages</param-name>
        <param-value>com.example.resource</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
</servlet>
<servlet-mapping>
    <servlet-name>Jersey</servlet-name>
    <url-pattern>/api/*</url-pattern>
</servlet-mapping>
```

### RESTEasy 配置

```xml
<!-- web.xml -->
<context-param>
    <param-name>resteasy.scan</param-name>
    <param-value>true</param-value>
</context-param>
<context-param>
    <param-name>resteasy.servlet.mapping.prefix</param-name>
    <param-value>/api</param-value>
</context-param>
```

### CXF 配置

```xml
<!-- web.xml -->
<servlet>
    <servlet-name>CXFServlet</servlet-name>
    <servlet-class>org.apache.cxf.jaxrs.servlet.CXFServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>CXFServlet</servlet-name>
    <url-pattern>/api/*</url-pattern>
</servlet-mapping>
```

---

## 常见模式

### RESTful CRUD

```java
@Path("/users")
public class UserResource {

    @GET
    public List<User> list() { }

    @GET
    @Path("/{id}")
    public User get(@PathParam("id") Long id) { }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public User create(UserDto dto) { }

    @PUT
    @Path("/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public User update(@PathParam("id") Long id, UserDto dto) { }

    @DELETE
    @Path("/{id}")
    public void delete(@PathParam("id") Long id) { }
}
```

### 子资源

```java
@Path("/users/{userId}")
public class UserResource {

    @Path("/posts")
    public PostResource getPosts(@PathParam("userId") Long userId) {
        return new PostResource(userId);
    }
}

public class PostResource {
    private Long userId;

    @GET
    public List<Post> list() { }

    @POST
    public Post create(PostDto dto) { }
}
```

**子资源路径：** `/users/{userId}/posts`

### 内容协商

```java
@GET
@Path("/data")
@Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
public Response getData(@HeaderParam("Accept") String accept) {
    // 根据 Accept 头返回不同格式
}
```

---

## 限制与边界

### @Consumes / @Produces

```java
@POST
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public Response create(UserDto dto) { }
```

**提取要点：**
- `@Consumes` 确定请求 Content-Type
- `@Produces` 确定响应 Content-Type

---

## 异常处理

```java
@Provider
public class ExceptionMapper implements ExceptionMapper<Exception> {
    @Override
    public Response toResponse(Exception e) {
        return Response.status(500).entity(e.getMessage()).build();
    }
}
```

---

## 拦截器和过滤器

### ContainerRequestFilter

```java
@Provider
@PreMatching
public class AuthFilter implements ContainerRequestFilter {
    @Override
    public void filter(ContainerRequestContext ctx) {
        String path = ctx.getUriInfo().getPath();
        // 检查路径权限
    }
}
```

**提取要点：**
- 记录路径拦截规则
- 影响请求可达性，需记录拦截规则

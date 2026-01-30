---
name: java-route-mapper
description: Java Web 源码路由与参数映射分析工具。从源码中提取**所有** HTTP 路由和参数，生成完整 Burp Suite 请求模板，并自动保存为 MD 文档。适用于：(1) 无 API 文档的项目完整接口梳理，(2) 生成所有接口的 Burp 测试请求，(3) 源码端点完整分析。支持 Spring MVC、Servlet、JAX-RS、Struts 2、CXF Web Services 等框架。**必须输出所有接口，不省略任何内容，包括 Web Service 的完整 SOAP 方法**。
---

# Java Source Route & Parameter Mapper

分析 Java Web 项目源码，提取完整的 HTTP 路由与请求参数结构，生成 Burp Suite Repeater 请求模板。

## ⚠️ 核心要求：完整输出

**此技能必须输出所有发现的接口，不允许省略。**

- ✅ 每个接口都要有完整的参数分析
- ✅ 每个接口都要有 Burp Suite 请求模板（必须放在 md 代码块中）
- ✅ 输出接口总数和清单供核对
- ❌ 禁止使用"..."、"等"、"其他"省略
- ❌ 禁止只输出"关键接口"或"重要接口"
- ❌ 禁止因为数量大而省略

---

## ⚠️ CRITICAL 规则汇总（强制执行）

**以下规则为强制性要求，违反任何一条都会导致输出不合格。**

---

### CRITICAL 1: 通配符/动态路由强制展开

#### 1.1 Struts2 通配符路由

**适用场景：** struts.xml 中存在以下通配符配置时必须强制展开
- `name="*_*"` - 双通配符
- `name="user_*"` - 单通配符
- `name="*"` - 全匹配

**强制执行步骤（不可跳过）：**

1. **识别通配符配置**
   ```xml
   <action name="*_*" class="{1}Action" method="{2}">
   ```

2. **反编译该 namespace 下所有 Action 类**
   ```bash
   mcp__java-decompile-mcp__decompile_directory(
       directory_path="{WEB-INF/classes/对应包路径}",
       recursive=true,
       save_to_file=true
   )
   ```

3. **提取每个 Action 类的业务方法**
   - 所有 public 方法
   - 排除：getter/setter（get*/set*/is*）
   - 排除：继承自 ActionSupport 的方法（execute 除外）
   - 保留：所有其他 public 方法

4. **生成路由映射表并为每个路由生成独立请求模板**

#### 1.2 Spring MVC 路径变量

**适用场景：** `@RequestMapping` 中存在路径变量时
- `@GetMapping("/user/{id}")` - 路径变量
- `@RequestMapping("/api/{version}/**")` - 通配符路径

**强制执行步骤：**

1. **识别路径变量模式**
   ```java
   @GetMapping("/user/{id}/orders/{orderId}")
   ```

2. **为每个路径变量生成占位符说明**
   ```markdown
   Path 变量:
   - {id}: 用户ID (类型: Long)
   - {orderId}: 订单ID (类型: String)
   ```

3. **在 Burp 模板中使用 `{{变量名}}` 格式**

#### 1.3 JAX-RS 路径参数

**适用场景：** `@Path` 注解中存在路径参数时
- `@Path("/users/{userId}")` - 路径参数
- `@Path("{resource}/{id}")` - 多级路径参数

**强制执行步骤：**

1. **识别 `@PathParam` 注解**
   ```java
   @GET
   @Path("/{userId}/profile")
   public User getProfile(@PathParam("userId") Long userId)
   ```

2. **提取参数类型并生成完整模板**

#### 1.4 Servlet URL Pattern 通配符

**适用场景：** web.xml 或 `@WebServlet` 中存在通配符时
- `<url-pattern>/api/*</url-pattern>` - 路径通配符
- `<url-pattern>*.do</url-pattern>` - 扩展名通配符

**强制执行步骤：**

1. **分析 Servlet 类的 doGet/doPost 方法**
2. **提取 `request.getPathInfo()` 或 `request.getServletPath()` 的使用方式**
3. **根据代码逻辑推断可能的子路径**

---

### CRITICAL 2: Web Service 方法完整输出规则

#### 2.1 配置文件优先原则

**Web Service 的 URL 路径必须从配置文件中读取，绝对不能根据类名或 endpoint id 推断！**

**解析优先级（按顺序执行）：**

1. **读取配置文件** - applicationContext.xml 或其他 Spring 配置
2. **提取 address 属性** - 这是 Web Service 路径的唯一真实来源
3. **验证 Servlet 映射** - 从 web.xml 获取 /ws/* 或 /services/*
4. **组装完整 URL** - 上下文路径 + Servlet映射 + address
5. **反编译实现类** - 仅用于提取方法签名，不用于推断路径

**URL 组成公式：**
```
完整URL = 上下文路径 + web.xml中的Servlet映射 + address属性值

示例: /myapp + /services/ + /UserApi = /myapp/services/UserApi
```

**错误示例（必须避免）：**
- ❌ 根据类名推断: `UserServiceImpl` → `/UserService`
- ❌ 根据 id 推断: `userWebService` → `/userWebService`
- ✅ 读取配置: `address="/UserApi"` → `/myapp/services/UserApi`

#### 2.2 CXF/JAX-WS 服务

**强制执行步骤：**

1. **从配置文件获取所有 endpoint**
   ```xml
   <jaxws:endpoint id="userService"
                   implementor="#userServiceImpl"
                   address="/UserService"/>
   ```

2. **反编译每个 Service 实现类**

3. **提取所有 public 方法** - 方法名、参数列表、返回类型

4. **为每个方法生成独立 SOAP 请求模板**

5. **记录配置来源** - 配置文件路径、行号、address 属性值、implementor 类名

#### 2.3 Axis/Axis2 服务

**强制执行步骤：**

1. **读取 server-config.wsdd 或 services.xml**
   ```xml
   <service name="UserService" provider="java:RPC">
     <parameter name="className" value="com.example.UserService"/>
   </service>
   ```

2. **提取服务名和实现类**

3. **反编译实现类获取方法列表**

4. **URL 组成：** `/axis/services/{serviceName}`

#### 2.4 executeInterface 类型服务特殊处理

对于使用 interfaceId 参数路由的通用执行接口：

1. **反编译实现类，查找所有 interfaceId 定义**
2. **为每个 interfaceId 生成独立请求模板**

---

### CRITICAL 3: 禁止的输出格式

**以下输出格式绝对禁止使用：**

| 禁止模式 | 错误示例 | 正确做法 |
|:---------|:---------|:---------|
| 使用"等"省略 | `LoginAction, UserAction等` | 列出全部 Action |
| 使用"..."省略 | `method1, method2, ...` | 列出全部方法 |
| 使用"其他"省略 | `以及其他20个方法` | 列出全部20个方法 |
| 使用"更多"省略 | `更多接口请查看源码` | 直接列出所有接口 |
| 使用占位符 | `{action}_{method}.action` | 展开为实际 URL |
| 使用范围表示 | `001 ~ 050` | 逐个列出 001, 002, ..., 050 |
| 描述替代列表 | `方法列表: 用户管理相关` | 列出具体方法名 |
| 只给 WSDL 地址 | `请通过 WSDL 查看可用方法` | 列出所有 SOAP 方法 |
| 只列类名不列方法 | `UserAction 支持多个方法` | 列出每个方法的完整模板 |

---

### CRITICAL 4: 各框架必须的输出格式

#### 4.1 Struts2 路由

```markdown
=== [1] login_login.action ===
URL: `/admin/login_login.action`
方法: LoginAction.login()
参数: loginName (String), password (String)

Burp Suite 请求模板:
\```http
POST /admin/login_login.action HTTP/1.1
Host: {{host}}
Content-Type: application/x-www-form-urlencoded

loginName={{username}}&password={{password}}
\```
```

#### 4.2 Spring MVC 路由

```markdown
=== [1] GET /api/users/{id} ===
位置: UserController.getUser (UserController.java:45)
HTTP 方法: GET
URL 路径: /api/users/{id}

参数结构:
  Path: {id} (Long) - 用户ID
  Header: Authorization - Bearer Token

Burp Suite 请求模板:
\```http
GET /api/users/{{userId}} HTTP/1.1
Host: {{host}}
Authorization: Bearer {{token}}
\```
```

#### 4.3 JAX-RS 路由

```markdown
=== [1] GET /rest/users/{userId} ===
位置: UserResource.getUser (UserResource.java:32)
HTTP 方法: GET
URL 路径: /rest/users/{userId}

参数结构:
  Path: {userId} (Long)
  Query: includeOrders (boolean, 可选)

Burp Suite 请求模板:
\```http
GET /rest/users/{{userId}}?includeOrders=true HTTP/1.1
Host: {{host}}
Accept: application/json
\```
```

#### 4.4 Servlet 路由

```markdown
=== [1] POST /api/upload ===
位置: UploadServlet.doPost (UploadServlet.java:28)
HTTP 方法: POST
URL 路径: /api/upload

参数结构:
  Body: multipart/form-data
    - file (File) - 上传文件
    - description (String) - 文件描述

Burp Suite 请求模板:
\```http
POST /api/upload HTTP/1.1
Host: {{host}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

{{fileContent}}
------WebKitFormBoundary
Content-Disposition: form-data; name="description"

{{description}}
------WebKitFormBoundary--
\```
```

#### 4.5 Web Service (SOAP) 方法

```markdown
### UserService (共 5 个方法)

- **配置文件**: applicationContext.xml:42
- **address 属性**: /UserApi
- **完整 URL**: /myapp/services/UserApi

=== [WS-1] login ===
方法签名: login(String loginName, String password)
返回类型: String

Burp Suite 请求模板:
\```http
POST /myapp/services/UserApi HTTP/1.1
Host: {{host}}
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://webservice.example.com">
  <soapenv:Header/>
  <soapenv:Body>
    <web:login>
      <loginName>{{username}}</loginName>
      <password>{{password}}</password>
    </web:login>
  </soapenv:Body>
</soapenv:Envelope>
\```
```

---

### CRITICAL 5: 输出前强制验证

**此验证必须通过才能写入文件，验证不通过时必须返回补充内容。**

#### 5.1 数量一致性检查

| 检查项 | 计算公式 | 通过条件 |
|:-------|:---------|:---------|
| Struts2 路由 | 实际模板数 ÷ Action类数 | ≥ 3 |
| Spring MVC 接口 | 实际模板数 ÷ Controller类数 | ≥ 2 |
| JAX-RS 接口 | 实际模板数 ÷ Resource类数 | ≥ 2 |
| Servlet 接口 | 实际模板数 ÷ Servlet类数 | ≥ 1 |
| Web Service 方法 | 实际模板数 ÷ 反编译获得的方法数 | = 100% |

#### 5.2 省略词检测

扫描输出内容，检测到任何省略标志时必须替换为完整内容。

#### 5.3 文件完整性检查

- [ ] 主索引中每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的请求模板（不是摘要）
- [ ] Web Service 索引中的每个服务都有完整的方法列表
- [ ] 没有"详见xxx"但 xxx 文件不存在的情况

#### 5.4 验证不通过时的处理流程

1. 停止当前输出
2. 识别缺失的内容类型
3. 执行反编译获取完整信息
4. 补充缺失的请求模板
5. 重新执行验证
6. 验证通过后才写入文件

---

### CRITICAL 6: 完成性检查清单

**在标记任务完成前，必须执行以下检查：**

- [ ] 主索引文件已生成
- [ ] README说明文档已生成
- [ ] 主索引中列出的每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的路由信息（或明确说明无路由）
- [ ] 所有文件链接可访问
- [ ] 已通过验证命令检查

**如果发现缺失文件，必须：**
1. 立即补充缺失的文件
2. 更新主索引（如果链接不匹配）
3. 重新执行完整性检查

---

## 工作流程

### 1. 项目分析初始化

```
输入: 项目源码路径
       可选: 项目上下文路径、已知框架信息
```

**初始化步骤：**

1. 识别项目类型和框架（通过配置文件和目录结构）- **支持多框架混合项目**
2. 确定路由加载方式（注解驱动 / XML 配置 / 混合）
3. 提取上下文路径和基础 URL

### 2. 框架识别与任务制定

**多框架支持：** 一个项目可能同时使用多种 Web 框架，需要分别识别并制定分析任务。

| 框架 | 识别特征 | 参考资料 |
|------|---------|---------|
| Spring MVC | `@Controller`、`@RequestMapping` | [SPRING_MVC.md](references/SPRING_MVC.md) |
| Spring Boot | `application.properties/yml`、Spring Boot starter | [SPRING_MVC.md](references/SPRING_MVC.md) |
| Servlet | `web.xml`、`@WebServlet` | [SERVLET.md](references/SERVLET.md) |
| JAX-RS | `@Path`、`@GET`、`@POST` | [JAXRS.md](references/JAXRS.md) |
| Struts 2 | `struts.xml` | [STRUTS.md](references/STRUTS.md) |
| CXF Web Services | `/ws/*`、`@WebService`、`applicationContext.xml` | [WEBSERVICE.md](references/WEBSERVICE.md) |

**任务制定规则：**
- 检测到的每个框架都生成独立的分析任务
- 任务按执行顺序排列（框架初始化 → 路由扫描 → 参数解析）
- 混合配置（注解+XML）需要同步分析两种方式

### 3. 路由枚举

扫描项目源码，提取所有对外可访问的 HTTP 路由。

**扫描范围：**
- `@Controller` / `@RestController` 类
- `@RequestMapping` 及其变体注解
- Servlet 配置（web.xml、@WebServlet）
- JAX-RS 注解（@Path、@GET、@POST 等）
- Struts2 Action 配置
- Web Service 端点配置

**输出信息：**
- HTTP 方法
- URL 路径（完整路径）
- 对应的控制器类和方法

### 4. 参数结构解析

对每个路由解析其参数结构。

**参数来源：**
- **Path 变量**：`@PathVariable`、`@PathParam`
- **Query 参数**：`@RequestParam`、`@QueryParam`
- **Body 参数**：`@RequestBody`、请求对象、Form 表单
- **Header 参数**：`@RequestHeader`、`@HeaderParam`
- **Cookie 参数**：`@CookieValue`、`@CookieParam`

**参数类型分析：**
- 基本类型（String、int、long 等）
- 对象类型（POJO）
- 集合类型（List、Map、Set）
- 枚举类型

### 5. 反编译支持（必要时）

当接口定义或方法签名位于已编译的 .class 文件或第三方 JAR 中时：

1. 使用 MCP Java Decompiler 工具反编译目标文件
2. 提取方法签名和参数类型定义
3. 还原参数结构

**反编译策略：**
- 仅反编译包含目标接口或参数定义的类
- 优先使用已存在的源码
- 记录反编译来源以便追溯

### 6. 生成输出

**重要：必须输出所有发现的接口，不要省略或使用摘要。**

为**每个**接口生成完整的 HTTP 请求模板，包含：
- 所有路由（即使数量很大）
- 每个路由的完整参数结构
- 每个路由的 Burp Suite 请求模板（必须放在 md 代码块中）

**禁止的操作：**
- ❌ 不要使用"..."省略接口
- ❌ 不要使用"等"、"其他"来省略
- ❌ 不要只输出"关键接口"或"重要接口"
- ❌ 不要因为数量大而使用表格摘要
- ❌ 不要说"由于数量庞大，只列出部分"
- ❌ 不要只输出 WSDL 地址而不生成具体的 SOAP 请求
- ❌ 不要只列出 Action 类名而不生成具体的请求模板

**强制要求：**
- ✅ 每个 Struts2 action 路由都要有对应的请求模板
- ✅ 每个 REST 接口都要有完整的请求模板
- ✅ 每个 Web Service 方法都要有独立的 SOAP 请求模板
- ✅ 对于 executeInterface 类型的服务，必须为每个 methodId 生成独立请求模板

**要求的输出格式（每条）：**

````markdown
=== [序号] 接口标识 ===

描述: 简要描述（如有注解描述）
位置: ClassName.methodName (源文件:行号)

HTTP 方法: GET/POST/PUT/DELETE 等
URL 路径: /完整/路径/结构

参数结构:
  Path: {pathVar1}, {pathVar2}
  Query: param1, param2 (类型: String)
  Body: ContentType (类型定义)
  Header: X-Custom-Header
  Cookie: sessionId

Burp Suite 请求模板(必须在代码块中):
```http
HTTP_METHOD /path/structure HTTP/1.1
Host: {{host}}
Content-Type: application/json
[其他必需 Header]

[请求 Body]
```
````

### 7. 文件拆分策略

**输出必须为 MD 文件格式，按层级目录拆分（一个层级一个 MD 文件）。**

当接口数量较大时，必须拆分输出文件以确保每个接口都有完整的模板。

#### 7.1 拆分触发条件

满足以下任一条件时触发拆分：
- 单个模块接口数量 > 50 个
- 单个 namespace 接口数量 > 20 个
- 单个 Web Service 方法数量 > 10 个
- 预估输出文件大小 > 100KB

#### 7.2 文件名策略

**文件名策略是动态生成的，不限于固定的模块名。**

| 文件类型 | 命名格式 | 示例 |
|---------|---------|------|
| 主索引 | `{项目名}_route_audit/{项目名}_route_audit_{时间戳}.md` | `myapp_route_audit/myapp_route_audit_20260121.md` |
| 模块详情 | `{项目名}_route_audit/{项目名}_module_{模块名}_{时间戳}.md` | `myapp_route_audit/myapp_module_admin_20260121.md` |
| Web Service | `{项目名}_route_audit/{项目名}_ws_{服务名}_{时间戳}.md` | `myapp_route_audit/myapp_ws_userservice_20260121.md` |
| Namespace 拆分 | `{项目名}_route_audit/{项目名}_{namespace}_{时间戳}.md` | `myapp_route_audit/myapp_admin_user_20260121.md` |
| README | `{项目名}_route_audit/{项目名}_README_{时间戳}.md` | `myapp_route_audit/myapp_README_20260121.md` |

**动态模块名示例：**

| 实际模块/namespace | 生成的文件名 |
|------------------|:-------------|
| `admin` | `myapp_module_admin_20260121.md` |
| `user` | `myapp_module_user_20260121.md` |
| `config` | `myapp_module_config_20260121.md` |
| `report` | `myapp_module_report_20260121.md` |
| `upload` | `myapp_module_upload_20260121.md` |
| `api` | `myapp_module_api_20260121.md` |
| `common` | `myapp_module_common_20260121.md` |
| `product` | `myapp_module_product_20260121.md` |
| `order` | `myapp_module_order_20260121.md` |
| `/` (root namespace) | `myapp_module_root_20260121.md` |

**模块识别来源：**

1. **目录结构** - webapps 下的子目录名
2. **上下文路径** - Context Path 配置
3. **Struts2 namespace** - struts.xml 中的 package namespace
4. **Spring @RequestMapping** - 类级别的路径前缀
5. **Web Service 路径** - 如 `/services/`, `/ws/`

#### 7.3 拆分策略

**策略 A: 按模块拆分（推荐）**

为每个模块生成独立的 MD 文件：

```
{project_name}_route_audit/
├── {project_name}_route_audit_{timestamp}.md         # 主索引文件
├── {project_name}_module_admin_{timestamp}.md        # admin 模块详情
├── {project_name}_module_itc_{timestamp}.md          # itc 模块详情
├── {project_name}_module_xxx_{timestamp}.md          # 其他模块（动态生成）
└── {project_name}_README_{timestamp}.md              # 说明文档
```

**主索引文件内容：**
```markdown
# {项目名称} - 路由审计报告（索引）

生成时间: {timestamp}
分析路径: {project_path}

## 项目概览
[项目基本信息]

## 模块索引

| 模块 | 文件 | 接口数量 | 框架 |
|:-----|:-------|:-----|
| admin | [module_admin_20260121.md](module_admin_20260121.md) | 218 | Struts2+Spring+CXF |
| itc | [module_itc_20260121.md](module_itc_20260121.md) | 85 | Struts2+CXF |
| ... | ... | ... | ... |

## 统计摘要
[总体统计]
```

**模块详情文件内容：**
````markdown
# {项目名称} - {模块名} 模块详情

生成时间: {timestamp}
模块路径: /{module-context-path}

## 模块概览

[模块基本信息、框架配置]

## 接口详细列表

### Struts2 路由

=== [1] user_login.action ===
位置: AuthAction.login (路径:行号)
HTTP 方法: POST
URL 路径: /admin/user_login.action

Burp Suite 请求模板(必须在代码块中):
```http
[完整请求模板]
```

=== [2] sso_checkLogin.action ===
[完整请求模板]

[所有接口的完整模板...]
````

**策略 B: 按 namespace 拆分（适用于接口极多的情况）**

为每个 namespace 生成独立的 MD 文件：

```
{project_name}_route_audit_{timestamp}.md              # 主索引
{project_name}_admin_device_{timestamp}.md              # /device namespace
{project_name}_admin_channel_{timestamp}.md            # /channel namespace
{project_name}_admin admin_login_{timestamp}.md              # / namespace (登录相关)
{project_name}_rest_{timestamp}.md                    # REST 接口
{project_name}_webservices_{timestamp}.md              # Web Service
```

#### 7.4 拆分实现规则

1. **先分析，再拆分**
   - 完成路由分析后，统计统计各模块/namespace 的接口数量
   - 根据数量决定拆分策略

2. **生成主索引文件**
   - 包含项目概览、模块索引、统计摘要
   - 指向各个详情文件的链接

3. **并行生成详情文件**
   - 每个模块/namespace:独立写入文件
   - 每个文件包含该部分所有接口的完整模板

4. **保证可追溯性**
   - 主索引包含各详情文件的完整路径
   - 详情文件顶部注明所属模块和生成时间

#### 7.5 Web Service 方法拆分

对于 `execute` 类型或类似动态调用的 Web Service：

**错误做法：**
```markdown
#### UserService
支持的方法ID: user_001_001, user_001_002, ... (共40个)
```

**正确做法 - 拆分为独立文件：**

主文件：
```markdown
#### UserService (服务路径: /services/UserService)
详细方法列表见: [myapp_webservice_user_20260121.md](myapp_webservice_user_20260121.md)
```

详情文件 `myapp_webservice_user_20260121.md`：
````markdown
# UserService 方法详情

=== [1] user.create ===
方法ID: user_001_001
描述: 创建用户
参数: {"username": "...", "email": "...", "role": "..."}

Burp Suite 请求模板(必须在代码块中):
```http
POST /admin/services/UserService HTTP/1.1
Host: {{host}}
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://webservice.example.com">
  <soapenv:Header/>
  <soapenv:Body>
    <web:executeInterface>
      <interfaceId>user_001_001</interfaceId>
      <jsonParam>{"username":"{{username}}","email":"{{email}}","role":"{{role}}"}</jsonParam>
    </web:executeInterface>
  </soapenv:Body>
</soapenv:Envelope>
```

=== [2] user.update ===
[完整请求模板]

[所有40个方法都有完整模板...]
````

### 8. 输出文件结构

**完整输出结构：**

```
=== 项目概览 ===
[项目基本信息]

=== 模块1: XXX ===
[该模块下所有接口的完整列表，每个接口都有详细分析]

=== 模块2: XXX ===
[该模块下所有接口的完整列表，每个接口都有详细分析]

...

=== 完整接口清单 ===
[所有接口的索引列表，确保没有遗漏]
```

**自动保存为 MD 文档：**

完成分析后，**必须**将完整报告保存为 Markdown 文件：

```bash
# 主索引文件（始终生成）
{project_name}_route_audit_{timestamp}.md

# 模块详情文件（根据拆分策略生成）
{project_name}_module_admin_{timestamp}.md
{project_name}_module_itc_{timestamp}.md
{project_name}_admin_webservice_{timestamp}.md
...
```

**保存步骤：**
1. 完成所有路由分析
2. 统计各模块/namespace 的接口数量
3. 根据拆分触发条件决定拆分策略
4. 生成主索引文件
5. 并行生成各模块/namespace 的详情文件
6. **【CRITICAL】执行完整性检查（见下方检查清单）**
7. 在输出中告知用户所有文件保存位置
8. 确保每个文件都有完整的接口模板

---

## 大型项目分批处理策略

### 触发条件

当满足以下任一条件时，启用分批处理：
- 预估接口总数 > 100
- 单个 namespace 接口数 > 30
- 单个 Web Service 方法数 > 20

### 分批处理步骤

**步骤 1：按 namespace/模块分组**

```
admin 模块:
  - / namespace: 15 个路由
  - /device namespace: 45 个路由
  - /channel namespace: 30 个路由
  - ...
```

**步骤 2：逐个 namespace 处理**

```
处理 /device namespace:
  1. 反编译该 namespace 下所有 Action
  2. 提取所有方法
  3. 生成所有请求模板
  4. 验证完整性
  5. 写入文件
  6. 确认完成后，进入下一个 namespace
```

**步骤 3：增量写入**

- 每完成 10 个接口立即写入文件
- 不要等待全部分析完成再输出
- 避免因上下文过长导致遗漏

**步骤 4：进度检查点**

每个 namespace 完成后：
```markdown
✅ /device namespace 完成
   - Action 类: 8 个
   - 生成请求模板: 45 个
   - 验证: 45 ÷ 8 = 5.6 ≥ 3 ✓

⏳ /channel namespace 处理中...
```

### 文件命名规则

对于大型项目，按 namespace 拆分文件：

```
{project}_route_audit_{date}.md              # 主索引
{project}_module_{module}_{date}.md          # 模块概览
{project}_{module}_{namespace}_{date}.md     # namespace 详情

示例（假设项目名为 myapp）：
myapp_route_audit_20260129.md
myapp_module_admin_20260129.md
myapp_admin_device_20260129.md
myapp_admin_channel_20260129.md
myapp_admin_api_20260129.md
```

---

## 自动修正规则

当检测到省略内容时，自动执行修正：

### 修正规则表

| 检测到的问题 | 自动修正动作 |
|:-------------|:-------------|
| `Action1, Action2等` | 反编译获取完整 Action 列表，替换为全部 |
| `{action}_{method}.action` | 反编译获取实际方法，展开为具体 URL |
| `方法列表: 描述文字` | 反编译获取方法签名，替换为具体方法 |
| `共N个方法` 但列出 < N | 补充缺失的方法直到数量匹配 |
| `interfaceId: xxx ~ yyy` | 展开为逐个 interfaceId |

### 修正示例

**修正前**：
```markdown
### /c namespace
支持的 Action: CommonQuery, SpecialQuery, TogetherQuery 等 (共7个)
```

**修正后**：
```markdown
### /c namespace

=== [1] CommonQuery_list ===
URL: /admin/c/CommonQuery_list.action
[完整请求模板]

=== [2] CommonQuery_query ===
URL: /admin/c/CommonQuery_query.action
[完整请求模板]

=== [3] SpecialQuery_list ===
...

=== [4] TogetherQuery_list ===
...

=== [5] IntervalQuery_list ===
...

=== [6] CollisionQuery_list ===
...

=== [7] DistrustfulQuery_list ===
...

（共 7 个 Action，已全部列出，每个 Action 的所有方法均有独立模板）
```

---

## ⚠️ 完成性检查清单（CRITICAL）

**在标记任务完成前，必须执行以下检查：**

### 模块完整性检查

```markdown
□ 主索引中列出的每个模块都已生成对应的详情文件

  演示案例：
  ==========
  假设主索引文件的"模块索引"表格如下：

  | 模块 | 文件 | 接口数量 |
  |:-----|:-------|:-----|
  | admin | [myapp_module_admin.md](myapp_module_admin.md) | 218 |
  | user | [myapp_module_user.md](myapp_module_user.md) | 85 |
  | api | [myapp_module_api.md](myapp_module_api.md) | 45 |

  验证步骤：
  1. 检查 myapp_module_admin.md 是否存在
  2. 检查 myapp_module_user.md 是否存在
  3. 检查 myapp_module_api.md 是否存在
  4. 确认模块数量(3) = 实际文件数量(3)

□ Web Service 索引中的每个服务都已生成对应的详情文件

□ 没有"详见xxx"但xxx文件不存在的情况
```

### 交叉验证清单

```markdown
□ 文件数量一致性
  演示案例：主索引列出5个模块 → 应该有5个对应的 module_xxx.md 文件

□ 文件名一致性
  演示案例：主索引引用 myapp_module_admin.md → 实际文件名必须完全匹配

□ 链接有效性
  演示案例：点击主索引中的 [myapp_module_admin.md] 链接应能成功打开
```

### 内容完整性检查

```markdown
□ 每个详情文件都包含：
  - 模块概览（项目名称、上下文路径、框架）
  - 框架配置（配置文件位置）
  - 路由详细列表（每个接口的完整信息）
  - Burp Suite 请求模板

□ 对于空模块（无路由的模块）：
  演示案例：
  ==========
  某模块 upload 只有静态资源，没有业务路由

  正确做法：仍然生成 myapp_module_upload.md
  ```markdown
  # MyApp - upload 模块详情

  ## 模块概览
  该模块主要用于静态文件上传，未检测到业务路由。

  ## 检查结果
  - WEB-INF目录：不存在
  - 配置文件：无
  - 路由接口：无
```

  错误做法：跳过不生成文件
```

### 执行验证命令

**演示案例：在完成所有文件生成后，运行以下命令验证**

```bash
# 假设项目名称为 myapp，生成的文件如下：
# myapp_route_audit_20260129.md    (主索引)
# myapp_module_admin_20260129.md   (admin模块)
# myapp_module_user_20260129.md    (user模块)
# myapp_module_api_20260129.md     (api模块)

# 验证命令1: 检查生成的文件列表
ls -la myapp_module_*.md
# 预期输出：应该看到3个模块详情文件

# 验证命令2: 从主索引中提取所有引用的文件名
grep -o "myapp_module_[^)]*md" myapp_route_audit_20260129.md | sort -u

# 验证命令3: 检查引用的文件是否都存在
grep -o "myapp_module_[^)]*md" myapp_route_audit_20260129.md | while read f; do
  if [ ! -f "$f" ]; then
    echo "❌ 缺失文件: $f"
  else
    echo "✅ 存在文件: $f"
  fi
done
```

### 完成确认

**演示案例：完整的检查流程**

```markdown
假设分析了一个名为 myshop 的电商项目，包含以下模块：

步骤1: 生成主索引文件
  ✅ myshop_route_audit_20260129.md

步骤2: 检查主索引中的模块列表
  主索引显示：product, order, user, payment (4个模块)

步骤3: 验证详情文件是否存在
  ✅ myshop_module_product_20260129.md
  ✅ myshop_module_order_20260129.md
  ✅ myshop_module_user_20260129.md
  ✅ myshop_module_payment_20260129.md

步骤4: 生成README文档
  ✅ myshop_README_20260129.md

步骤5: 执行验证命令
  $ grep -o "myshop_module_[^)]*md" myshop_route_audit_20260129.md | while read f; do [ -f "$f" ] || echo "缺失: $f"; done
  (无输出表示所有文件都存在)

步骤6: 确认完成
  所有检查项通过 → 可以标记任务完成
```

**只有在以下条件全部满足时，才能标记任务为完成：**

- [ ] 主索引文件已生成
- [ ] README说明文档已生成
- [ ] 主索引中列出的每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的路由信息（或明确说明无路由）
- [ ] 所有文件链接可访问
- [ ] 已通过验证命令检查

**如果发现缺失文件，必须：**
1. 立即补充缺失的文件
2. 更新主索引（如果链接不匹配）
3. 重新执行完整性检查

**MD 主索引文件模板：**
```markdown
# {项目名称} - 路由审计报告（索引）

生成时间: {timestamp}
分析路径: {project_path}

## 项目概览

**项目名称**: {project_name}
**框架**: {frameworks}
**模块数量**: {count} 个主要模块

**框架识别**:
- {framework1}: {description}
- {framework2}: {description}

---

## 模块索引

| 模块 | 文件 | 接口数量 | 框架 |
|:-----|:-------|:-----|
| admin | [module_admin_{timestamp}.md](module_admin_{timestamp}.md) | {count} | Struts2+Spring+CXF |
| itc | [module_itc_{timestamp}.md](module_itc_{timestamp}.md) | {count} | Struts2+CXF |
| ... | ... | ... | ... |

---

## Web Service 索引

| 服务 | 文件 | 方法数量 |
|:-----|:----|:--------|
| ProductService | [webservice_product_{timestamp}.md](webservice_product_{timestamp}.md) | {count} |
| UserService | [webservice_user_{timestamp}.md](webservice_user_{timestamp}.md) | {count} |
| ... | ... | ... |

---

## 统计摘要

| 模块 | Action类数 | REST接口 | WS接口 |
|:-----|:--------|:-------|
| admin | 218 | 6 | 4+ |
| itc | 85 | 0 | 2+ |
| ... | ... | ... | ... |
| **总计** | **{total}** | **{total}** | **{total}** |

---

## 安全注意事项

{security_notes}

---

**报告生成完毕**
详情文件已按模块拆分，请查看上述链接获取完整接口列表和 Burp Suite 请求模板。
```

**MD 模块详情文件模板：**
````markdown
# {项目名称} - {模块名} 模块详情

生成时间: {timestamp}
模块路径: /{module-context-path}

## 模块概览

**上下文路径**: `/admin`
**框架**: Struts2 + Spring MVC + CXF Web Service

---

## 接口详细列表

### Struts2 路由

=== [1] user_login.action ===
位置: AuthAction.login (src/main/java/com/example/app/auth/AuthAction.java:45)
HTTP 方法: POST
URL 路径: /admin/user_login.action

Burp Suite 请求模板(必须在代码块中):
```http
[完整请求模板]
```

[所有接口的完整模板...]
````

### 9. 生成说明文档

**必须生成一个说明文档**，内容是如何识别路由以及参数的教程。

**说明文档命名：**
```
{project_name}_README_{timestamp}.md
```

**说明文档内容模板：**
```markdown
# {项目名称} - 路由识别教程

生成时间: {timestamp}

## 本文档说明

本文档说明如何从 {项目名称} 的源码中识别 HTTP 路由和请求参数。

---

## 使用的框架

#### 1. Spring MVC

**识别方法：**
- 查找带有 `@Controller` 或 `@RestController` 注解的类
- 查找带有 `@RequestMapping` 及其变体（`@GetMapping`、`@PostMapping` 等）的方法

**路由组成：**
- 类级别的 `@RequestMapping` 值作为基础路径
- 方法级别的 `@RequestMapping` 值追加到基础路径后

**参数识别：**
| 注解 | 参数来源 | 示例 |
|:-----|:--------|:-----|
| `@PathVariable` | URL 路径变量 | `/user/{id}` |
| `@RequestParam` | URL 查询参数 | `?name=xxx` |
| `@RequestBody` | 请求体 | JSON/XML |
| `@RequestHeader` | HTTP 请求头 | `X-Auth-Token` |
| `@CookieValue` | Cookie | `JSESSIONID` |

---

#### 2. Struts 2

**识别方法：**
- 解析 `struts.xml` 配置文件
- 查找 `<action>` 标签的配置

**路由组成：**
- `<package>` 标签的 `namespace` 属性
- `<action>` 标签的 `name` 属性 + `.action` 后缀

**参数识别：**
- 查看 Action 类的属性定义
- 查看 `struts.xml` 中的 `<param>` 配置
- 查看拦截器配置中的参数绑定

---

#### 3. Web Service (CXF/JAX-WS)

**识别方法：**
- 查找 `applicationContext.xml` 中的 `<jaxws:endpoint>` 配置
- 反编译实现类，查找 `@WebService` 注解

**路由组成：**
- endpoint 的 `address` 属性

**参数识别：**
- 通过反编译获取方法类中的参数定义
- 查看接口文档（如 WSDL）

---

#### 4. JAX-RS

**识别方法：**
- 查找带有 `@Path` 注解的类
- 查找带有 `@GET`、`@POST` 等注解的方法

**路由组成：**
- 类级别的 `@Path` 值作为基础路径
- 方法级别的 `@Path` 值追加到基础路径后

**参数识别：**
| 注解 | 参数来源 | 示例 |
|:-----|:--------|:-----|
| `@PathParam` | URL 路径变量 | `/user/{id}` |
| `@QueryParam` | URL 查询参数 | `?name=xxx` |

---

#### 5. Servlet

**识别方法：**
- 查找 `web.xml` 中的 `<servlet>` 和 `<servlet-mapping>` 配置
- 查找带有 `@WebServlet` 注解的类

**路由组成：**
- `<url-pattern>` 标签的值

**参数识别：**
- 查看 Servlet 类的 `doGet`、`doPost` 等方法
- 从 `HttpServletRequest` 中提取参数

---

## 参数类型说明

### 基本类型
| Java 类型 | HTTP 表示 | 示例 |
|:--------|:--------|:-----|
| String | 文本 | `"value"` |
| int/Integer | 整数 | `123` |
| long/Long | 长整数 | `123456789` |
| boolean/Boolean | 布尔值 | `true` |

### 集合类型
| Java 类型 | HTTP 表示 | 示例 |
|:--------|:--------|:-----|
| List/Array | JSON 数组 | `["a", "b", "c"]` |
| Map | JSON 对象 | `{"key": "value"}` |

### 对象类型 (POJO)
- 反序列化为嵌套的 JSON 对象
- 字段名与方法对应

---

## 反编译使用说明

当源码不可用时，使用 MCP Java Decompiler：

1. 找到目标 `.class` 文件
2. 使用 `mcp__java-decompile-mcp__decompile_file` 反编译
3. 从反编译结果中提取方法签名和参数定义

---

## 常见问题

**Q: 为什么某些路由无法解析？**
A: 可能原因：
- 使用了动态路由（如通配符 `*`）
- 使用了自定义拦截器/过滤器
- 配置使用了表达式（如 SpEL）

**Q: 参数类型显示为 `unknown`？**
A: 使用反编译工具获取完整的类定义

**Q: Web Service 方法列表为空？**
A: 需要反编译 Service 实现类以获取方法定义

---

## 参考文档

- [SPRING_MVC.md](references/SPRING_MVC.md)
- [STRUTS.md](references/STRUTS.md)
- [WEBSERVICE.md](references/WEBSERVICE.md)
- [JAXRS.md](references/JAXRS.md)
- [SERVLET.md](references/SERVLET.md)
- [ANNOTATIONS.md](references/ANNOTATIONS.md)
- [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md) - 反编译策略指南
```

---

## 工具使用

### MCP Java Decompiler

```bash
# 反编译单个文件
mcp__java-decompile-mcp__decompile_file(
  file_path,
  output_dir,      # 输出目录，默认为文件所在目录下的 decompiled 文件夹
  save_to_file     # 是否直接保存到文件系统(推荐)，默认为 True
)

# 反编译目录
mcp__java-decompile-mcp__decompile_directory(
  directory_path,
  output_dir,      # 输出目录，默认为目标目录下的 decompiled 文件夹
  recursive,       # 是否递归扫描子目录，默认为 True
  save_to_file,    # 是否直接保存到文件系统(推荐)，默认为 True
  show_progress,   # 是否显示详细进度信息，默认为 True
  max_workers      # 最大并发线程数，默认为 4
)

# 反编译多个文件
mcp__java-decompile-mcp__decompile_files(
  file_paths,
  output_dir,      # 输出目录，默认为当前目录下的 decompiled 文件夹
  save_to_file,    # 是否直接保存到文件系统(推荐)，默认为 True
  show_progress,   # 是否显示详细进度信息，默认为 True
  max_workers      # 最大并发线程数，默认为 4
)
```

## 限制与边界

**仅执行以下操作：**
- 从源码/反编译结果中提取已有的路由定义
- 解析已声明的参数结构
- 生成 HTTP 请求模板

**不执行以下操作：**
- 不进行漏洞分析或安全风险判断
- 不推断接口业务逻辑或行为
- 不编造不存在的路由或参数
- 不推断默认值或可选性（除非明确标注）

## 最佳实践

1. **完整输出**：必须输出所有接口，不省略任何内容
   - 即使有 100+ 个接口，也要全部列出
   - 每个接口都要有完整的参数分析和 Burp 模板
   - 使用序号或索引确保用户可以验证没有遗漏
   - 禁止使用"示例"、"其他"、"..."等省略词汇

2. **优先源码**：仅在必要时使用反编译

3. **记录来源**：标注每个路由的源文件位置

4. **保持一致**：输出格式统一，便于后续处理

5. **渐进式输出**：边分析边输出，但每个接口必须完整

6. **错误处理**：遇到无法解析的配置时记录并跳过，跳过的也要记录在输出中

7. **可验证性**：在输出末处提供接口总数和清单，用户可以核对

8. **文件拆分**：当接口数量较多时，按模块或 namespace 拆分文件
   - 确保每个拆分后的文件都有完整的接口列表
   - 主索引文件提供各详情文件的链接

9. **动态适配**：文件名根据实际项目中发现的模块名/namespace 动态生成
   - 不局限于预设的模块名（如 admin、itc）
   - 适配各种可能的模块命名

10. **⭐ Web Service 配置文件优先（CRITICAL）**

    **这是最容易出错的环节，必须严格遵守：**

    a. **必须读取配置文件**
       ```
       applicationContext.xml 中的 <jaxws:endpoint> 配置
       ```

    b. **路径的唯一真实来源是 `address` 属性**
       ```xml
       <jaxws:endpoint address="/UserApi" />
       实际路径 = /myapp/services/UserApi
       ```

    c. **禁止任何形式的推断**
       - ❌ 根据类名推断路径
       - ❌ 根据 endpoint id 推断路径
       - ❌ 假设驼峰命名转换规则
       - ✅ 只使用配置文件中明确声明的 address 值

    d. **验证检查清单**
       ```markdown
       在输出 Web Service 时必须验证：
       - [ ] 是否读取了 applicationContext.xml？
       - [ ] 是否提取了 address 属性？
       - [ ] 是否验证了 web.xml 的 Servlet 映射？
       - [ ] URL 是否直接使用配置中的 address 值？
       - [ ] 是否进行了任何类名推断？（如果有，标记为未验证）
       - [ ] 是否标注了配置来源和行号？
       ```

    e. **输出必须包含配置追溯信息**
       ```markdown
       ### UserService
       - 配置文件: applicationContext.xml:42
       - address 属性: /UserApi
       - 完整 URL: /myapp/services/UserApi
       ```

    f. **参考文档**
       - 详细的 CXF Web Service 解析步骤见 [WEBSERVICE.md](references/WEBSERVICE.md)

## 示例输出

### 主索引文件示例

```markdown
# MyApp - 路由审计报告（索引）

生成时间: 2026-01-21
分析路径: /path/to/webapps

## 项目概览

**项目名称**: MyApp 企业管理系统
**框架**: Struts2 + Spring MVC + CXF Web Service
**模块数量**: 5 个主要模块

---

## 模块索引

| 模块 | 文件 | 接口数量 | 框架 |
|:-----|:-------|:-----|
| admin | [myapp_module_admin_20260121.md](myapp_module_admin_20260121.md) | 218 | Struts2+Spring+CXF |
| user | [myapp_module_user_20260121.md](myapp_module_user_20260121.md) | 85 | Struts2+CXF |
| config | [myapp_module_config_20260121.md](myapp_module_config_20260121.md) | 0 | - |
| report | [myapp_module_report_20260121.md](myapp_module_report_20260121.md) | 0 | - |
| upload | [myapp_module_upload_20260121.md](myapp_module_upload_20260121.md) | 0 | - |

---

## Web Service 索引

| 服务 | 文件 | 方法数量 |
|:-----|:----|:--------|
| ProductService | [myapp_ws_productservice_20260121.md](myapp_ws_productservice_20260121.md) | 20 |
| UserService | [myapp_ws_userservice_20260121.md](myapp_ws_userservice_20260121.md) | 42 |

---

## 统计摘要

| 模块 | Action类数 | REST接口 | WS接口 |
|:-----|:--------|:-------|
| admin | 218 | 6 | 4+ |
| itc | 85 | 0 | 2+ |
| **总计** | **303** | **6** | **6** |

---

**报告生成完毕**
```

### 模块详情文件示例

````markdown
# MyApp - admin 模块详情

生成时间: 2026-01-21
模块路径: /admin

## 模块概览

**上下文路径**: `/admin`
**框架**: Struts2 + Spring MVC + CXF Web Service

---

## 接口详细列表

### Struts2 路由 (namespace: /)

=== [1] user_login.action ===
位置: AuthAction.login (src/.../AuthAction.java:45)
HTTP 方法: POST
URL 路径: /admin/user_login.action

Burp Suite 请求模板(必须在代码块中):
```http
POST /admin/user_login.action HTTP/1.1
Host: {{host}}
Content-Type: application/x-www-form-urlencoded

loginName={{username}}&password={{password}}
```
=== [2] user_logout.action ===
[完整请求模板]

[继续列出所有接口...]
````

### Web Service 详情文件示例

````markdown
# UserService 方法详情

生成时间: 2026-01-21
服务路径: /admin/services/UserService
命名空间: http://webservice.example.com

---

=== [1] user.create ===
方法ID: user_001_001
描述: 创建用户
参数: username (String), email (String), role (String)

Burp Suite 请求模板(必须在代码块中):
```http
POST /admin/services/UserService HTTP/1.1
Host: {{host}}
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://webservice.example.com">
  <soapenv:Header/>
  <soapenv:Body>
    <web:executeInterface>
      <interfaceId>user_001_001</interfaceId>
      <jsonParam>{"username":"{{username}}","email":"{{email}}","role":"{{role}}"}</jsonParam>
    </web:executeInterface>
  </soapenv:Body>
</soapenv:Envelope>
```

=== [2] user.update ===
[完整请求模板]

[所有42个方法都有完整模板...]
````

### 说明文档示例

```markdown
# MyApp - 路由识别教程

生成时间: 2026-01-21

## 本文档说明

本文档说明如何从 MyApp 企业管理系统的源码中识别 HTTP 路由和请求参数。

---

## 使用的框架

本项目同时使用了以下框架：

1. **Struts 2** - 处理主要的页面跳转和业务逻辑
2. **Spring MVC** - 提供 REST API 接口
3. **CXF Web Service** - 提供 SOAP Web Service 接口

### 1. Struts 2

**识别方法：**
- 解析 `struts.xml` 配置文件
- 查找 `<action>` 标签的配置

**路由组成：**
- `<package>` 标签的 `namespace` 属性
- `<action>` 标签的 `name` 属性 + `.action` 后缀

**参数识别：**
- 查看 Action 类的属性定义
- 查看 `struts.xml` 中的 `<param>` 配置
- 查看拦截器配置中的参数绑定

---

[更多内容...]
```

## 故障排除

| 问题 | 解决方案 |
|:-----|:---------|
| 无法识别框架 | 检查项目根目录的配置文件，参考 [FRAMEWORK_PATTERNS.md](references/FRAMEWORK_PATTERNS.md) |
| 路由路径不完整 | 检查类级别的 `@RequestMapping` 和上下文路径配置 |
| 参数类型未知 | 使用反编译工具获取完整的类型定义 |
| 生成的请求无法访问 | 确认未受安全拦截器/过滤器限制 |
| 模块名不是预期的 | 文件名是动态生成的，根据实际发现的模块/namespace 生成 |

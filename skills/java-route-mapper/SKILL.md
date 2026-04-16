---
name: java-route-mapper
description: Java Web 源码路由与参数映射分析工具。从源码中提取**所有** HTTP 路由和参数结构，并自动保存为 MD 文档。适用于：(1) 无 API 文档的项目完整接口梳理，(2) 下游漏洞审计 Skill 的路由数据源，(3) 源码端点完整分析。支持 Spring MVC、Servlet、JAX-RS、Struts 2、CXF Web Services 等框架。**必须输出所有接口，不省略任何内容，包括 Web Service 的完整 SOAP 方法**。
---

# Java Source Route & Parameter Mapper

从 Java Web 项目源码中**提取**所有 HTTP 路由与请求参数结构，为下游漏洞审计 Skill 提供完整的路由数据。**不进行安全漏洞评估、代码质量分析或任何路由提取范围之外的内容输出。**

## ⚠️ 核心要求：完整输出

**此技能必须输出所有发现的接口，不允许省略。**

- ✅ 每个接口都要有完整的参数分析
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
   find {WEB-INF/classes/对应包路径} -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
   ```

3. **提取每个 Action 类的业务方法**
   - 所有 public 方法
   - 排除：getter/setter（get*/set*/is*）
   - 排除：继承自 ActionSupport 的方法（execute 除外）
   - 保留：所有其他 public 方法

4. **生成路由映射表**

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

3. **在参数结构中标注变量类型**

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

4. **为每个方法记录完整的方法签名和参数列表**

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
2. **为每个 interfaceId 记录独立的参数结构**

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
HTTP 方法: POST
Content-Type: application/x-www-form-urlencoded

参数结构:
  Body: loginName (String), password (String)
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

参数结构:
  Body: SOAP XML
    - loginName (String) - 登录名
    - password (String) - 密码
```

---

### CRITICAL 5: 输出前强制验证

**此验证必须通过才能写入文件，验证不通过时必须返回补充内容。**

#### 5.1 数量一致性检查

| 检查项 | 计算公式 | 通过条件 |
|:-------|:---------|:---------|
| Struts2 路由 | 实际接口数 ÷ Action类数 | ≥ 3 |
| Spring MVC 接口 | 实际接口数 ÷ Controller类数 | ≥ 2 |
| JAX-RS 接口 | 实际接口数 ÷ Resource类数 | ≥ 2 |
| Servlet 接口 | 实际接口数 ÷ Servlet类数 | ≥ 1 |
| Web Service 方法 | 实际接口数 ÷ 反编译获得的方法数 | = 100% |

#### 5.2 省略词检测

扫描输出内容，检测到任何省略标志时必须替换为完整内容。

#### 5.3 文件完整性检查

- [ ] 主索引中每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的路由和参数信息（不是摘要）
- [ ] Web Service 索引中的每个服务都有完整的方法列表
- [ ] 没有"详见xxx"但 xxx 文件不存在的情况

#### 5.4 验证不通过时的处理流程

1. 停止当前输出
2. 识别缺失的内容类型
3. 执行反编译获取完整信息
4. 补充缺失的接口和参数信息
5. 重新执行验证
6. 验证通过后才写入文件

---

### CRITICAL 6: 完成性检查清单（强制执行）

**在标记任务完成前，必须执行以下检查：**

#### 6.1 模块完整性检查

```markdown
□ 主索引中列出的每个模块都已生成对应的详情文件

  演示案例：
  ==========
  假设主索引文件的"模块索引"表格如下：

  | 模块 | 文件 | 接口数量 |
  |:-----|:-------|:-----|
  | admin | [admin/myapp_module_admin.md](admin/myapp_module_admin.md) | 218 |
  | user | [user/myapp_module_user.md](user/myapp_module_user.md) | 85 |
  | api | [api/myapp_module_api.md](api/myapp_module_api.md) | 45 |

  验证步骤：
  1. 检查 admin/myapp_module_admin.md 是否存在
  2. 检查 user/myapp_module_user.md 是否存在
  3. 检查 api/myapp_module_api.md 是否存在
  4. 确认模块数量(3) = 实际文件数量(3)

□ Web Service 索引中的每个服务都已生成对应的详情文件

□ 没有"详见xxx"但xxx文件不存在的情况
```

#### 6.2 交叉验证清单

```markdown
□ 文件数量一致性
  演示案例：主索引列出5个模块 → 必须有5个对应的模块子目录，且每个子目录中都有对应的 module_xxx.md 文件

□ 文件名一致性
  演示案例：主索引引用 admin/myapp_module_admin.md → 实际相对路径和文件名必须完全匹配

□ 链接有效性
  演示案例：点击主索引中的 [admin/myapp_module_admin.md] 链接应能成功打开
```

#### 6.3 内容完整性检查

```markdown
□ 每个详情文件都包含：
  - 模块概览（项目名称、上下文路径、框架）
  - 框架配置（配置文件位置）
  - 路由详细列表（每个接口的完整信息）

□ 对于空模块（无路由的模块）：
  演示案例：
  ==========
  某模块 upload 只有静态资源，没有业务路由

  正确做法：仍然生成 upload/myapp_module_upload.md
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

#### 6.4 执行验证命令

**演示案例：在完成所有文件生成后，运行以下命令验证**

```bash
# 假设项目名称为 myapp，输出目录为 route_mapper/，生成的文件如下：
# route_mapper/myapp_route_mapper_20260129.md       (主索引)
# route_mapper/admin/myapp_module_admin_20260129.md  (admin模块)
# route_mapper/user/myapp_module_user_20260129.md    (user模块)
# route_mapper/api/myapp_module_api_20260129.md      (api模块)

# 验证命令1: 检查生成的模块子目录和文件
find route_mapper/ -name "*_module_*.md" -type f
# 预期输出：应该看到3个模块详情文件

# 验证命令2: 从主索引中提取所有引用的文件路径
grep -oP '[a-z]+/myapp_module_[^)]*md' route_mapper/myapp_route_mapper_20260129.md | sort -u

# 验证命令3: 检查引用的文件是否都存在
grep -oP '[a-z]+/myapp_[^)]*md' route_mapper/myapp_route_mapper_20260129.md | while read f; do
  if [ ! -f "route_mapper/$f" ]; then
    echo "❌ 缺失文件: route_mapper/$f"
  else
    echo "✅ 存在文件: route_mapper/$f"
  fi
done
```

#### 6.5 完成确认

**演示案例：完整的检查流程**

```markdown
假设分析了一个名为 myshop 的电商项目，包含以下模块：

步骤1: 生成主索引文件
  ✅ route_mapper/myshop_route_mapper_20260129.md

步骤2: 检查主索引中的模块列表
  主索引显示：product, order, user, payment (4个模块)

步骤3: 验证模块子目录和详情文件是否存在
  ✅ route_mapper/product/myshop_module_product_20260129.md
  ✅ route_mapper/order/myshop_module_order_20260129.md
  ✅ route_mapper/user/myshop_module_user_20260129.md
  ✅ route_mapper/payment/myshop_module_payment_20260129.md

步骤4: 生成README文档
  ✅ route_mapper/myshop_README_20260129.md

步骤5: 执行验证命令
  $ find route_mapper/ -name "*_module_*.md" -type f | wc -l
  4 (与主索引中模块数量一致)

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

---

## 工作流程

### 1. 项目扫描初始化

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

**参数类型解析：**
- 基本类型（String、int、long 等）
- 对象类型（POJO）
- 集合类型（List、Map、Set）
- 枚举类型

### 5. 反编译支持（必要时）

当接口定义或方法签名位于已编译的 .class 文件或第三方 JAR 中时：

1. 使用 CFR 反编译器反编译目标文件
2. 提取方法签名和参数类型定义
3. 还原参数结构

**反编译策略：**
- 仅反编译包含目标接口或参数定义的类
- 优先使用已存在的源码
- 记录反编译来源以便追溯

### 6. 生成输出

**重要：必须输出所有发现的接口，不要省略或使用摘要。**

为**每个**接口生成完整的路由与参数结构记录，包含：
- 所有路由（即使数量很大）
- 每个路由的完整参数结构

**禁止的操作：**
- ❌ 不要使用"..."省略接口
- ❌ 不要使用"等"、"其他"来省略
- ❌ 不要只输出"关键接口"或"重要接口"
- ❌ 不要因为数量大而使用表格摘要
- ❌ 不要说"由于数量庞大，只列出部分"
- ❌ 不要只输出 WSDL 地址而不列出具体的 SOAP 方法
- ❌ 不要只列出 Action 类名而不列出具体的路由和参数

**强制要求：**
- ✅ 每个 Struts2 action 路由都要有对应的参数结构
- ✅ 每个 REST 接口都要有完整的参数结构
- ✅ 每个 Web Service 方法都要有独立的方法签名和参数列表
- ✅ 对于 executeInterface 类型的服务，必须为每个 methodId 列出独立的参数结构

**要求的输出格式（每条）：**

````markdown
=== [序号] 接口标识 ===

注解: （仅复制源码中的 @ApiOperation 或 Javadoc 原文，无注解时留空）
位置: ClassName.methodName (源文件:行号)

HTTP 方法: GET/POST/PUT/DELETE 等
URL 路径: /完整/路径/结构
Content-Type: application/json 等

参数结构:
  Path: {pathVar1}, {pathVar2}
  Query: param1, param2 (类型: String)
  Body: ContentType (类型定义)
  Header: X-Custom-Header
  Cookie: sessionId
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

#### 7.2 文件名与目录策略

**按模块建子目录，文件名动态生成。**

| 文件类型 | 命名格式 | 示例 |
|---------|---------|------|
| 主索引 | `route_mapper/{项目名}_route_mapper_{时间戳}.md` | `route_mapper/myapp_route_mapper_20260121.md` |
| 模块详情 | `route_mapper/{模块名}/{项目名}_module_{模块名}_{时间戳}.md` | `route_mapper/admin/myapp_module_admin_20260121.md` |
| Web Service | `route_mapper/webservice/{项目名}_ws_{服务名}_{时间戳}.md` | `route_mapper/webservice/myapp_ws_userservice_20260121.md` |
| Namespace 拆分 | `route_mapper/{模块名}/{项目名}_{namespace}_{时间戳}.md` | `route_mapper/admin/myapp_admin_user_20260121.md` |
| README | `route_mapper/{项目名}_README_{时间戳}.md` | `route_mapper/myapp_README_20260121.md` |

**目录创建规则：**
- 主索引和 README 放在 `route_mapper/` 根目录
- 每个模块的详情文件放在 `route_mapper/{模块名}/` 子目录下
- 所有 Web Service 文件放在 `route_mapper/webservice/` 子目录下
- 子目录由 route-mapper agent 按需创建（`mkdir -p`）

**动态模块名示例：**

| 实际模块/namespace | 子目录 | 生成的文件名 |
|------------------|:------|:-------------|
| `admin` | `admin/` | `admin/myapp_module_admin_20260121.md` |
| `user` | `user/` | `user/myapp_module_user_20260121.md` |
| `config` | `config/` | `config/myapp_module_config_20260121.md` |
| `api` | `api/` | `api/myapp_module_api_20260121.md` |
| `product` | `product/` | `product/myapp_module_product_20260121.md` |
| `order` | `order/` | `order/myapp_module_order_20260121.md` |
| `/` (root namespace) | `root/` | `root/myapp_module_root_20260121.md` |

**模块识别来源：**

1. **目录结构** - webapps 下的子目录名
2. **上下文路径** - Context Path 配置
3. **Struts2 namespace** - struts.xml 中的 package namespace
4. **Spring @RequestMapping** - 类级别的路径前缀
5. **Web Service 路径** - 如 `/services/`, `/ws/`

#### 7.3 拆分策略

**策略 A: 按模块子目录拆分（推荐）**

每个模块一个子目录，主索引放根目录：

```
route_mapper/
├── {project_name}_route_mapper_{timestamp}.md         # 主索引文件（根目录）
├── {project_name}_README_{timestamp}.md               # 说明文档（根目录）
├── admin/                                             # admin 模块子目录
│   └── {project_name}_module_admin_{timestamp}.md     # 接口 ≤ 50 → 单文件
├── user/                                              # user 模块子目录
│   ├── {project_name}_module_user_{timestamp}.md      # 接口 > 50 → 模块概览 + namespace 拆分
│   ├── {project_name}_user_manage_{timestamp}.md      # namespace 详情
│   └── {project_name}_user_auth_{timestamp}.md        # namespace 详情
└── webservice/                                        # Web Service 子目录
    └── {project_name}_ws_orderService_{timestamp}.md
```

**主索引文件中的链接指向子目录：**
```markdown
## 模块索引

| 模块 | 文件 | 接口数量 | 框架 |
|:-----|:-------|:-----|:-----|
| admin | [admin/myapp_module_admin_20260121.md](admin/myapp_module_admin_20260121.md) | 35 | Struts2 |
| user | [user/myapp_module_user_20260121.md](user/myapp_module_user_20260121.md) | 218 | Struts2+Spring |

## Web Service 索引

| 服务 | 文件 | 方法数量 |
|:-----|:----|:--------|
| OrderService | [webservice/myapp_ws_orderService_20260121.md](webservice/myapp_ws_orderService_20260121.md) | 40 |
```

**拆分触发规则：**

| 条件 | 行为 |
|:-----|:-----|
| 模块接口 ≤ 50 | 单文件放在模块子目录下 |
| 模块接口 > 50 | 模块概览 + 按 namespace 拆分，都放在模块子目录下 |

**策略 B: 按 namespace 拆分（适用于单模块接口极多的情况）**

当单模块接口 > 50 时，在该模块子目录内按 namespace 继续拆分：

```
route_mapper/admin/
├── {project_name}_module_admin_{timestamp}.md          # 模块概览（含子文件索引）
├── {project_name}_admin_device_{timestamp}.md          # /device namespace
├── {project_name}_admin_channel_{timestamp}.md         # /channel namespace
└── {project_name}_admin_login_{timestamp}.md           # / namespace (登录相关)
```

#### 7.4 拆分实现规则

1. **先分析，再拆分**
   - 完成路由分析后，统计统计各模块/namespace 的接口数量
   - 根据数量决定拆分策略

2. **生成主索引文件**
   - 包含项目概览、模块索引、统计摘要
   - 指向各个详情文件的链接

3. **创建模块子目录并生成详情文件**
   - 为每个模块执行 `mkdir -p {output_path}/route_mapper/{模块名}/`
   - Web Service 统一放入 `mkdir -p {output_path}/route_mapper/webservice/`
   - 每个模块/namespace 独立写入对应子目录下的文件

4. **保证可追溯性**
   - 主索引包含各详情文件的**相对子目录路径**（如 `admin/myapp_module_admin_xxx.md`）
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
详细方法列表见: [webservice/myapp_ws_user_20260121.md](webservice/myapp_ws_user_20260121.md)
```

详情文件 `webservice/myapp_ws_user_20260121.md`：
````markdown
# UserService 方法详情

=== [1] user.create ===
方法ID: user_001_001
描述: 创建用户
参数: {"username": "...", "email": "...", "role": "..."}

方法签名: executeInterface(String interfaceId, String jsonParam)
Content-Type: text/xml; charset=utf-8
完整 URL: /admin/services/UserService

参数结构:
  Body: SOAP XML
    - interfaceId: user_001_001
    - jsonParam: {"username": "...", "email": "...", "role": "..."}

=== [2] user.update ===
[完整参数结构]

[所有40个方法都有完整参数结构...]
````

### 8. 输出文件结构

**严格按照 references/ 目录中的填充式模板生成输出文件。**

| 文件类型 | 模板 | 命名格式 | 数量 |
|---------|------|---------|------|
| 主索引 | [OUTPUT_TEMPLATE_INDEX.md](references/OUTPUT_TEMPLATE_INDEX.md) | `route_mapper/{project_name}_route_mapper_{YYYYMMDD_HHMMSS}.md` | 1 个 |
| 模块详情 | [OUTPUT_TEMPLATE_MODULE.md](references/OUTPUT_TEMPLATE_MODULE.md) | `route_mapper/{module_name}/{project_name}_module_{module_name}_{YYYYMMDD_HHMMSS}.md` | N 个（按模块） |
| WS 详情 | [OUTPUT_TEMPLATE_MODULE.md](references/OUTPUT_TEMPLATE_MODULE.md) | `route_mapper/webservice/{project_name}_ws_{service_name}_{YYYYMMDD_HHMMSS}.md` | N 个（按服务） |
| 说明文档 | [OUTPUT_TEMPLATE_README.md](references/OUTPUT_TEMPLATE_README.md) | `route_mapper/{project_name}_route_README_{YYYYMMDD_HHMMSS}.md` | 1 个 |

**关键规则：**
- 所有【填写】占位符必须替换为实际内容
- 每个接口必须有完整的参数结构
- 不得省略任何接口
- 文件名根据实际项目中发现的模块名/namespace 动态生成
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

**保存步骤：**
1. 完成所有路由分析
2. 统计各模块/namespace 的接口数量
3. 根据拆分触发条件决定拆分策略
4. 按模板生成主索引文件
5. 按模板生成各模块/namespace 的详情文件
6. 按模板生成说明文档
7. **执行各模板末尾的自检清单**
8. 在输出中告知用户所有文件保存位置

---

## 大型项目分批处理策略

### 触发条件

当满足以下任一条件时，启用分批处理：
- 预估接口总数 > 100
- 单个 namespace 接口数 > 30
- 单个 Web Service 方法数 > 20

### 分批处理步骤

**步骤 1：按 namespace/模块分组**
**步骤 2：逐个 namespace 处理**（反编译 → 提取方法 → 生成参数结构 → 验证 → 写入）
**步骤 3：增量写入**（每完成 10 个接口立即写入文件）
**步骤 4：进度检查点**（每个 namespace 完成后验证接口数量）

### 文件命名规则

对于大型项目，按模块子目录 + namespace 拆分文件：
```
route_mapper/
├── {project}_route_mapper_{date}.md                    # 主索引
├── {module}/
│   ├── {project}_module_{module}_{date}.md             # 模块概览
│   └── {project}_{module}_{namespace}_{date}.md        # namespace 详情
└── webservice/
    └── {project}_ws_{service}_{date}.md                # Web Service 详情
```

---

## 自动修正规则

当检测到省略内容时，自动执行修正：

| 检测到的问题 | 自动修正动作 |
|:-------------|:-------------|
| `Action1, Action2等` | 反编译获取完整 Action 列表，替换为全部 |
| `{action}_{method}.action` | 反编译获取实际方法，展开为具体 URL |
| `方法列表: 描述文字` | 反编译获取方法签名，替换为具体方法 |
| `共N个方法` 但列出 < N | 补充缺失的方法直到数量匹配 |
| `interfaceId: xxx ~ yyy` | 展开为逐个 interfaceId |

---

## 故障排除

| 问题 | 解决方案 |
|:-----|:---------|
| 无法识别框架 | 检查项目根目录的配置文件，参考 [FRAMEWORK_PATTERNS.md](references/FRAMEWORK_PATTERNS.md) |
| 路由路径不完整 | 检查类级别的 `@RequestMapping` 和上下文路径配置 |
| 参数类型未知 | 使用反编译工具获取完整的类型定义 |
| 生成的路由信息不完整 | 确认未受安全拦截器/过滤器限制 |
| 模块名不是预期的 | 文件名是动态生成的，根据实际发现的模块/namespace 生成 |

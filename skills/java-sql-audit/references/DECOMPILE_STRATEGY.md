# SQL 注入审计反编译策略指南

## 目录

- [何时反编译](#何时反编译)
- [反编译工具使用](#反编译工具使用)
- [SQL 相关类识别与定位](#sql-相关类识别与定位)
- [反编译结果提取](#反编译结果提取)
- [常见故障](#常见故障)

---

## 何时反编译

### 必须反编译的场景

1. **项目只有编译后的字节码**
   - WAR/JAR 包部署，无源码
   - 第三方依赖中的 DAO 组件

2. **SQL 相关类定义在 .class 文件中**
   - 自定义 DAO/Mapper 类
   - SQL 工具类
   - 数据访问层实现

3. **需要提取 SQL 拼接点**
   - 动态 SQL 构建
   - SQL 拼接逻辑
   - 参数处理方式

### 不需要反编译的场景

1. 源码已存在且可读取
2. 标准框架类（MyBatis/Hibernate 核心类）
3. Mapper XML 配置文件可直接读取

---

## 反编译工具使用

### CFR CLI 反编译器

> 详细的 CFR 获取策略和通用调用方式参见 `java-shared/DECOMPILE_STRATEGY.md`。

#### 单个文件反编译

```bash
# 反编译单个 DAO/Mapper 类
java -jar {CFR_JAR} /path/to/WEB-INF/classes/com/example/dao/UserDao.class --outputdir {output_path}/decompiled
```

#### 目录反编译

```bash
# 递归反编译整个 DAO 包
find /path/to/WEB-INF/classes/com/example/dao -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

#### 批量文件反编译

```bash
# 反编译多个指定的 SQL 相关类
java -jar {CFR_JAR} /path/to/UserDao.class /path/to/OrderMapper.class /path/to/SqlHelper.class /path/to/BaseRepository.class --outputdir {output_path}/decompiled
```

#### 检查 Java 环境

```bash
# 检查 Java 版本（反编译需要）
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help

# 如果 CFR 不存在，下载
curl -L -o {output_path}/cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
```

---

## SQL 相关类识别与定位

### 按框架定位

#### JDBC 相关类

```bash
# 查找导入 java.sql 的类
find . -name "*.class" | xargs strings | grep -l "java.sql"

# 常见类名模式
*Dao.class
*DaoImpl.class
*JdbcTemplate*.class
*DbHelper*.class
*SqlUtil*.class
```

**反编译目标：**
```python
jdbc_classes = [
    "*Dao.class",
    "*DaoImpl.class",
    "*JdbcTemplate*.class",
    "*DbHelper*.class"
]
```

#### MyBatis 相关类

```bash
# 查找 Mapper 类
find . -name "*Mapper.class" -o -name "*MapperImpl.class"

# 常见类名模式
*Mapper.class
*MapperImpl.class
*SqlProvider.class
```

**反编译目标：**
```python
mybatis_classes = [
    "*Mapper.class",
    "*MapperImpl.class",
    "*SqlProvider.class"
]
```

**同时检查 XML 文件：**
```bash
# Mapper XML 不需要反编译，直接读取
find . -name "*Mapper.xml" -o -name "*Dao.xml"
```

#### Hibernate 相关类

```bash
# 查找 Repository/DAO 类
find . -name "*Repository*.class" -o -name "*Dao.class"

# 常见类名模式
*Repository.class
*RepositoryImpl.class
*Dao.class
*DaoImpl.class
*Entity.class
```

**反编译目标：**
```python
hibernate_classes = [
    "*Repository.class",
    "*RepositoryImpl.class",
    "*Dao.class",
    "*DaoImpl.class"
]
```

### 按配置文件定位

#### 从 Spring 配置定位

```xml
<!-- applicationContext.xml -->
<bean id="userDao" class="com.example.dao.UserDaoImpl"/>
```

**提取类路径：** `com.example.dao.UserDaoImpl`
**对应 class 文件：** `WEB-INF/classes/com/example/dao/UserDaoImpl.class`

#### 从 MyBatis 配置定位

```xml
<!-- mybatis-config.xml -->
<mappers>
    <mapper resource="mapper/UserMapper.xml"/>
    <package name="com.example.mapper"/>
</mappers>
```

---

## 反编译结果提取

### JDBC 类识别要点

```java
// 反编译后的 UserDao 示例
public class UserDao {

    private DataSource dataSource;

    // ⚠️ 关注点 1: SQL 字符串构建
    public User findById(String id) {
        // ❌ 危险：字符串拼接
        String sql = "SELECT * FROM users WHERE id = " + id;

        Connection conn = dataSource.getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        // ...
    }

    // ⚠️ 关注点 2: 安全的预编译
    public User findByIdSafe(String id) {
        // ✅ 安全：使用 PreparedStatement
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, id);
        ResultSet rs = pstmt.executeQuery();
        // ...
    }

    // ⚠️ 关注点 3: 动态 SQL 构建
    public List<User> search(Map<String, String> params) {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE 1=1");

        // ❌ 危险：动态拼接
        if (params.get("name") != null) {
            sql.append(" AND name = '" + params.get("name") + "'");
        }
        // ...
    }
}
```

**提取信息：**

| 方法名 | SQL 构建方式 | 注入判定 |
|--------|------------|---------|
| findById | 字符串拼接 | **高危注入点** |
| findByIdSafe | PreparedStatement | 安全 |
| search | 动态 StringBuilder | **高危注入点** |

### MyBatis Mapper 类检查要点

```java
// 反编译后的 UserMapper 示例
@Mapper
public interface UserMapper {

    // ⚠️ 关注点 1: ${} 使用
    @Select("SELECT * FROM users WHERE id = ${id}")
    User findById(String id);  // ❌ 危险

    // ⚠️ 关注点 2: #{} 使用
    @Select("SELECT * FROM users WHERE name = #{name}")
    User findByName(String name);  // ✅ 安全

    // ⚠️ 关注点 3: 动态 ORDER BY
    @Select("SELECT * FROM users ORDER BY ${orderBy}")
    List<User> findAll(String orderBy);  // ❌ 危险
}
```

### Hibernate Repository 检查要点

```java
// 反编译后的 UserRepository 示例
@Repository
public class UserRepositoryImpl implements UserRepository {

    @PersistenceContext
    private EntityManager em;

    // ⚠️ 关注点 1: HQL 拼接
    public User findByUsername(String username) {
        // ❌ 危险：HQL 拼接
        String hql = "FROM User WHERE username = '" + username + "'";
        return em.createQuery(hql, User.class).getSingleResult();
    }

    // ⚠️ 关注点 2: 参数绑定
    public User findByUsernameSafe(String username) {
        // ✅ 安全：参数绑定
        String hql = "FROM User WHERE username = :username";
        return em.createQuery(hql, User.class)
                 .setParameter("username", username)
                 .getSingleResult();
    }

    // ⚠️ 关注点 3: Native SQL
    public User findByIdNative(Long id) {
        // ❌ 危险：Native SQL 拼接
        String sql = "SELECT * FROM users WHERE id = " + id;
        return (User) em.createNativeQuery(sql, User.class).getSingleResult();
    }
}
```

---

## 反编译策略

### 策略 1: 最小化反编译（推荐）

```bash
# 只反编译与 SQL 直接相关的类

# 步骤 1: 从配置文件识别 DAO/Mapper 类，然后反编译
find {classes_path} \( -name "*Dao.class" -o -name "*Mapper.class" -o -name "*Repository.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 步骤 2: 阅读反编译结果，识别需要进一步分析的 SQL 相关依赖

# 步骤 3: 按需反编译依赖类
java -jar {CFR_JAR} {classes_path}/com/example/util/SqlHelper.class --outputdir {output_path}/decompiled
```

### 策略 2: 层级反编译

```bash
# 第一层: 反编译 DAO/Mapper
find {classes_path} \( -name "*Dao.class" -o -name "*Mapper.class" -o -name "*Repository.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 第二层: 反编译 Service（追踪调用链）
find {classes_path} \( -name "*Service.class" -o -name "*ServiceImpl.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 第三层: 反编译工具类
find {classes_path} \( -name "*SqlUtil*.class" -o -name "*DbHelper*.class" -o -name "*SqlBuilder*.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 策略 3: 按包反编译

```bash
# 当 SQL 类集中在特定包下
find {classes_path}/com/example/dao -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
find {classes_path}/com/example/mapper -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
find {classes_path}/com/example/repository -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

---

## 常见故障

### 故障 1: 反编译失败

**可能原因：**
- Java 版本不匹配
- 代码被混淆
- class 文件损坏

**解决方案：**
```bash
# 检查 Java 版本
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help

# 如果 CFR 不存在，下载
curl -L -o {output_path}/cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
```

### 故障 2: MyBatis 注解丢失

**表现：**
```java
// 反编译后注解可能被保留
@Select("SELECT * FROM users")  // 通常保留
@Mapper  // 通常保留
```

**说明：**
- 运行时注解通常被保留
- 编译时注解可能丢失
- 需结合 XML 配置文件分析

### 故障 3: 泛型信息丢失

**表现：**
```java
// 原始
List<User> users = findAll();

// 反编译后
List users = findAll();
```

**影响：**
- 不影响 SQL 注入分析
- 可通过使用上下文推断类型

---

## 反编译结果记录

输出时必须标注反编译来源：

```markdown
=== [SQL-001] SQL 注入 - 字符串拼接 ===
风险等级: 高
位置: UserDao.findById (UserDao.java:25)
来源: **反编译 WEB-INF/classes/com/example/dao/UserDao.class**
框架: JDBC

漏洞特征:
- 使用字符串拼接构建 SQL
- 参数 id 直接拼接到查询语句

漏洞代码:
\```java
String sql = "SELECT * FROM users WHERE id = " + id;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
\```
```

---

## 性能优化

### 批量操作

```bash
# 一次性反编译多个文件，减少启动开销
java -jar {CFR_JAR} file1.class file2.class file3.class --outputdir {output_path}/decompiled
```

### 目录级批量处理

```bash
# 反编译整个 DAO 包
find {classes_path}/com/example/dao -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 如果文件数量过多，使用分批处理
find {classes_path} -name "*.class" | xargs -L 50 java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 缓存利用

- 反编译结果保存在 `{output_path}/decompiled/` 目录下
- 再次分析时先检查是否已存在反编译结果
- 避免重复反编译相同的类

# 反编译策略指南

## 目录

- [何时反编译](#何时反编译)
- [反编译工具使用](#反编译工具使用)
- [反编译结果分析](#反编译结果分析)
- [常见问题](#常见问题)

---

## 何时反编译

### 必须反编译的场景

1. **接口定义在 .class 文件中**
   - 项目只包含编译后的字节码
   - 依赖的库仅提供 JAR 包

2. **参数类型需要深入提取**
   - DTO/POJO 类无源码
   - 复杂的泛型类型需要确定具体类型

3. **第三方框架扩展**
   - 自定义的注解处理器
   - 框架的内部实现

### 不需要反编译的场景

1. 源码已存在且可读取
2. 标准库/JDK 类
3. 已有文档的第三方库

---

## 反编译工具使用

### CFR CLI 反编译器

> 详细的 CFR 获取策略和通用调用方式参见 `java-shared/DECOMPILE_STRATEGY.md`。

#### 单个文件反编译

```bash
# 反编译单个 .class 文件
java -jar {CFR_JAR} /path/to/MyController.class --outputdir {output_path}/decompiled

# 反编译单个 .jar 文件
java -jar {CFR_JAR} /path/to/app.jar --outputdir {output_path}/decompiled
```

#### 目录反编译

```bash
# 递归反编译整个目录
find /path/to/classes -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

#### 批量文件反编译

```bash
# 反编译多个文件
java -jar {CFR_JAR} /path/to/UserController.class /path/to/ProductController.class /path/to/OrderController.class --outputdir {output_path}/decompiled
```

### 反编译策略

#### 策略 1: 最小化反编译

```bash
# 只反编译需要的类，而非整个项目
# 1. 先反编译 Controller 类
find {classes_path} -name "*Controller.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 2. 阅读反编译结果，识别需要进一步分析的参数类型
# 3. 按需反编译参数类型类
java -jar {CFR_JAR} {classes_path}/com/example/dto/UserDto.class --outputdir {output_path}/decompiled
```

#### 策略 2: 层级反编译

```bash
# 1. 先反编译控制器类
find {classes_path} -name "*Controller.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 2. 反编译参数类型（DTO/POJO）
find {classes_path} \( -name "*Dto.class" -o -name "*VO.class" -o -name "*Request.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 3. 如果参数类型是嵌套对象，继续反编译
java -jar {CFR_JAR} {classes_path}/com/example/dto/ProfileDto.class --outputdir {output_path}/decompiled
```

#### 策略 3: 缓存利用

```bash
# 已反编译的文件保存在 {output_path}/decompiled/ 目录下
# 再次分析时先检查是否已存在反编译结果，避免重复反编译
ls {output_path}/decompiled/com/example/controller/UserController.java
```

---

## 反编译结果分析

### 识别关键信息

```java
// 反编译后的控制器示例
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable("id") Long id) {
        // 方法实现
    }

    @PostMapping
    public User create(@RequestBody UserDto dto) {
        // 方法实现
    }
}
```

**提取内容：**
- 类名: `UserController`
- 基础路径: `/api/users`
- 方法 1: `getUser` → GET `/api/users/{id}`, 参数 `id: Long`
- 方法 2: `create` → POST `/api/users`, 参数 `dto: UserDto`

### 参数类型分析

```java
// 反编译后的 DTO
public class UserDto {
    private String username;
    private String password;
    private Integer age;
    private List<String> roles;
    private ProfileDto profile;

    // getter/setter
}
```

**提取内容：**
- `username`: String
- `password`: String
- `age`: Integer
- `roles`: List<String>
- `profile`: ProfileDto (需要进一步分析)

### 泛型类型解析

```java
// 原始代码
public Response<List<User>> listUsers() { }

// 反编译后可能丢失泛型
public Response listUsers() { }
```

**处理策略：**
1. 检查方法返回值的使用
2. 分析方法体内的类型转换
3. 参考相关测试代码

### 匿名内部类

```java
// 反编译可能显示为
new Comparator() {
    public int compare(Object o1, Object o2) {
        // ...
    }
}
```

**处理策略：**
- 匿名类通常不影响路由结构
- 可忽略或标注为内部实现

---

## 常见问题

### 问题 1: 反编译失败

**可能原因：**
- 文件损坏
- 不支持的 Java 版本
- 混淆的代码

**解决方案：**
```bash
# 检查 Java 版本
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help

# 如反编译结果不完整，记录为"无法反编译"并跳过
```

### 问题 2: 反编译结果不完整

**表现：**
- 缺少方法体
- 变量名被混淆

**影响：**
- 路由结构仍然可识别（注解保留）
- 参数名可能丢失，但类型可推断

**解决方案：**
```python
# 从注解中提取信息
annotations = extract_annotations(method)

# 从参数类型中提取信息
param_types = extract_parameter_types(method)

# 即使变量名丢失，仍然可以生成模板
generate_template(annotations, param_types)
```

### 问题 3: Lambda 表达式

```java
// 原始代码
users.stream().filter(u -> u.getAge() > 18).collect(toList());

// 反编译后可能显示为
users.stream().filter(new Predicate() {
    public boolean test(Object u) {
        return ((User)u).getAge() > 18;
    }
}).collect(toList());
```

**处理策略：**
- Lambda 不影响路由分析
- 关注注解和方法签名

### 问题 4: 枚举类型

```java
// 反编译结果
public enum UserRole {
    ADMIN, USER, GUEST;
}
```

**提取内容：**
- 枚举类: `UserRole`
- 可能值: `ADMIN`, `USER`, `GUEST`

**参数示例：**
```
role=ADMIN
role=USER
role=GUEST
```

---

## 反编译结果验证

### 验证清单

- [ ] 类路径与预期一致
- [ ] 注解信息完整
- [ ] 方法签名清晰
- [ ] 参数类型可解析
- [ ] 泛型信息合理

---

## 记录反编译来源

```python
# 输出时标注反编译来源
{
    "route": "/api/users/{id}",
    "method": "GET",
    "parameters": [
        {
            "name": "id",
            "type": "Long",
            "source": "decompiled: UserController.class:45"
        }
    ],
    "controller_location": "decompiled: UserController.class"
}
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
# 反编译整个目录
find {classes_path} -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 如果文件数量过多，使用分批处理
find {classes_path} -name "*.class" | xargs -L 50 java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 缓存利用

```bash
# 反编译结果保存在 {output_path}/decompiled/ 目录下
# 再次分析时先检查是否已存在反编译结果
# 避免重复反编译相同的类
```

---

## 反编译与源码混合

当项目同时包含源码和编译文件时：

1. **优先使用源码** — 如果 `.java` 文件已存在，直接读取，不反编译
2. **源码不存在则反编译** — 仅对没有源码的 `.class` 文件执行反编译
3. **缓存利用** — 已反编译的文件保存在 `{output_path}/decompiled/` 目录下，避免重复反编译

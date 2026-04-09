# CFR 反编译工具 CLI 使用指南（共享）

所有审计 Skill 共享此 CFR CLI 反编译指南，确保反编译方式统一。

---

## 1. CFR 获取策略

### 1.1 用户指定 cfr.jar 路径

如果用户在调用 Skill 时提供了 cfr.jar 的路径，直接使用该路径：

```bash
# 用户指定路径示例
CFR_JAR="/path/to/cfr-0.152.jar"
```

### 1.2 自动下载（未指定路径时）

如果用户未指定 cfr.jar 路径，按以下顺序查找或下载：

**步骤 1：在输出目录下查找已有的 cfr.jar**

```bash
# 在审计输出目录下查找
find {output_path} -name "cfr-*.jar" -type f 2>/dev/null | head -1
```

**步骤 2：如果未找到，下载到审计输出目录**

```bash
curl -L -o {output_path}/cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
CFR_JAR="{output_path}/cfr-0.152.jar"
```

### 1.3 环境验证

```bash
# 检查 Java 是否可用
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help
```

---

## 2. CFR CLI 调用方式

> **⚠️ 重要约束：**
> - CFR **不接受目录路径**作为输入参数，只接受 `.class` 或 `.jar` 文件路径
> - CFR **没有 `--recurse` 参数**，递归反编译必须使用 `find ... | xargs` 方式
> - 直接传目录会报 `FileNotFoundException: ... (Is a directory)`
> - 传 `--recurse true` 会报 `Unknown argument recurse`

### 2.1 单个文件反编译

```bash
# 反编译单个 .class 文件
java -jar {CFR_JAR} /path/to/MyClass.class --outputdir {output_path}/decompiled

# 反编译单个 .jar 文件（自动解包所有类）
java -jar {CFR_JAR} /path/to/app.jar --outputdir {output_path}/decompiled
```

### 2.2 多个文件反编译

```bash
# 反编译多个指定文件
java -jar {CFR_JAR} /path/to/A.class /path/to/B.class /path/to/C.class --outputdir {output_path}/decompiled
```

### 2.3 目录递归反编译

```bash
# 反编译目录下所有 .class 文件
find /path/to/WEB-INF/classes -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译指定包下的所有 .class 文件
find /path/to/WEB-INF/classes/com/example/controller -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 2.4 按类名模式反编译

```bash
# 反编译所有 Controller 类
find /path/to/classes -name "*Controller.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译所有 DAO/Mapper 类
find /path/to/classes \( -name "*Dao.class" -o -name "*Mapper.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

---

## 3. 反编译策略

### 策略 1: 最小化反编译（推荐）

只反编译需要分析的目标类，按需逐步扩展：

```bash
# 步骤 1: 反编译入口类（Controller/Filter/Action）
find {classes_path} -name "*Controller.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 步骤 2: 阅读反编译结果，识别需要进一步分析的依赖类

# 步骤 3: 按需反编译依赖类
java -jar {CFR_JAR} {classes_path}/com/example/service/UserService.class --outputdir {output_path}/decompiled
```

### 策略 2: 层级反编译

```bash
# 第一层: Controller/Action/Servlet
find {classes_path} \( -name "*Controller.class" -o -name "*Action.class" -o -name "*Servlet.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 第二层: Service
find {classes_path} \( -name "*Service.class" -o -name "*ServiceImpl.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 第三层: DAO/Repository
find {classes_path} \( -name "*Dao.class" -o -name "*Mapper.class" -o -name "*Repository.class" \) | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 策略 3: 按包反编译

```bash
# 反编译整个业务包
find {classes_path}/com/example -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

---

## 4. 反编译与源码混合策略

当项目同时包含源码和编译文件时：

1. **优先使用源码** — 如果 `.java` 文件已存在，直接读取，不反编译
2. **源码不存在则反编译** — 仅对没有源码的 `.class` 文件执行反编译
3. **缓存利用** — 已反编译的文件保存在 `{output_path}/decompiled/` 目录下，避免重复反编译

---

## 5. 常见故障处理

### 故障 1: Java 未安装

```bash
# 检查 Java 是否可用
java -version
# 如果不可用，提示用户安装 JRE/JDK
```

### 故障 2: CFR 下载失败

```bash
# 检查网络连接
curl -I "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"

# 提示用户手动下载并指定路径
```

### 故障 3: 反编译失败（混淆代码）

- 注解信息通常仍被保留（`@Controller`、`@RequestMapping` 等）
- 变量名可能被混淆，但方法签名和类型信息仍可用
- 如反编译结果不完整，记录为"无法反编译"并跳过

### 故障 4: xargs 参数过长

```bash
# 如果文件数量过多导致 xargs 报错，使用分批处理
find {classes_path} -name "*.class" | xargs -L 50 java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

---

## 6. 反编译结果验证

### 验证清单

- [ ] 类路径与预期一致
- [ ] 注解信息完整（`@Controller`、`@RequestMapping` 等）
- [ ] 方法签名清晰
- [ ] 参数类型可解析

### 反编译结果标注

输出审计报告时，必须标注反编译来源：

```markdown
位置: UserController.getUser (UserController.java:25)
来源: **反编译 WEB-INF/classes/com/example/controller/UserController.class**
```

# 文件读取审计反编译策略指南

## 目录

- [何时反编译](#何时反编译)
- [反编译工具使用](#反编译工具使用)
- [文件操作相关类识别与定位](#文件操作相关类识别与定位)
- [反编译结果分析](#反编译结果分析)
- [常见问题](#常见问题)

---

## 何时反编译

### 必须反编译的场景

1. **项目只有编译后的字节码**
   - WAR/JAR 包部署，无源码
   - 第三方依赖中的文件操作组件

2. **文件操作相关类定义在 .class 文件中**
   - 自定义 Controller/Service 类
   - 文件操作工具类
   - 下载/上传处理类

3. **需要分析文件操作逻辑**
   - 文件路径拼接
   - 路径校验逻辑
   - 文件读取方式

### 不需要反编译的场景

1. 源码已存在且可读取
2. 标准框架类（Spring MVC 核心类）
3. 配置文件可直接读取

---

## 反编译工具使用

### CFR CLI 反编译器

> 详细的 CFR 获取策略和通用调用方式参见 `java-shared/DECOMPILE_STRATEGY.md`。

#### 单个文件反编译

```bash
# 反编译单个 Controller 类
java -jar {CFR_JAR} /path/to/WEB-INF/classes/com/example/controller/FileController.class --outputdir {output_path}/decompiled
```

**输出示例：**
```
反编译结果保存到：{output_path}/decompiled/com/example/controller/FileController.java
```

#### 目录反编译

```bash
# 递归反编译整个 Controller 包
find /path/to/WEB-INF/classes/com/example/controller -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

#### 批量文件反编译

```bash
# 反编译多个指定的文件操作相关类
java -jar {CFR_JAR} /path/to/FileController.class /path/to/FileService.class /path/to/FileUtil.class /path/to/DownloadHandler.class --outputdir {output_path}/decompiled
```

---

## 文件操作相关类识别与定位

### 按功能定位

#### 文件下载/读取相关类

```bash
# 查找包含 download/readFile 的类
find . -name "*.class" | xargs strings | grep -l "download\|readFile\|getFile"

# 常见类名模式
*Controller.class
*Service.class
*FileUtil*.class
*FileHelper*.class
*DownloadHandler*.class
```

**反编译目标：**
```python
file_operation_classes = [
    "*FileController.class",
    "*DownloadController.class",
    "*FileService.class",
    "*FileUtil*.class",
    "*FileHelper*.class"
]
```

### 按包定位

#### 从 Spring 配置定位

```xml
<!-- applicationContext.xml -->
<bean id="fileService" class="com.example.service.FileServiceImpl"/>
```

**提取类路径：** `com.example.service.FileServiceImpl`
**对应 class 文件：** `WEB-INF/classes/com/example/service/FileServiceImpl.class`

---

## 反编译结果分析

### Controller 类分析要点

```java
// 反编译后的 FileController 示例
@RestController
@RequestMapping("/file")
public class FileController {

    // ⚠️ 关注点 1: 路径参数来源
    @GetMapping("/download")
    public void download(@RequestParam String filePath, HttpServletResponse response) {
        // ❌ 危险：直接使用用户输入
        FileInputStream fis = new FileInputStream(filePath);
        // ...
    }

    // ⚠️ 关注点 2: 路径拼接
    @GetMapping("/read")
    public String readFile(@RequestParam String fileName) {
        // ❌ 危险：路径拼接未校验
        String fullPath = "/var/uploads/" + fileName;
        return Files.readString(Path.of(fullPath));
    }

    // ⚠️ 关注点 3: 安全的实现
    @GetMapping("/download-safe")
    public void downloadSafe(@RequestParam String fileName, HttpServletResponse response) {
        // ✅ 安全：路径规范化 + 白名单
        String basePath = "/var/uploads";
        File file = new File(basePath, fileName);
        String canonicalPath = file.getCanonicalPath();
        if (!canonicalPath.startsWith(basePath)) {
            throw new SecurityException("Invalid path");
        }
        // ...
    }
}
```

**提取信息：**

| 信息类型 | 内容 | 漏洞判定 |
|----------|------|----------|
| download | 直接使用 filePath 参数 | **高危** |
| readFile | 路径拼接未校验 | **高危** |
| downloadSafe | 规范化 + 白名单 | 安全 |

### Service 类分析要点

```java
// 反编译后的 FileService 示例
@Service
public class FileServiceImpl implements FileService {

    // ⚠️ 关注点 1: 路径处理逻辑
    public String readFile(String filePath) {
        // ❌ 危险：未校验
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            // ...
        }
    }

    // ⚠️ 关注点 2: 路径校验
    public String readFileSafe(String fileName) {
        // ✅ 安全：白名单扩展名
        if (!fileName.endsWith(".txt") && !fileName.endsWith(".pdf")) {
            throw new SecurityException("Invalid file type");
        }

        // ✅ 安全：规范化路径
        String basePath = "/var/uploads";
        File file = new File(basePath, fileName);
        String canonicalPath = file.getCanonicalPath();

        if (!canonicalPath.startsWith(basePath)) {
            throw new SecurityException("Path traversal detected");
        }
        // ...
    }
}
```

### 工具类分析要点

```java
// 反编译后的 FileUtil 示例
public class FileUtil {

    // ⚠️ 关注点 1: 通用文件读取方法
    public static byte[] readFileBytes(String filePath) {
        // ❌ 危险：通用方法未校验
        return Files.readAllBytes(Path.of(filePath));
    }

    // ⚠️ 关注点 2: 路径规范化工具
    public static String getCanonicalPath(String basePath, String fileName) {
        // ✅ 安全：提供规范化工具
        File file = new File(basePath, fileName);
        return file.getCanonicalPath();
    }

    // ⚠️ 关注点 3: 路径校验工具
    public static boolean isPathSafe(String path, String allowedBase) {
        // ✅ 安全：提供校验工具
        return path.startsWith(allowedBase);
    }
}
```

---

## 反编译策略

### 策略 1: 最小化反编译（推荐）

```python
# 只反编译与文件操作直接相关的类

# 步骤 1: 从路由识别 Controller 类
file_controllers = find_file_controllers()

# 步骤 2: 反编译 Controller 类
for cls in file_controllers:
    decompile_file(cls)

# 步骤 3: 分析依赖，反编译文件操作相关的依赖类
dependencies = extract_file_dependencies(file_controllers)
for dep in dependencies:
    if is_file_related(dep):
        decompile_file(dep)
```

### 策略 2: 层级反编译

```python
# 第一层: 反编译 Controller
layer1 = ["*FileController.class", "*DownloadController.class"]
decompile_by_pattern(layer1)

# 第二层: 反编译 Service
layer2 = ["*FileService.class", "*FileServiceImpl.class"]
decompile_by_pattern(layer2)

# 第三层: 反编译工具类
layer3 = ["*FileUtil*.class", "*FileHelper*.class"]
decompile_by_pattern(layer3)
```

### 策略 3: 按包反编译

```bash
# 当文件操作类集中在特定包下
find {classes_path}/com/example/controller -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
find {classes_path}/com/example/service -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
find {classes_path}/com/example/util -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
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

### 故障 2: 注解丢失

**表现：**
```java
// 反编译后注解通常被保留
@GetMapping("/download")  // 通常保留
@RequestParam  // 通常保留
```

**说明：**
- 运行时注解通常被保留
- 编译时注解可能丢失

---

## 反编译结果记录

输出时必须标注反编译来源：

```markdown
=== [FILE-001] 任意文件读取 ===
风险等级: 高
位置: FileController.download (FileController.java:25)
来源: **反编译 WEB-INF/classes/com/example/controller/FileController.class**

漏洞描述:
- 直接使用用户输入的 filePath 参数
- 未进行路径校验
- 可导致任意文件读取

漏洞代码:
\```java
@GetMapping("/download")
public void download(@RequestParam String filePath) {
    FileInputStream fis = new FileInputStream(filePath);
    // ...
}
\```

反编译输出路径:
/path/to/decompiled/com/example/controller/FileController.java
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
# 反编译整个 Controller 包
find {classes_path}/com/example/controller -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 如果文件数量过多，使用分批处理
find {classes_path} -name "*.class" | xargs -L 50 java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

### 缓存利用

- 反编译结果保存在 `{output_path}/decompiled/` 目录下
- 再次分析时先检查是否已存在反编译结果
- 避免重复反编译相同的类

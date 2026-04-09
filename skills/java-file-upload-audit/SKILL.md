---
name: java-file-upload-audit
description: Java Web 源码文件上传漏洞审计工具。用于从源码中识别所有文件上传入口并检查上传路径、文件名处理与校验逻辑漏洞。适用于：(1) 识别 Servlet/Commons FileUpload 与 Spring Boot MultipartFile 上传实现，(2) 发现任意文件上传、路径穿越与可执行文件上传漏洞，(3) 检查文件名/目录/类型/大小校验是否缺失或可绕过，(4) 审计上传目录与访问控制。**支持反编译 .class/.jar 文件提取上传逻辑**。结合 java-route-mapper 使用可实现完整的路由+文件上传审计。
---

# Java 文件上传漏洞审计工具

检查 Java Web 项目源码，识别文件上传实现并检测上传相关漏洞（任意文件上传、路径穿越、文件覆盖、Web 根目录可执行等）。

## 核心要求

**此技能必须完整分析所有上传相关代码，不允许省略。**

- ✅ 识别所有上传入口点（ServletFileUpload / MultipartFile / transferTo / FileItem）
- ✅ 标注每个上传点的保存路径、文件名来源与校验策略
- ✅ 检测所有潜在的上传漏洞模式（类型校验缺失、路径穿越、Web 根目录写入、文件覆盖）
- ✅ 当源码不可用时必须反编译，并输出反编译文件清单（文件名 + 位置）
- ❌ 禁止省略任何上传入口
- ❌ 禁止跳过反编译步骤

---

## 漏洞分级标准

**详见 [SEVERITY_RATING.md](../java-shared/SEVERITY_RATING.md)**

- 漏洞编号格式: `{C/H/M/L}-UPLOAD-{序号}`
- 严重等级 = f(可达性 R, 影响范围 I, 利用复杂度 C)
- Score = R × 0.40 + I × 0.35 + C × 0.25，映射 CVSS 3.1

| 前缀 | CVSS 3.1 | 含义 |
|------|----------|------|
| 🔴 **C** | 9.0-10.0 | 可直接导致系统沦陷 |
| 🟠 **H** | 7.0-8.9 | 可造成重大损害 |
| 🟡 **M** | 4.0-6.9 | 可造成一定损害 |
| 🔵 **L** | 0.1-3.9 | 安全加固项 |

---

## 技能协作流程（CRITICAL）

**java-file-upload-audit 必须在 java-route-mapper 之后执行，基于已梳理的路由信息进行审计。**

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
│     │ │   └─ JSON 内部字段                                      │
│     │ └─ Burp Suite 请求模板                                    │
│     │                                                           │
│     ↓                                                           │
│  [步骤2] java-file-upload-audit（本技能）                       │
│     │                                                           │
│     │ 输入：java-route-mapper 的输出                            │
│     │                                                           │
│     │ 执行：                                                    │
│     │ ├─ 快速扫描上传实现                                       │
│     │ ├─ 参数-上传映射分析                                      │
│     │ ├─ 校验逻辑与保存路径分析                                 │
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

**在开始审计前，必须先检查是否已有 java-route-mapper 的输出文件：**

```
{project_name}_audit/
├── route_mapper/
│   ├── {project_name}_route_mapper_{timestamp}.md    ← 主索引（先读此文件定位模块详情）
│   ├── {module_name}/
│   │   └── {project_name}_module_{module_name}_{timestamp}.md  ← 模块详情
│   └── webservice/
│       └── {project_name}_ws_{service_name}_{timestamp}.md
└── file_upload_audit/
    └── {project_name}_file_upload_audit_{timestamp}.md  ← 本技能输出
```

**如果 route_mapper 输出不存在，建议先运行：**
```python
Skill(skill="java-route-mapper", args="--project {project_path}")
```

### 从 route_mapper 获取的关键信息

| 信息 | 用途 |
|:-----|:-----|
| 路由路径 | 定位上传 Controller/Servlet 入口 |
| 参数名 + 类型 | 识别 MultipartFile / FileItem / fileName 参数 |
| JSON 内部字段 | 识别嵌套上传参数 |
| 参数用途描述 | 判断是否用于文件名或保存路径 |

---

## 工作流程（三阶段）

### 阶段1: 快速扫描（优先执行）

**目标：快速定位上传相关代码，不遗漏关键点。**

```bash
# 1.1 Servlet/Commons FileUpload
rg -n "ServletFileUpload|DiskFileItemFactory|FileItem|isMultipartContent" --glob="*.java"

# 1.2 Spring Boot MultipartFile
rg -n "MultipartFile|@RequestParam\\(\"file\"\\)|transferTo\\(" --glob="*.java"

# 1.3 文件名/路径相关
rg -n "getOriginalFilename|getName\\(\\)|getRealPath\\(\"/uploads\"\\)|uploadDir" --glob="*.java"
rg -n "new File\\(|Paths\\.get\\(|Path\\.of\\(|File\\.separator" --glob="*.java"

# 1.4 上传接口路由
rg -n "@PostMapping\\(|@RequestMapping\\(.*upload|/upload" --glob="*.java"
```

**输出：高危文件清单（按优先级排序）**

| 优先级 | 文件类型 | 审计重点 |
|:-------|:---------|:---------|
| P0 | `*Controller.java` / `*Servlet.java` 中包含 upload 逻辑 | MultipartFile/FileItem |
| P1 | `*Service.java`, `*ServiceImpl.java` | 文件保存路径/重命名 |
| P2 | `*Util.java`, `*Storage.java`, `*File*.java` | 通用存储封装 |
| P3 | `*Config.java`, `application.yml` | 文件大小/目录配置 |

### 阶段2: 参数-上传映射分析

**基于 route_mapper 输出，检查每个上传参数是否影响文件名或保存路径。**

#### 2.1 高危参数识别

| 参数来源 | 参数名 | 类型 | 漏洞等级 |
|:---------|:-------|:-----|:-----|
| @RequestParam | `file` | MultipartFile | **高危** - 直接上传 |
| FileItem | `item` | FileItem | **高危** - fileName 可控 |
| @RequestParam | `fileName` | String | **高危** - 文件名拼接 |
| JSON | `upload.path` | String | **高危** - 目录拼接 |

#### 2.2 参数追踪（示例）

```
HTTP 参数: file (MultipartFile)
    ↓
Controller.handleFileUpload(file)
    ↓
file.getOriginalFilename()  ← 文件名来源
    ↓
Paths.get(uploadDir).resolve(fileName)
    ↓
file.transferTo(filePath)   ← 上传写入点
```

#### 2.3 上传点检查

对每个上传写入点，检查：

1. **文件名来源是否可控？**
   - `getOriginalFilename()` / `item.getName()` → 高危
   - 服务器生成随机名 → 低危

2. **是否有路径规范化与目录限制？**
   - `getCanonicalPath()` + 固定上传目录 → 较安全
   - 直接拼接路径 → 高危

3. **是否做类型/内容校验？**
   - 白名单扩展名/Content-Type/魔数校验 → 安全
   - 仅检查非空或无校验 → 高危

4. **上传目录是否在 Web 根目录？**
   - `getRealPath("/uploads")` / `/uploads/` → 高危
   - 非 Web 可访问目录 → 较安全

### 阶段3: 深入检查与报告

当上传逻辑复杂或参数多层传递时，调用 java-route-tracer 获取完整调用链并补充校验路径分析。

---

## 上传实现识别（来自 Notion 资料的关键点）

### 1) Servlet/Commons FileUpload

**识别特征：**
- `ServletFileUpload.isMultipartContent(request)`
- `DiskFileItemFactory` / `ServletFileUpload`
- `upload.parseRequest(request)` → `List<FileItem>`
- `item.getName()` 作为文件名
- `item.write(storeFile)` 写入文件
- `getServletContext().getRealPath("/uploads")` 作为保存目录

**Notion 记录要点：**
- 示例未校验表单字段名，`name="file"` **不会被校验**。
- 仅设置了大小上限（如 `upload.setSizeMax(5MB)`），未见扩展名/类型/路径校验。

### 2) Spring Boot MultipartFile

**识别特征：**
- `@RequestParam("file") MultipartFile file`
- `file.getOriginalFilename()`
- `file.transferTo(filePath)`
- 固定上传目录 `uploadDir = "/uploads/"`

**Notion 记录要点：**
- `@RequestParam("file")` 会校验表单字段名，需要 `name="file"`。
- 示例未见文件名净化、类型白名单或目录隔离。

**详细检测规则参见** [UPLOAD_RULES.md](references/UPLOAD_RULES.md)

---

## 反编译阶段（CRITICAL）

**当源码不可用时，必须使用 CFR 反编译器反编译上传相关类（详见 `java-shared/DECOMPILE_STRATEGY.md`）。**

### 反编译工具调用

```bash
# 反编译单个上传相关类
java -jar {CFR_JAR} /path/to/UploadController.class --outputdir {output_path}/decompiled

# 反编译上传相关目录
find /path/to/WEB-INF/classes/com/example/upload -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译多个指定文件
java -jar {CFR_JAR} /path/to/UploadController.class /path/to/FileStorageService.class /path/to/UploadUtil.class --outputdir {output_path}/decompiled
```

### 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| Controller/Servlet | `*Upload*Controller.class`, `*Servlet.class` | 提取上传入口 |
| Service/Storage | `*Storage*.class`, `*FileService*.class` | 追踪保存路径 |
| 工具类 | `*UploadUtil*.class`, `*FileUtil*.class` | 查找通用校验 |
| 配置类 | `*Config*.class` | 获取上传目录/大小限制 |

**反编译输出要求：**
- 输出“反编译文件清单”，包含原始文件名与反编译输出路径
- 反编译文件路径需可定位到具体目录

---

## 执行条件分析（CRITICAL - 避免误报）

**发现上传逻辑后，必须检查该逻辑是否真的会被执行！**

| 检查项 | 说明 | 影响 |
|--------|------|------|
| 权限校验 | 仅管理员可访问 | 影响可利用性 |
| 参数校验 | 字段名/类型/大小校验 | 降低漏洞可利用性 |
| 目录限制 | 固定上传目录 | 降低路径穿越 |
| 可访问性 | 上传目录是否可 Web 访问 | 决定是否可执行 |

结论分级必须标注：✅ 已确认可利用 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖

---

## 报告生成

**输出单个综合审计报告文件：**

```
{project_name}_audit/file_upload_audit/
└── {route_name}/
    └── {project_name}_file_upload_audit_{timestamp}.md
```

**路由名说明：**
- 路由名从路由路径提取，去掉前缀斜杠和特殊字符
- 例如：`/api/file/upload` → `api_file_upload`

---

## 输出格式

**严格按照 [references/OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) 中的填充式模板生成输出文件。**

- 文件名格式: `{project_name}_file_upload_audit_{YYYYMMDD_HHMMSS}.md`
- 不得修改模板结构、不得增删章节、不得调整顺序
- 所有【填写】占位符必须替换为实际内容
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

---

## 审计检查清单（防遗漏）

### 代码分析检查
- [ ] 所有上传入口已分析（Servlet/MultipartFile）
- [ ] 每个上传点均标注文件名来源与保存路径
- [ ] 目录与访问控制已分析

### 反编译检查
- [ ] 源码不可用时已反编译
- [ ] 反编译文件清单已输出（文件名 + 位置）

### 报告完整性检查
- [ ] **综合审计报告已生成，且通过 OUTPUT_TEMPLATE.md 末尾的自检清单**

---

## 参考资料

- [OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) - 输出报告填充式模板
- [UPLOAD_RULES.md](references/UPLOAD_RULES.md) - 上传实现识别与风险规则

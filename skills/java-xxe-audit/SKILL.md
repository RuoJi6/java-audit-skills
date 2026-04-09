---
name: java-xxe-audit
description: Java Web 源码 XXE (XML External Entity) 漏洞审计工具。从源码中识别所有 XML 解析操作并检测外部实体注入漏洞。适用于：(1) 识别 XML 解析器类型和实现方式，(2) 发现 XXE 注入漏洞，(3) 检查外部实体防护配置情况，(4) 审计 XML 输入来源与回显逻辑。支持 XMLReader、SAXBuilder、SAXReader、SAXParserFactory、DocumentBuilderFactory 五种主流解析器。**支持反编译 .class/.jar 文件提取 XML 解析逻辑**。结合 java-route-mapper 使用可实现完整的路由+XXE审计。
---

# Java XXE 漏洞审计工具

检查 Java Web 项目源码，识别 XML 解析实现，检测 XXE (XML External Entity) 注入漏洞。

## 核心要求

**此技能必须完整检查所有 XML 解析相关代码，不允许省略。**

- ✅ 识别所有 XML 解析入口点（5 种解析器）
- ✅ 检查每个解析器的外部实体防护配置
- ✅ 追踪 XML 输入来源（用户可控性）
- ✅ 检测回显点（数据是否返回给用户）
- ✅ 为每个漏洞点提供验证 PoC
- ❌ 禁止省略任何 XML 解析操作
- ❌ 禁止跳过反编译步骤

---

## 漏洞分级标准

**详见 [SEVERITY_RATING.md](../java-shared/SEVERITY_RATING.md)**

- 漏洞编号格式: `{C/H/M/L}-XXE-{序号}`
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

**java-xxe-audit 必须在 java-route-mapper 之后执行，基于已梳理的路由信息进行审计。**

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
│     │ └─ Content-Type 识别（application/xml, text/xml）         │
│     │                                                           │
│     ↓                                                           │
│  [步骤2] java-xxe-audit（本技能）                               │
│     │                                                           │
│     │ 输入：java-route-mapper 的输出                            │
│     │                                                           │
│     │ 执行：                                                    │
│     │ ├─ 快速扫描 XML 解析类                                    │
│     │ ├─ 检查解析器安全配置                                     │
│     │ ├─ 追踪 XML 输入来源                                      │
│     │ └─ 检查回显路径                                           │
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
└── xxe_audit/
    └── {project_name}_xxe_audit_{timestamp}.md  ← 本技能输出
```

**如果 route_mapper 输出不存在，必须先运行：**
```python
Skill(skill="java-route-mapper", args="--project {project_path}")
```

### 从 route_mapper 获取的关键信息

| 信息 | 用途 |
|:-----|:-----|
| 路由路径 | 定位 Controller/Servlet 入口 |
| Content-Type | 识别接受 XML 输入的端点 |
| 参数来源 | 识别 getInputStream() 等原始输入 |
| 请求方法 | POST 方法更可能接受 XML Body |

---

## 工作流程（三阶段）

### 阶段1: 快速扫描（优先执行）

**目标：快速定位所有 XML 解析点和高危文件。**

```bash
# 1.1 搜索 XML 解析器创建
grep -ri "XMLReaderFactory.createXMLReader" --include="*.java"
grep -ri "new SAXBuilder" --include="*.java"
grep -ri "new SAXReader" --include="*.java"
grep -ri "SAXParserFactory.newInstance" --include="*.java"
grep -ri "DocumentBuilderFactory.newInstance" --include="*.java"

# 1.2 搜索 XML 解析执行点
grep -ri "\.parse\s*(" --include="*.java"
grep -ri "\.build\s*(" --include="*.java"
grep -ri "\.read\s*(" --include="*.java"

# 1.3 搜索 XML 输入来源
grep -ri "getInputStream" --include="*.java"
grep -ri "InputSource" --include="*.java"
grep -ri "StringReader" --include="*.java"
grep -ri "StreamSource" --include="*.java"

# 1.4 搜索安全配置（判断是否已防护）
grep -ri "disallow-doctype-decl" --include="*.java"
grep -ri "external-general-entities" --include="*.java"
grep -ri "external-parameter-entities" --include="*.java"
grep -ri "setFeature" --include="*.java"
grep -ri "setExpandEntityReferences" --include="*.java"

# 1.5 搜索其他 XML 相关类
grep -ri "TransformerFactory" --include="*.java"
grep -ri "SchemaFactory" --include="*.java"
grep -ri "XMLInputFactory" --include="*.java"
grep -ri "Unmarshaller\|JAXBContext" --include="*.java"
```

**输出：高危文件清单（按优先级排序）**

| 优先级 | 文件类型 | 审计重点 |
|:-------|:---------|:---------|
| P0 | 直接使用 `getInputStream()` + XML 解析 | 用户可控 XML 直接解析 |
| P1 | Servlet/Controller 中的 XML 处理 | HTTP 入口处的 XML 解析 |
| P2 | XML 工具类 `*XmlUtil*.java` | 通用 XML 解析方法 |
| P3 | WebService/SOAP 处理类 | SOAP XML 解析 |

### 阶段2: 解析器安全配置检查

**对阶段1发现的每个 XML 解析点，逐一检查安全配置状态。**

#### 2.1 解析器识别与配置检查

对每个解析器实例，检查是否设置了以下防护特性：

| 防护特性 | Feature URI | 作用 |
|:---------|:------------|:-----|
| 禁止 DOCTYPE | `http://apache.org/xml/features/disallow-doctype-decl` | **最严格，推荐** |
| 禁止外部通用实体 | `http://xml.org/sax/features/external-general-entities` | 禁用外部实体引用 |
| 禁止外部参数实体 | `http://xml.org/sax/features/external-parameter-entities` | 禁用参数实体 |
| 禁止外部 DTD 加载 | `http://apache.org/xml/features/nonvalidating/load-external-dtd` | 禁止加载外部 DTD |

详细检测规则参见各解析器参考文档：

| 解析器 | 参考资料 |
|--------|----------|
| XMLReader | [PARSERS.md - XMLReader 章节](references/PARSERS.md#1-xmlreader) |
| SAXBuilder (JDOM2) | [PARSERS.md - SAXBuilder 章节](references/PARSERS.md#2-saxbuilder-jdom2) |
| SAXReader (dom4j) | [PARSERS.md - SAXReader 章节](references/PARSERS.md#3-saxreader-dom4j) |
| SAXParserFactory | [PARSERS.md - SAXParserFactory 章节](references/PARSERS.md#4-saxparserfactory) |
| DocumentBuilderFactory | [PARSERS.md - DocumentBuilderFactory 章节](references/PARSERS.md#5-documentbuilderfactory) |

#### 2.2 XML 输入来源追踪

对每个 XML 解析点，追踪输入来源：

```
HTTP 请求体: request.getInputStream()
     ↓
InputSource / StringReader / StreamSource
     ↓
XMLReader.parse() / SAXBuilder.build() / SAXReader.read() / ...
     ↓
解析结果: Document / Element / Node
     ↓
回显: response.getWriter().write() / model.addAttribute() / ...
```

| 输入来源 | 用户可控性 | 风险等级 |
|:---------|:-----------|:---------|
| `request.getInputStream()` | **完全可控** | 高危 |
| `request.getParameter("xml")` | **完全可控** | 高危 |
| `@RequestBody String xml` | **完全可控** | 高危 |
| `MultipartFile.getInputStream()` | **完全可控** | 高危 |
| 数据库读取的 XML 字段 | 间接可控 | 中危 |
| 配置文件/硬编码 XML | 不可控 | 低 |

#### 2.3 回显路径检查

XXE 利用方式取决于是否有回显：

| 回显方式 | 利用类型 | 检测方法 |
|:---------|:---------|:---------|
| 解析结果写入 HTTP 响应 | **有回显 XXE** | 搜索 `response.getWriter()`, `getText()`, `getTextContent()` |
| 解析结果写入页面模型 | **有回显 XXE** | 搜索 `model.addAttribute()`, `request.setAttribute()` |
| 解析结果仅做逻辑处理 | **Blind XXE (OOB)** | 需通过外部 DTD 外带数据 |
| 解析但无任何输出 | **Blind XXE (OOB)** | 需通过外部 DTD 外带数据 |

### 阶段3: 详细检测与报告

#### 3.1 触发 java-route-tracer

当发现以下情况时，调用 java-route-tracer 获取完整调用链：

| 触发条件 | 调用方式 |
|:---------|:---------|
| XML 输入经过多层传递 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 解析器在工具类/基类中 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 回显路径不明确 | `Skill(skill="java-route-tracer", args="--route {route}")` |

#### 3.2 生成报告

整合所有检测结果，生成综合审计报告。

---

## XML 解析器识别

| 解析器 | 识别特征 | 所属包/依赖 | 参考资料 |
|--------|----------|-------------|----------|
| XMLReader | `XMLReaderFactory.createXMLReader()`, `xmlReader.parse()` | `org.xml.sax` (JDK 内置) | [PARSERS.md](references/PARSERS.md) |
| SAXBuilder | `new SAXBuilder()`, `saxBuilder.build()` | `org.jdom2` (jdom2) | [PARSERS.md](references/PARSERS.md) |
| SAXReader | `new SAXReader()`, `reader.read()` | `org.dom4j.io` (dom4j) | [PARSERS.md](references/PARSERS.md) |
| SAXParserFactory | `SAXParserFactory.newInstance()`, `.getXMLReader().parse()` | `javax.xml.parsers` (JDK 内置) | [PARSERS.md](references/PARSERS.md) |
| DocumentBuilderFactory | `DocumentBuilderFactory.newInstance()`, `builder.parse()` | `javax.xml.parsers` (JDK 内置) | [PARSERS.md](references/PARSERS.md) |

### 其他可能受 XXE 影响的组件

| 组件 | 识别特征 | 漏洞说明 |
|------|----------|----------|
| TransformerFactory | `TransformerFactory.newInstance()` | XSLT 处理可触发 XXE |
| SchemaFactory | `SchemaFactory.newInstance()` | XML Schema 验证可触发 XXE |
| XMLInputFactory (StAX) | `XMLInputFactory.newInstance()` | StAX 解析器可触发 XXE |
| JAXB Unmarshaller | `JAXBContext.newInstance()`, `unmarshaller.unmarshal()` | XML 反序列化可触发 XXE |

---

## 反编译阶段（CRITICAL）

**当源码不可用时，必须使用 CFR 反编译器反编译 XML 解析相关类。**

详细策略参见 [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md)

### 反编译工具调用

```bash
# 反编译单个 XML 处理类
java -jar {CFR_JAR} /path/to/XmlParser.class --outputdir {output_path}/decompiled

# 反编译 XML 处理相关目录
find /path/to/WEB-INF/classes/com/example/util -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled

# 反编译多个指定文件
java -jar {CFR_JAR} /path/to/XmlUtil.class /path/to/XmlParser.class /path/to/SoapHandler.class --outputdir {output_path}/decompiled
```

### 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| XML 工具类 | `*Xml*.class`, `*XML*.class`, `*Parser*.class` | 提取 XML 解析逻辑 |
| Servlet | `*Servlet.class`, `*Controller.class` | 追踪输入来源 |
| WebService | `*WebService*.class`, `*Soap*.class`, `*WS*.class` | SOAP XML 处理 |
| 过滤器 | `*Filter.class` | XML 请求预处理 |

---

## XXE 检测规则速查

### ⚠️ 危险模式（无安全配置的解析器）

| 解析器 | 危险代码 | 漏洞说明 |
|:-------|:---------|:---------|
| XMLReader | `XMLReaderFactory.createXMLReader()` 后直接 `parse()` | 未禁用外部实体 |
| SAXBuilder | `new SAXBuilder()` 后直接 `build()` | 未禁用外部实体 |
| SAXReader | `new SAXReader()` 后直接 `read()` | 未禁用外部实体 |
| SAXParserFactory | `SAXParserFactory.newInstance()` 后直接 `parse()` | 未禁用外部实体 |
| DocumentBuilderFactory | `DocumentBuilderFactory.newInstance()` 后直接 `parse()` | 未禁用外部实体 |

### ✅ 安全模式（已配置防护）

**所有解析器的安全修复方式一致——禁用 DOCTYPE 或外部实体：**

```java
// 方式1: 禁止 DOCTYPE 声明（最严格，推荐）
setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 方式2: 分别禁用外部实体
setFeature("http://xml.org/sax/features/external-general-entities", false);
setFeature("http://xml.org/sax/features/external-parameter-entities", false);
setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

### ⚠️ 输入来源检测（CRITICAL - 确认用户可控性）

**必须搜索的输入来源模式：**

```bash
# HTTP 请求体
grep -ri "getInputStream" --include="*.java"
grep -ri "getReader" --include="*.java"

# 参数传入 XML
grep -ri "getParameter.*xml\|getParameter.*XML" --include="*.java"

# Spring 注解
grep -ri "@RequestBody" --include="*.java"

# 文件上传
grep -ri "MultipartFile" --include="*.java" | grep -i "xml"

# SOAP/WebService
grep -ri "@WebService\|@WebMethod" --include="*.java"
```

---

## 数据流追踪（需要时加载 java-route-tracer）

### 何时需要参数追踪

| 场景 | 说明 | 操作 |
|------|------|------|
| XML 输入经过多层传递 | HTTP 请求体经 Controller → Service → Util 多层传递后解析 | 加载 java-route-tracer |
| 解析器在工具类中 | XML 解析在通用 XmlUtil 类中，多处调用 | 加载 java-route-tracer |
| 回显路径不明确 | 解析结果经过多次转换后输出 | 加载 java-route-tracer |
| SOAP 处理链 | WebService 请求经拦截器/处理器链 | 加载 java-route-tracer |

### 自动触发 java-route-tracer

```python
# 当需要追踪 XML 输入流向时
Skill(
    skill="java-route-tracer",
    args="--route {controller_route} --project {project_path}"
)
```

---

## 报告生成

**输出单个综合审计报告文件：**

```
{project_name}_audit/xxe_audit/
└── {route_name}/
    └── {project_name}_xxe_audit_{timestamp}.md      # 综合审计报告
```

**路由名说明：**
- 路由名从路由路径提取，去掉前缀斜杠和特殊字符
- 例如：`/api/xml/parse` → `api_xml_parse`
- 例如：`/ws/soap/endpoint` → `ws_soap_endpoint`

---

## 输出格式

**严格按照 [references/OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) 中的填充式模板生成输出文件。**

- 文件名格式: `{project_name}_xxe_audit_{YYYYMMDD_HHMMSS}.md`
- 不得修改模板结构、不得增删章节、不得调整顺序
- 所有【填写】占位符必须替换为实际内容
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

---

## 验证检查清单

**在标记审计完成前，必须执行以下检查：**

### 代码检测检查
- [ ] 所有 XML 解析类已检查
- [ ] 所有 5 种解析器类型均已搜索
- [ ] 每个解析器实例的安全配置已检查

### 输入来源检查
- [ ] 追踪了每个解析器的 XML 输入来源
- [ ] 确认了输入是否用户可控
- [ ] 检查了回显路径

### 漏洞检测检查
- [ ] 所有无防护的解析器已标记
- [ ] 所有用户可控输入已追踪
- [ ] 区分了有回显 XXE 和 Blind XXE

### 报告完整性检查
- [ ] **综合审计报告已生成，且通过 OUTPUT_TEMPLATE.md 末尾的自检清单**

---

## 参考资料

- [OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) - 输出报告填充式模板
- [PARSERS.md](references/PARSERS.md) - 五种 XML 解析器详细检测规则
- [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md) - 反编译策略指南

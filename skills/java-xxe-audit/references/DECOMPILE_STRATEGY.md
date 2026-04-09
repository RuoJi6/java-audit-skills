# XXE 审计反编译策略指南

## 目录

- [何时反编译](#何时反编译)
- [反编译工具使用](#反编译工具使用)
- [XML 解析类识别与定位](#xml-解析类识别与定位)
- [反编译结果检查](#反编译结果检查)
- [常见问题](#常见问题)

---

## 何时反编译

### 必须反编译的场景

1. **项目只有编译后的字节码**
   - WAR/JAR 包部署，无源码
   - 第三方依赖中的 XML 处理组件

2. **XML 解析类定义在 .class 文件中**
   - 自定义 XML 工具类
   - Servlet/Controller 中的 XML 处理
   - WebService/SOAP 处理器

3. **需要检查 XML 解析配置**
   - 确认是否设置了安全特性
   - 追踪解析器工厂的配置链
   - 检查自定义 EntityResolver

### 不需要反编译的场景

1. 源码已存在且可读取
2. 标准 XML 解析器框架核心类
3. Spring 配置文件可直接读取

---

## 反编译工具使用

### CFR CLI 反编译器

> 详细的 CFR 获取策略和通用调用方式参见 `java-shared/DECOMPILE_STRATEGY.md`。

#### 单个文件反编译

```bash
# 反编译单个 XML 处理类
java -jar {CFR_JAR} /path/to/WEB-INF/classes/com/example/util/XmlParser.class --outputdir {output_path}/decompiled
```

#### 目录反编译

```bash
# 递归反编译整个工具包
find /path/to/WEB-INF/classes/com/example/util -name "*.class" | xargs java -jar {CFR_JAR} --outputdir {output_path}/decompiled
```

#### 批量文件反编译

```bash
# 反编译多个 XML 相关类
java -jar {CFR_JAR} /path/to/XmlUtil.class /path/to/XmlParser.class /path/to/SoapHandler.class /path/to/XmlServlet.class --outputdir {output_path}/decompiled
```

#### 检查 Java 环境

```bash
# 检查 Java 版本
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help

# 如果 CFR 不存在，下载
curl -L -o {output_path}/cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
```

---

## XML 解析类识别与定位

### 按类名模式定位

```bash
# XML 工具类
find . -name "*Xml*.class" -o -name "*XML*.class"
find . -name "*Parser*.class" -o -name "*Parse*.class"
find . -name "*Sax*.class" -o -name "*SAX*.class"
find . -name "*Dom*.class" -o -name "*DOM*.class"

# Servlet/Controller
find . -name "*Servlet.class" -o -name "*Controller.class"

# WebService/SOAP
find . -name "*WebService*.class" -o -name "*Soap*.class" -o -name "*WS*.class"
find . -name "*Endpoint*.class" -o -name "*Handler*.class"
```

**反编译目标：**

```python
xxe_classes = [
    "*Xml*.class", "*XML*.class",
    "*Parser*.class", "*Parse*.class",
    "*Sax*.class", "*SAX*.class",
    "*Dom*.class", "*DOM*.class",
    "*Soap*.class", "*WS*.class"
]
```

### 按字节码特征定位

```bash
# 搜索包含 XML 解析器导入的 class 文件
find . -name "*.class" -exec strings {} \; | grep -l "XMLReaderFactory\|SAXBuilder\|SAXReader\|SAXParserFactory\|DocumentBuilderFactory"

# 搜索包含 InputSource 的类
find . -name "*.class" -exec strings {} \; | grep -l "org.xml.sax.InputSource"
```

### 从配置文件定位

#### Spring 配置

```xml
<!-- applicationContext.xml -->
<bean id="xmlParser" class="com.example.util.XmlParser"/>
```

**提取类路径：** `com.example.util.XmlParser`
**对应 class 文件：** `WEB-INF/classes/com/example/util/XmlParser.class`

#### web.xml Servlet 配置

```xml
<servlet>
    <servlet-name>xmlServlet</servlet-name>
    <servlet-class>com.example.servlet.XmlServlet</servlet-class>
</servlet>
```

**提取类路径：** `com.example.servlet.XmlServlet`

---

## 反编译结果检查

### 检查要点

反编译后重点关注：

```java
// 1. 解析器创建 — 确认使用了哪种解析器
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// 2. 安全特性设置 — 是否设置了防护
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);  // 有则安全

// 3. 输入来源 — XML 数据从哪来
builder.parse(new InputSource(request.getInputStream()));  // 用户可控

// 4. 结果使用 — 解析结果如何处理
String value = root.getTextContent();
response.getWriter().write(value);  // 回显到 HTTP 响应
```

### 示例检查

```java
// 反编译后的 XmlParser 示例
public class XmlParser {

    // ❌ 危险：未设置安全特性，用户输入直接解析
    public Document parseXml(InputStream inputStream) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);  // 这不能防 XXE！
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(inputStream));
    }

    // ✅ 安全：已设置防护
    public Document parseXmlSafe(InputStream inputStream) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(inputStream));
    }
}
```

**提取信息：**

| 方法 | 解析器 | 安全配置 | 漏洞判定 |
|------|--------|----------|----------|
| parseXml | DocumentBuilderFactory | ❌ 仅 setValidating(false) | **高危** |
| parseXmlSafe | DocumentBuilderFactory | ✅ disallow-doctype-decl | 安全 |

---

## 反编译策略

### 策略 1: 最小化反编译（推荐）

```python
# 只反编译与 XML 解析直接相关的类

# 步骤 1: 从配置文件和类名识别 XML 处理类
xml_classes = find_xml_classes()

# 步骤 2: 反编译 XML 相关类
for cls in xml_classes:
    decompile_file(cls)

# 步骤 3: 检查依赖，反编译调用者
callers = extract_xml_callers(xml_classes)
for caller in callers:
    decompile_file(caller)
```

### 策略 2: 层级反编译

```python
# 第一层: 反编译 XML 工具类
layer1 = ["*Xml*.class", "*Parser*.class", "*Sax*.class"]
decompile_by_pattern(layer1)

# 第二层: 反编译 Servlet/Controller（追踪输入来源）
layer2 = ["*Servlet.class", "*Controller.class", "*Action.class"]
decompile_by_pattern(layer2)

# 第三层: 反编译 WebService（SOAP 处理）
layer3 = ["*WebService*.class", "*Soap*.class", "*Endpoint*.class"]
decompile_by_pattern(layer3)
```

---

## 反编译结果记录

输出时必须标注反编译来源：

```markdown
### [XXE-001] XXE 注入 - 未防护的 DocumentBuilderFactory

| 项目 | 信息 |
|------|------|
| 漏洞等级 | 高 |
| 位置 | XmlParser.parseXml (XmlParser.java:15) |
| 来源 | **反编译 WEB-INF/classes/com/example/util/XmlParser.class** |
| 解析器 | DocumentBuilderFactory |

漏洞描述:
- DocumentBuilderFactory 未设置 disallow-doctype-decl
- 仅设置 setValidating(false)，不能防止 XXE
- 输入来源为 InputStream 参数，可能用户可控

漏洞代码:
\```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setValidating(false);
DocumentBuilder builder = factory.newDocumentBuilder();
return builder.parse(new InputSource(inputStream));
\```
```

---

## 常见问题

### 问题 1: 反编译失败

**解决方案：**
```bash
# 检查 Java 版本
java -version

# 验证 CFR 是否可用
java -jar {CFR_JAR} --help

# 如果 CFR 不存在，下载
curl -L -o {output_path}/cfr-0.152.jar "https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
```

### 问题 2: setFeature 调用被混淆

**表现：** 反编译后 Feature URI 字符串可能被拆分或混淆

**处理：** 搜索 `setFeature` 方法调用，逐一检查参数值

### 问题 3: 工厂模式封装

**表现：** XML 解析器通过工厂方法或 Spring Bean 创建

**处理：** 追踪工厂方法的实现，确认安全配置是否在工厂中设置

### 问题 4: 自定义 EntityResolver

**表现：**
```java
builder.setEntityResolver(new CustomEntityResolver());
```

**处理：** 必须反编译 `CustomEntityResolver` 类，检查是否真正阻止了外部实体加载

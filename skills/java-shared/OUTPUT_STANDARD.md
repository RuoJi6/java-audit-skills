# 统一输出规范

所有审计 Skill 共享此输出规范，确保不同 LLM 生成的报告格式一致。

---

## 硬约束声明（所有 Skill 必须遵守）

> **以下约束不可违反，任何违反都视为输出不合格：**
>
> 1. **不得增删章节** — 模板中有几个章节，输出就必须有几个章节，一个不多一个不少
> 2. **不得调整章节顺序** — 章节顺序必须与模板完全一致
> 3. **不得修改表格列** — 表格的列名和列数必须与模板完全一致
> 4. **所有【填写】占位符必须替换为实际内容** — 不得保留任何【填写】文字
> 5. **不得自由发挥添加额外章节或修改章节标题**
> 6. **不得将多个模板文件的内容合并到一个文件中输出**

---

## 1. 文件命名规则

### 1.1 命名格式

```
{project_name}_{skill_type}_{timestamp}.md
```

| 组成部分 | 规则 | 示例 |
|----------|------|------|
| `project_name` | 来自用户输入；若无则取源码根目录名；全小写、空格替换为下划线 | `my_project` |
| `skill_type` | 固定值，见下表 | `sql_audit` |
| `timestamp` | 格式: `YYYYMMDD_HHMMSS` | `20250324_143052` |

### 1.2 skill_type 枚举

| skill_type | 对应 Skill | 说明 |
|------------|-----------|------|
| `sql_audit` | java-sql-audit | SQL 注入审计报告 |
| `auth_audit` | java-auth-audit | 鉴权审计主报告 |
| `auth_mapping` | java-auth-audit | 路由-鉴权映射表 |
| `auth_README` | java-auth-audit | 鉴权审计说明文档 |
| `xxe_audit` | java-xxe-audit | XXE 审计报告 |
| `file_upload_audit` | java-file-upload-audit | 文件上传审计报告 |
| `file_read_audit` | java-file-read-audit | 文件读取审计报告 |
| `route_mapper` | java-route-mapper | 路由映射主索引 |
| `module_{name}` | java-route-mapper | 模块路由详情 |
| `ws_{name}` | java-route-mapper | Web Service 路由详情 |
| `route_README` | java-route-mapper | 路由映射说明文档 |
| `route_tracer` | java-route-tracer | 调用链追踪报告 |
| `vuln_report` | java-vuln-scanner | 组件漏洞检测报告 |

### 1.3 输出目录结构

```
{output_path}/
├── route_mapper/          # java-route-mapper 输出（含按模块划分的子目录，主索引在根目录）
├── auth_audit/            # java-auth-audit 输出
├── sql_audit/             # java-sql-audit 输出
├── xxe_audit/             # java-xxe-audit 输出
├── file_upload_audit/     # java-file-upload-audit 输出
├── file_read_audit/       # java-file-read-audit 输出
├── route_tracer/          # java-route-tracer 输出
├── vuln_report/           # java-vuln-scanner 输出
└── scripts/               # 临时脚本目录（运行时生成的脚本必须写入此目录，禁止写入临时目录）
```

---

## 2. 填充式占位符规范

### 2.1 占位符格式

使用 **【填写：说明文字】** 作为占位符，不使用 `{xxx}`。

| 写法 | 是否允许 | 原因 |
|------|----------|------|
| `【填写：项目名称】` | 允许 | 明确标记需要替换 |
| `【填写】` | 允许 | 简短场景使用 |
| `{project_name}` | 不允许 | 容易被 LLM 忽略或当作普通文本 |
| `<项目名称>` | 不允许 | 与 HTML/XML 标签混淆 |

### 2.2 占位符使用规则

1. 每个 `【填写】` 必须替换为实际内容
2. 如果某项确实无内容，填写 `无` 或 `N/A`，不得留空也不得保留占位符
3. 表格中的占位符表示该单元格必须有值

### 2.3 重复区块标记

当模板中某个区块需要重复出现时（如多个漏洞），使用：

```markdown
<!-- 以下区块按实际数量重复，每个漏洞一个区块 -->
### 【填写：漏洞编号】 【填写：漏洞标题】
...
<!-- 重复区块结束 -->
```

---

## 3. 通用报告骨架

以下是所有**漏洞审计类** Skill（sql-audit、auth-audit、xxe-audit、file-upload-audit、file-read-audit）的通用报告骨架。每个 Skill 的 OUTPUT_TEMPLATE.md 在此基础上扩展。

### 3.1 报告头部（必需）

```markdown
# 【填写：项目名称】 - 【填写：审计类型】审计报告

生成时间: 【填写：YYYY-MM-DD HH:MM:SS】
分析路径: 【填写：项目源码路径】
```

### 3.2 审计概述（必需）

```markdown
## 1. 审计概述

| 项目 | 信息 |
|------|------|
| 审计范围 | 【填写：项目源码路径】 |
| 审计框架 | 【填写：识别到的框架名称和版本】 |
| 分析方法 | 静态代码审计 + 数据流分析 |
```

### 3.3 风险统计表（必需，引用 SEVERITY_RATING.md）

```markdown
## 2. 风险统计

| 严重等级 | CVSS | 数量 | 说明 |
|----------|------|------|------|
| 🔴 C (Critical) | 9.0-10.0 | 【填写】 | 可直接导致系统沦陷 |
| 🟠 H (High) | 7.0-8.9 | 【填写】 | 可造成重大损害 |
| 🟡 M (Medium) | 4.0-6.9 | 【填写】 | 可造成一定损害 |
| 🔵 L (Low) | 0.1-3.9 | 【填写】 | 安全加固建议 |
```

### 3.4 漏洞详情区（必需，按数量重复）

```markdown
<!-- 以下区块按实际漏洞数量重复 -->
### 【填写：漏洞编号，格式 {C/H/M/L}-{TYPE}-{序号}】 【填写：漏洞标题】

| 项目 | 信息 |
|------|------|
| 严重等级 | 【填写：🔴/🟠/🟡/🔵 + Critical/High/Medium/Low + CVSS 分数】 |
| 可达性 (R) | 【填写：0-3 + 判定理由】 |
| 影响范围 (I) | 【填写：0-3 + 判定理由】 |
| 利用复杂度 (C) | 【填写：0-3 + 判定理由】 |
| 可利用性 | 【填写：✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖】 |
| 位置 | 【填写：ClassName.method (file:line)】 |
<!-- 重复区块结束 -->
```

### 3.5 审计结论（必需）

```markdown
## 审计结论

| 统计项 | 数量 |
|--------|------|
| 总检测点 | 【填写】 |
| 🔴 Critical | 【填写】 |
| 🟠 High | 【填写】 |
| 🟡 Medium | 【填写】 |
| 🔵 Low | 【填写】 |
| 安全（无漏洞） | 【填写】 |
```

---

## 4. 自检清单规范

每个 Skill 的 OUTPUT_TEMPLATE.md 末尾必须包含自检清单。自检清单格式如下：

```markdown
---

## 输出自检（生成文件后必须逐项确认）

- [ ] 文件名符合命名规则: {project_name}_{skill_type}_{YYYYMMDD_HHMMSS}.md
- [ ] 所有【填写】占位符已替换为实际内容
- [ ] 章节数量和顺序与模板一致
- [ ] 风险统计表有 C/H/M/L 四行
- [ ] 审计结论章节存在且数据与正文一致
- [ ] （各 Skill 特有检查项）
```

---

## 5. 各 Skill 输出模板位置

| Skill | 模板文件 | 输出文件数 |
|-------|---------|-----------|
| java-sql-audit | `references/OUTPUT_TEMPLATE.md` | 1 个 |
| java-auth-audit | `references/OUTPUT_TEMPLATE_MAIN.md` + `OUTPUT_TEMPLATE_MAPPING.md` + `OUTPUT_TEMPLATE_README.md` | 3 个 |
| java-xxe-audit | `references/OUTPUT_TEMPLATE.md` | 1 个 |
| java-file-upload-audit | `references/OUTPUT_TEMPLATE.md` | 1 个 |
| java-file-read-audit | `references/OUTPUT_TEMPLATE.md` | 1 个 |
| java-route-mapper | `references/OUTPUT_TEMPLATE_INDEX.md` + `OUTPUT_TEMPLATE_MODULE.md` + `OUTPUT_TEMPLATE_README.md` | N 个（按模块） |
| java-route-tracer | `references/OUTPUT_TEMPLATE_FULL.md` + `OUTPUT_TEMPLATE_SIMPLE.md` + `OUTPUT_TEMPLATE_INDEX.md` | N 个（按方法） |
| java-vuln-scanner | `references/OUTPUT_TEMPLATE.md` | 1 个 |

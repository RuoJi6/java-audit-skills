# 模块详情文件 — 填充式输出模板

> **硬约束（不可违反）：**
> 1. 不得增删章节 — 模板有 3 个章节，输出必须有 3 个章节
> 2. 不得调整章节顺序
> 3. 所有【填写】占位符必须替换为实际内容，不得保留
> 4. **必须列出该模块下所有接口，不得省略任何接口**
> 5. **每个接口必须有完整的参数结构**
> 6. 文件命名格式:
>    - 普通模块: `{project_name}_module_{module_name}_{YYYYMMDD_HHMMSS}.md`
>    - Web Service: `{project_name}_ws_{service_name}_{YYYYMMDD_HHMMSS}.md`
>
> 参考: java-shared/OUTPUT_STANDARD.md

---

## 以下为完整输出模板，直接填充生成

---

# 【填写：项目名称】 - 【填写：模块名】 模块详情

生成时间: 【填写：YYYY-MM-DD HH:MM:SS】
模块路径: 【填写：/module-context-path】

## 1. 模块概览

**上下文路径**: 【填写：如 /admin】
**框架**: 【填写：如 Struts2 + Spring MVC + CXF Web Service】

---

## 2. 接口详细列表

<!-- 按框架类型分组，每个接口一个区块 -->

### 【填写：框架类型，如 Struts2 路由 / Spring MVC 路由 / Web Service 方法】 (namespace: 【填写：namespace】)

<!-- 以下区块按实际接口数量重复 -->

=== [【填写：序号】] 【填写：接口标识，如 user_login.action / GET /api/users】 ===
位置: 【填写：ClassName.method (源文件路径:行号)】
HTTP 方法: 【填写：GET / POST / PUT / DELETE】
URL 路径: 【填写：完整 URL 路径】
Content-Type: 【填写：如 application/x-www-form-urlencoded / application/json / text/xml】

参数结构:
  【填写：按 Path / Query / Body / Header / Cookie 分类列出所有参数及其类型】

<!-- 重复区块结束 -->
<!-- 如有多个 namespace 或框架类型，重复上述分组结构 -->

---

## 3. 模块统计

| 统计项 | 数量 |
|--------|------|
| 总接口数 | 【填写】 |
| Struts2 路由 | 【填写；若无填 0】 |
| Spring MVC 路由 | 【填写；若无填 0】 |
| Web Service 方法 | 【填写；若无填 0】 |
| JAX-RS 路由 | 【填写；若无填 0】 |
| Servlet 路由 | 【填写；若无填 0】 |

---

## 输出自检（生成文件后必须逐项确认）

- [ ] 文件名符合命名规则
- [ ] 所有【填写】占位符已替换为实际内容
- [ ] 该模块下所有接口都已列出，无遗漏
- [ ] 每个接口都有完整的参数结构（按 Path/Query/Body/Header/Cookie 分类）
- [ ] 每个接口都有位置信息（ClassName.method + 文件路径 + 行号）
- [ ] Web Service 接口的 URL 来自配置文件的 address 属性（非推断）
- [ ] "3. 模块统计"的数字与实际列出的接口数一致
- [ ] 章节数量为 3 个，顺序与模板一致

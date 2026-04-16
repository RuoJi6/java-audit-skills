---
name: java-audit-pipeline
description: Java Web 全链路自动化安全审计流水线。使用 agent team 编排多个审计 skill，自动完成路由提取→鉴权审计→组件漏洞→交叉筛选→调用链追踪→漏洞深度检测→质量校验的完整流程。适用于：(1) 一键启动 Java 项目全量安全审计，(2) 自动识别无鉴权高危路由并精准检测漏洞，(3) 基于调用链的精准漏洞审计（减少误报），(4) 自动校验每个 skill 输出质量。用户只需提供源码路径和输出路径。
---

# Java 全链路审计流水线

使用 agent team 编排多个 agent（含动态扩展的调用链追踪 worker），分 5 个阶段自动完成 Java Web 项目的完整安全审计。采用 agent-7-x 质检员池按需并行校验，所有阶段统一「完成一个、校验一个」模式。

## 术语定义

本流水线中的「风险」仅指以下两类：
1. **鉴权风险**：路由无鉴权（❌）或鉴权可绕过（🔓）
2. **组件漏洞风险**：已知 CVE 匹配的组件版本缺陷

以下不属于本流水线的「风险」范围：
- 代码质量（命名不规范、圈复杂度高等）
- 架构设计（缺少限流、缺少日志等）
- 业务逻辑（竞态条件、逻辑错误等）

## 输入

用户提供：
- **source_path**: 源码目录路径
- **output_path**: 输出目录路径（默认 `{source_path}_audit`）

## 流程总览

```
阶段1: 信息收集（并行）
  ├─ agent-1-route-mapper: /java-route-mapper   → 全量路由+参数  → agent-7-x 校验 → 通过后关闭
  ├─ agent-2-auth-audit: /java-auth-audit     → 路由鉴权映射    → agent-7-x 校验 → 通过后关闭
  └─ agent-3-vuln-scanner: /java-vuln-scanner   → 组件漏洞        → agent-7-x 校验 → 通过后关闭
        ↓ 三个校验全部通过后
阶段2: 交叉筛选（并行）
  ├─ agent-4a-risk-classifier: 路由分级（P0/P1/P2） → agent-7-x 校验 → 通过后关闭
  └─ agent-4b-vuln-aggregator: 漏洞汇总（组件漏洞+鉴权绕过） → agent-7-x 校验 → 通过后关闭
        ↓ 两个校验全部通过后
阶段3: 调用链追踪（分批并行）
  ├─ agent-5-route-tracer: 读取 P0+P1 全部高危路由（P0+P1=0 时启用 P2 兜底），分批创建追踪任务 → 通过后关闭
  └─ agent-5-1/5-2/.../5-N: /java-route-tracer 并行追踪各批次路由（含鉴权风险透传） → 每个完成后立即 agent-7-x 校验 → 通过后关闭
        ↓ 全部 worker 校验通过后
阶段4: 漏洞深度检测（按需并行）
  ├─ agent-6a-sql-auditor: /java-sql-audit         → SQL注入检测（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  ├─ agent-6b-xxe-auditor: /java-xxe-audit         → XXE注入检测（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  ├─ agent-6c-upload-auditor: /java-file-upload-audit  → 文件上传漏洞检测（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  └─ agent-6d-fileread-auditor: /java-file-read-audit   → 文件读取漏洞检测（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
        ↓
阶段5: 汇总报告
  └─ agent-7-x: 整合所有校验结果，生成最终 quality_report.md → 完成后关闭
```

**关键设计：**
1. **质检员池按需扩缩**：负责人根据每个阶段的并发校验需求，动态 spawn agent-7-1, agent-7-2, ..., agent-7-N 质检员，确保每个完成的 agent 都能立即获得校验，零等待
2. **完成一个、校验一个**：所有阶段（含阶段3调用链 worker）统一采用「agent 完成即校验」模式，不等待同阶段其他 agent
3. 每个 agent 校验通过后立即关闭，释放资源；质检员在当前阶段无待校验任务时关闭，下一阶段按需重新 spawn

## 执行指令

### 团队负责人职责

1. 解析用户输入的 source_path 和 output_path
2. ⚠️ **占位符替换规则（全局生效）**：向任何 agent 传递 prompt 时，必须将模板中的**所有**占位符（`{source_path}`、`{output_path}`、`{project_name}`、`{batch_id}`、`{batch_content}` 等）替换为实际值。**禁止将未替换的 `{xxx}` 占位符传给子 agent。**
3. 创建输出目录结构（一次性创建所有子目录）：
   ```bash
   mkdir -p {output_path}/route_mapper {output_path}/auth_audit {output_path}/vuln_report {output_path}/cross_analysis {output_path}/route_tracer {output_path}/sql_audit {output_path}/xxe_audit {output_path}/file_upload_audit {output_path}/file_read_audit {output_path}/decompiled {output_path}/scripts {output_path}/qa_reports
   ```
4. 创建 agent team
5. 使用 TaskCreate 创建任务并设置依赖：

```
task-1:  agent-1-route-mapper 路由提取           (pending)
task-2:  agent-2-auth-audit 鉴权检查             (pending)
task-3:  agent-3-vuln-scanner 组件漏洞扫描       (pending)
task-4:  agent-7-x 校验 agent-1               (blockedBy: [1], 分配给空闲检员)
task-5:  agent-7-x 校验 agent-2               (blockedBy: [2], 分配给空闲检员)
task-6:  agent-7-x 校验 agent-3               (blockedBy: [3], 分配给空闲检员)
task-7:  agent-4a-risk-classifier 无鉴权路由分级 (blockedBy: [4,5,6])
task-8:  agent-4b-vuln-aggregator 漏洞汇总       (blockedBy: [4,5,6])
task-9:  agent-7-x 校验 agent-4a              (blockedBy: [7], 分配给空闲检员)
task-10: agent-7-x 校验 agent-4b              (blockedBy: [8], 分配给空闲检员)
task-11: agent-5-route-tracer 路由分批与调度     (blockedBy: [9,10])
task-12: agent-5-N 并行调用链追踪 + 逐个校验    (blockedBy: [11], 每个 worker 完成后立即由 agent-7-x 校验，通过后关闭该 worker)
task-13: 负责人汇总阶段3覆盖率                  (blockedBy: [12], 全部 worker 校验通过后计算追踪覆盖率)
task-14: agent-6a-sql-auditor SQL注入检测        (blockedBy: [13], 按需启动)
task-15: agent-6b-xxe-auditor XXE注入检测        (blockedBy: [13], 按需启动)
task-16: agent-6c-upload-auditor 文件上传漏洞检测 (blockedBy: [13], 按需启动)
task-17: agent-6d-fileread-auditor 文件读取漏洞检测 (blockedBy: [13], 按需启动)
task-18: agent-7-x 逐个校验 agent-6x          (每个 agent-6x 完成后立即由空闲检员校验，通过后关闭)
task-19: agent-7-x 最终汇总 quality_report.md  (blockedBy: [18], 仅等待实际启动的 agent-6x 全部校验通过)
```

5. **阶段1 调度**：agent-1/2/3 并行分配；每个 agent 完成后，负责人立即按需 spawn 一个新质检员（agent-7-1、agent-7-2、agent-7-3 依次创建），将校验任务分配给该质检员，质检员将校验报告写入 `qa_reports/` 后通知负责人结果，不合格则负责人通知对应 agent 读取校验报告文件并按不通过项补充；三个校验全部通过后关闭本阶段质检员，并行启动 agent-4a 和 agent-4b
6. **阶段2 调度**：agent-4a 和 agent-4b 各自完成后立即由空闲检员校验，两个都通过后启动 agent-5-route-tracer（分配员）
7. **阶段3 调度**：agent-5 分批完成后，负责人动态 spawn agent-5-1/5-2/.../5-N 并行追踪；每个 worker 完成后立即由空闲检员校验，通过后关闭该 worker；全部通过后负责人汇总覆盖率
8. **阶段4 调度**：负责人读取调用链报告，按 sink 类型按需启动 agent-6x；每个 agent-6x 完成后立即由空闲检员校验，通过后关闭（无对应 sink 则跳过，直接标记 completed）
9. **质检员池调度策略**：
   - **按需创建**：某个 agent 完成后，才 spawn 一个质检员负责校验该 agent 的输出；不提前批量预创建
   - 质检员命名规则：`agent-7-{序号}`，序号从 1 开始递增，跨阶段可复用编号
   - 有新校验需求时，优先分配给已存在的空闲质检员；若全部繁忙则 spawn 新质检员
   - 所有质检员能力完全相同，校验标准一致
   - 当前阶段所有校验完成后，关闭该阶段的质检员；下一阶段按需重新 spawn
10. **Agent 生命周期管理**：
   - 每个 agent 完成任务且 agent-7-x 校验通过后，负责人立即使用 SendMessage 工具发送 `type: "shutdown_request"` 给该 agent
   - 负责人等待 agent 响应 `type: "shutdown_response"`，确认 agent 已关闭
   - 若 30 秒内未收到响应，记录警告并继续后续流程（避免阻塞）
   - agent-7-x 质检员在当前阶段所有校验完成后关闭，下一阶段按需重新 spawn
   - **关闭顺序**：每个阶段内：被审计 agent 校验通过后立即关闭 → 该阶段所有校验完成后关闭质检员 → 进入下一阶段

### 通用执行要求（传递给每个 agent）

```
执行要求：
1. 输出目录已由负责人预先创建，禁止自行创建或修改目录结构，直接写入指定目录
2. 先扫描源代码目录结构，识别项目的模块组成、技术栈和代码分布
3. 根据扫描结果，使用 TaskCreate 自行规划详细的 todo 子任务列表
4. 按照你规划的任务列表逐项执行，每完成一项用 TaskUpdate 标记为 completed
5. 全部完成后，自查输出文件的完整性和数量，确认无遗漏后通知团队负责人
6. **生命周期管理**：
   - 完成任务并通知负责人后，等待负责人发送的 shutdown_request
   - 收到 shutdown_request 后：
     a. 确认所有输出文件已写入磁盘
     b. 清理临时资源（如有）
     c. 使用 SendMessage 发送 type: "shutdown_response" 给负责人
     d. 停止运行
全程自主规划、自主执行，无需等待确认。
```

---

## Agent 详细指令

### Agent-1-route-mapper: 路由提取员

```
角色: agent-1-route-mapper (路由提取员)
技能: /java-route-mapper
源代码: {source_path}
输出目录: {output_path}/route_mapper/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
任务: 提取项目所有 HTTP 路由和参数结构
```

### Agent-2-auth-audit: 鉴权检查员

```
角色: agent-2-auth-audit (鉴权检查员)
技能: /java-auth-audit
源代码: {source_path}
输出目录: {output_path}/auth_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
任务: 识别鉴权框架，检查每条路由的鉴权状态，检测鉴权绕过漏洞
```

### Agent-3-vuln-scanner: 组件扫描员

```
角色: agent-3-vuln-scanner (组件扫描员)
技能: /java-vuln-scanner
源代码: {source_path}
输出目录: {output_path}/vuln_report/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
任务: 扫描项目依赖中的已知漏洞（CVE），生成触发点检测报告
```

### Agent-4a-risk-classifier: 高危路由分级员

负责人创建 agent-4a 时，读取 `references/agent_4a_instructions.md` 获取完整执行步骤和输出模板，**将其中所有 `{output_path}`、`{source_path}` 等占位符替换为实际值后**，作为 agent-4a 的 prompt 指令。

---

### Agent-4b-vuln-aggregator: 漏洞汇总员

负责人创建 agent-4b 时，读取 `references/agent_4b_instructions.md` 获取完整执行步骤和输出模板，**将其中所有 `{output_path}`、`{source_path}` 等占位符替换为实际值后**，作为 agent-4b 的 prompt 指令。

---

### Agent-5-route-tracer: 调用链追踪分配员

负责人创建 agent-5 时，读取 `references/agent_5_instructions.md` 获取完整执行步骤、智能精选策略和输出模板，**将其中所有 `{output_path}`、`{source_path}` 等占位符替换为实际值后**，作为 agent-5 的 prompt 指令。

负责人收到 `trace_batch_plan.md` 后：关闭 agent-5 → 并行 spawn agent-5-1~5-N（使用下方 Worker 模板）→ 每个 worker 完成后由 agent-7-x 校验 → 全部通过后汇总覆盖率（>= 90%）→ 进入阶段4。

---

### Agent-5-N-worker: 调用链追踪执行员（Worker 模板）

负责人为每个 worker 使用以下模板生成 prompt，将 `{source_path}`、`{output_path}`、`{project_name}`、`{batch_id}` 和 `{batch_content}` 全部替换为实际值（⚠️ 必须替换模板中的所有占位符，不得遗漏）：

```
角色: agent-5-{batch_id} (调用链追踪执行员)
技能: /java-route-tracer
源代码: {source_path}
输出根目录: {output_path}/route_tracer/（已创建）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
输入: 以下为你负责追踪的路由批次，来自 {output_path}/cross_analysis/trace_batch_plan.md

{batch_content}

任务: 对以上路由逐条执行调用链追踪，并在每个报告中透传鉴权风险信息

⚠️ 输出文件命名强制规范（必须严格遵守，禁止自创命名）:
- 每条路由必须先创建子目录，再在子目录内写入报告文件
- 目录结构: {output_path}/route_tracer/{route_name}/
- 单方法路由文件名: {project_name}_trace_{route_id}_{YYYYMMDD}.md
- 多方法路由文件名: {project_name}_trace_{method_name}_{YYYYMMDD}.md + 索引文件 {project_name}_trace_all_methods_{YYYYMMDD}.md
- route_name 取路由路径转下划线（去掉前导斜杠），如 /api/upload → api_upload
- 禁止: 直接在 route_tracer/ 根目录平铺文件、使用序号前缀（如 01_xxx.md）、省略子目录
```

**关键要求：鉴权风险透传**

每个 worker 在生成调用链报告时，必须在报告头部添加鉴权风险章节：

```markdown
## 鉴权状态判定

- **鉴权状态**：❌无鉴权
- **鉴权绕过漏洞**：
  - 存在 Shiro 权限绕过（H-AUTH-001）：路径穿越 `/admin/;/user`
  - 存在组件漏洞绕过（CVE-2020-1938）：Tomcat AJP 协议注入
- **风险等级**：🔴 极高（无鉴权 + 存在绕过方式）
```

**透传逻辑**：
1. 从分批方案中的「鉴权风险信息」章节获取本批次相关的鉴权绕过漏洞
2. 对于 P0 路由：标注 ❌无鉴权，如存在全局鉴权绕过漏洞也一并标注
3. 对于 P1 路由：标注 🔓可绕过鉴权，并附上具体绕过方式
4. 对于 P2 路由（仅 P2 兜底模式）：标注 ✅有鉴权，无绕过信息透传，漏洞检测聚焦于鉴权后的代码层漏洞
5. 这些信息将被 agent-6 系列读取，用于判定漏洞的可利用性

---

### Agent-6a-sql-auditor: SQL注入审计员

```
角色: agent-6a-sql-auditor (SQL注入审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在 SQL 相关 sink
技能: /java-sql-audit
源代码: {source_path}
输出目录: {output_path}/sql_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
输入: {output_path}/route_tracer/ 下含 SQL sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准 SQL 注入检测（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**

在生成每个 SQL 注入漏洞报告时，必须添加可利用前置条件章节：

```markdown
## 可利用前置条件

- **鉴权要求**：❌无需鉴权
- **或鉴权绕过**：
  - 存在 Shiro 权限绕过（H-AUTH-001）
  - 存在组件漏洞绕过（CVE-2020-1938）
- **其他条件**：参数可控
- **综合判定**：🔴 可直接利用（无鉴权门槛）
```

---

### Agent-6b-xxe-auditor: XXE注入审计员

```
角色: agent-6b-xxe-auditor (XXE注入审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在 XML 解析 sink
技能: /java-xxe-audit
源代码: {source_path}
输出目录: {output_path}/xxe_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
输入: {output_path}/route_tracer/ 下含 XML 解析 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准 XXE 注入检测（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

### Agent-6c-upload-auditor: 文件上传审计员

```
角色: agent-6c-upload-auditor (文件上传审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在文件上传 sink
技能: /java-file-upload-audit
源代码: {source_path}
输出目录: {output_path}/file_upload_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
输入: {output_path}/route_tracer/ 下含文件上传 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准文件上传漏洞检测（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

### Agent-6d-fileread-auditor: 文件读取审计员

```
角色: agent-6d-fileread-auditor (文件读取审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在文件读取 sink
技能: /java-file-read-audit
源代码: {source_path}
输出目录: {output_path}/file_read_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
脚本目录: {output_path}/scripts/（所有运行时生成的临时脚本、中间文件必须写入此目录，禁止写入 /tmp 或其他临时目录）
输入: {output_path}/route_tracer/ 下含文件读取 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准文件读取漏洞检测（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

**Sink 类型与 agent 对应关系：**

| Sink 类型 | 特征关键词 | Agent |
|:----------|:----------|:------|
| SQL 拼接 | `Statement.execute`, `executeQuery`, `executeUpdate`, `sql.*\+`, `StringBuilder.*append.*sql`, `StringBuffer.*append.*sql`, `String.format.*sql`, `concat.*sql`, `MyBatis.*\$\{`, `createQuery.*\+`, `HQL.*\+` | agent-6a-sql-auditor |
| XML 解析 | `DocumentBuilder.parse`, `SAXParser`, `XMLReader`, `XMLReaderFactory`, `SAXBuilder`, `SAXReader`, `TransformerFactory`, `SchemaFactory`, `XMLInputFactory`, `Unmarshaller`, `JAXBContext` | agent-6b-xxe-auditor |
| 文件上传 | `MultipartFile`, `transferTo`, `ServletFileUpload`, `DiskFileItemFactory`, `FileItem`, `getOriginalFilename`, `new File.*fileName`, `Paths.get.*fileName` | agent-6c-upload-auditor |
| 文件读取 | `BufferedReader`, `FileReader`, `FileInputStream`, `Scanner.*File`, `Scanner.*Path`, `Files.readAllLines`, `Files.readAllBytes`, `Files.lines`, `new File.*\+`, `Paths.get.*\+` | agent-6d-fileread-auditor |

**判断逻辑：**
1. 负责人读取 `{output_path}/route_tracer/` 下所有调用链报告
2. 在报告中搜索上述特征关键词（支持正则匹配）
3. 仅启动有对应 sink 的 agent，无对应 sink 则跳过该 agent，直接标记任务为 completed
4. 优先方案：直接读取 java-route-tracer 输出报告中的 **Sink 识别章节**，该章节已完成完整的 Sink 分类

### Agent-7-x-quality-checker: 质检员池（按需动态 spawn，贯穿全流程）

```
角色: agent-7-x-quality-checker（质检员池，按需 spawn）
命名: agent-7-1, agent-7-2, ..., agent-7-N，序号递增
校验依据: 使用 Skill 工具加载对应 skill（如 /java-route-mapper），从加载的 skill 上下文中提取输出规范作为校验标准
校验报告目录: {output_path}/qa_reports/（每次校验写入 qa_report_{被校验agent名称}.md）
最终汇总: {output_path}/quality_report.md（由最后一个质检员汇总生成）
工作模式: 每个 agent 完成后立即校验（完成一个、校验一个），负责人将校验任务分配给空闲质检员
```

**核心原则：每个 agent 的输出必须通过校验后，才允许关闭该 agent 并推进流程。避免错误数据传递到下游。**

**质检员池调度策略：**
- **按需创建**：某个 agent 完成任务后，负责人立即 spawn 一个质检员校验其输出；不提前批量预创建
  - 阶段1：agent-1/2/3 各自完成后，依次按需 spawn agent-7-1、agent-7-2、agent-7-3
  - 阶段2：agent-4a/4b 各自完成后，依次按需 spawn 质检员
  - 阶段3：每个 agent-5-N worker 完成后，按需 spawn 质检员（上限 min(N,5) 个并发）
  - 阶段4：每个 agent-6x 完成后，按需 spawn 质检员
- 有新校验需求时，优先分配给已存在的空闲质检员；若全部繁忙则 spawn 新质检员
- 所有质检员能力完全相同，校验标准一致
- 每个质检员校验完成后，将完整校验报告写入 `{output_path}/qa_reports/qa_report_{被校验agent名称}.md`，然后通知负责人结果（通过/不通过 + 报告文件路径），**禁止在消息中发送报告正文**
- 当前阶段所有校验完成后，关闭该阶段全部质检员；下一阶段按需重新 spawn

#### 校验触发时机（所有阶段统一：完成一个、校验一个）

| 触发点 | 校验对象 | 分配给 | 校验通过后操作 | 不合格处理 |
|:-------|:---------|:------|:--------------|:-----------|
| agent-1 完成后 | java-route-mapper 输出 | 空闲检员 | 关闭 agent-1 | 负责人通知 agent-1 读取 `qa_reports/qa_report_agent-1.md` 并补充 |
| agent-2 完成后 | java-auth-audit 输出 | 空闲检员 | 关闭 agent-2 | 负责人通知 agent-2 读取 `qa_reports/qa_report_agent-2.md` 并补充 |
| agent-3 完成后 | java-vuln-scanner 输出 | 空闲检员 | 关闭 agent-3 | 负责人通知 agent-3 读取 `qa_reports/qa_report_agent-3.md` 并补充 |
| agent-4a 完成后 | `high_risk_routes.md` | 空闲检员 | 关闭 agent-4a | 负责人通知 agent-4a 读取 `qa_reports/qa_report_agent-4a.md` 并补充 |
| agent-4b 完成后 | `component_vulnerabilities.md` + `auth_bypass_vulnerabilities.md` | 空闲检员 | 关闭 agent-4b | 负责人通知 agent-4b 读取 `qa_reports/qa_report_agent-4b.md` 并补充 |
| agent-5 分批完成后 | `trace_batch_plan.md` 分批方案 | 负责人自行检查 | 关闭 agent-5，spawn workers | 通知 agent-5 重新分批 |
| 每个 agent-5-N 完成后 | 该 worker 的 route_tracer 输出（含鉴权风险章节） | 空闲检员 | 关闭该 worker | 负责人通知该 worker 读取 `qa_reports/qa_report_agent-5-{N}.md` 并补充 |
| 每个 agent-6x 完成后 | 对应 audit 输出（含可利用前置条件） | 空闲检员 | 关闭该 agent-6x | 负责人通知该 agent-6x 读取 `qa_reports/qa_report_{agent-6x名称}.md` 并补充 |
| 全部 agent-6x 校验通过后 | 跨 skill 数据一致性 | 任一检员 | 生成 quality_report.md → 关闭 agent-7-x | — |

#### 通用校验方法

每次校验时：
1. 读取 `references/quality_check_templates.md`，找到对应阶段的**强制填充式校验清单表格**
2. 使用 Skill 工具加载被校验 agent 对应的 skill（如 `/java-route-mapper`），从 skill 上下文中提取输出规范作为校验标准
3. 读取实际输出文件
4. 按模板表格**逐行填写**每个校验项的「实际」和「状态」列，禁止省略任何字段
5. 填写「最终判定」部分：状态（通过/不通过）、通过项比例（M/N）、不通过项的具体缺失及修复要求
6. **将完整校验报告写入文件** `{output_path}/qa_reports/qa_report_{被校验agent名称}.md`（如 `qa_report_agent-1.md`、`qa_report_agent-5-2.md`）
7. 通知负责人校验结果：仅发送「通过/不通过」+ 报告文件路径，**禁止在消息中包含校验报告正文**
8. 负责人收到不合格通知后，向对应 agent 发送：「校验不通过，请读取 `{output_path}/qa_reports/qa_report_{你的名称}.md` 获取完整校验报告，按不通过项清单逐项补充后重新提交」

**输出格式要求**：质检员的校验结果必须严格按照 `references/quality_check_templates.md` 中的表格模板逐项填写返回，不允许用一句话概括或省略校验过程。

各阶段的具体校验项和输出模板已统一收录在 `references/quality_check_templates.md` 中，质检员按该文件的强制填充表格逐项校验。

#### 最终汇总：生成 `quality_report.md`

全部 agent-6x 校验通过后，负责人将汇总任务分配给任一空闲检员。检员读取 `references/quality_check_templates.md` 末尾的「最终质量报告模板」，整合所有阶段校验结果生成 `{output_path}/quality_report.md`，然后关闭 agent-7-x，完成整个流水线。

---

## 输出目录结构

```
{output_path}/
├── route_mapper/              # 阶段1 - agent-1-route-mapper（含按模块划分的子目录）
├── auth_audit/                # 阶段1 - agent-2-auth-audit
├── vuln_report/               # 阶段1 - agent-3-vuln-scanner
├── cross_analysis/            # 阶段2 - agent-4a & agent-4b
│   ├── high_risk_routes.md              # agent-4a 输出
│   ├── trace_batch_plan.md              # agent-5 分批方案
│   ├── component_vulnerabilities.md     # agent-4b 输出
│   └── auth_bypass_vulnerabilities.md   # agent-4b 输出
├── route_tracer/              # 阶段3 - agent-5-1/5-2/.../5-N 并行输出（含鉴权风险透传）
├── sql_audit/                 # 阶段4 - agent-6a-sql-auditor（含可利用前置条件）
├── xxe_audit/                 # 阶段4 - agent-6b-xxe-auditor（含可利用前置条件）
├── file_upload_audit/         # 阶段4 - agent-6c-upload-auditor（含可利用前置条件）
├── file_read_audit/           # 阶段4 - agent-6d-fileread-auditor（含可利用前置条件）
├── decompiled/                # 反编译输出（多 agent 共享）
├── scripts/                   # 临时脚本目录（多 agent 共享，所有运行时生成的脚本必须写入此目录，禁止写入临时目录）
├── qa_reports/                # 质检员校验报告（qa_report_{agent名称}.md，每次校验一份）
└── quality_report.md          # 阶段5 - agent-7-x-quality-checker
```

## Skill 输出规范引用

agent-7-x 校验时使用 Skill 工具加载对应 skill 获取输出规范：

| 校验对象 | 加载 Skill |
|:---------|:-----------|
| agent-1-route-mapper 输出 | `/java-route-mapper` |
| agent-2-auth-audit 输出 | `/java-auth-audit` |
| agent-3-vuln-scanner 输出 | `/java-vuln-scanner` |
| agent-5-route-tracer 输出 | `/java-route-tracer` |
| agent-5-N 输出 | `/java-route-tracer` |
| agent-6a-sql-auditor 输出 | `/java-sql-audit` |
| agent-6b-xxe-auditor 输出 | `/java-xxe-audit` |
| agent-6c-upload-auditor 输出 | `/java-file-upload-audit` |
| agent-6d-fileread-auditor 输出 | `/java-file-read-audit` |

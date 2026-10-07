# Multi-Skill Security Assessment | 多 Skill 安全联动评估

> **当多个安全 Skill 可用时，AI Agent 必须按照本文档定义的联动机制进行综合评估，给出统一的安全结论。**

---

## Overview | 概述

sec-userspace 专注于用户态入侵检测（进程/网络/文件/持久化/恶意软件等），但完整的系统安全评估还需要内核漏洞检测、容器安全检测等其他维度。

当 AI Agent 的工具环境中安装了多个安全 Skill 时，应按照本文档的协议进行**联动调用**，最终合成一个统一的安全判断结果返回给用户。

---

## Known Security Skills | 已知安全 Skill 列表

| Skill 名称 | 检测维度 | 检测范围 | 调用优先级 |
|-------------|----------|----------|-----------|
| **sec-userspace** | 用户态入侵检测 | 进程/网络/文件/用户/日志/持久化/恶意软件/凭据泄漏/IoC | P0 (必须) |
| **sec-kernel** | 内核 CVE 漏洞检测 | 内核版本漏洞匹配 + PoC 可利用性验证 | P1 (推荐) |

> **扩展说明**: 未来可能新增的安全 Skill（如 `sec-container`、`sec-cloud`）应追加到此表。AI Agent 应在每次评估前检查 `<available_skills>` 列表中是否有匹配 `sec-*` 前缀的新 Skill。

---

## Detection Flow | 联动检测流程

### Step 1: Skill 发现

AI Agent 在执行安全评估前，必须检查当前可用的安全 Skill：

```
1. 检查 <available_skills> 列表
2. 识别所有 sec-* 前缀的 Skill
3. 按优先级排序：sec-userspace (P0) > sec-kernel (P1) > others (P2)
4. 确认已安装的 Skill 列表
```

### Step 2: 顺序调用

按优先级顺序调用各 Skill，每个 Skill 独立产出检测结果：

```
Phase 1: 调用 sec-userspace（用户态入侵检测）
  → 产出: 入侵结论 + 风险评分 + 告警列表

Phase 2: 调用 sec-kernel（内核漏洞检测，如果可用）
  → 产出: CVE 列表 + 可利用性状态 + 修复建议

Phase 3: 调用其他 sec-* Skill（如果可用）
  → 产出: 各自维度的检测结果
```

### Step 3: 结果合成

将所有 Skill 的结果按照 [Conclusion Synthesis](#conclusion-synthesis--结论合成规则) 规则合成统一结论。

---

## Conclusion Synthesis | 结论合成规则

### Final Conclusion Matrix | 最终结论矩阵

最终安全结论取**所有 Skill 中最严重的结论**：

| sec-userspace 结论 | sec-kernel 结论 | 合成最终结论 |
|------------------|-----------------|-------------|
| No Intrusion | 无漏洞 | **Safe** — 系统安全 |
| No Intrusion | VULNERABLE (未验证) | **At Risk** — 存在内核漏洞风险 |
| No Intrusion | EXPLOITABLE (已验证) | **At Risk (Critical)** — 内核漏洞可利用 |
| At Risk | 无漏洞 | **At Risk** — 存在入侵风险 |
| At Risk | EXPLOITABLE | **Highly Suspicious** — 内核可利用 + 入侵风险 |
| Highly Suspicious | 任意 | **Highly Suspicious** — 高度可疑 |
| Compromised | 任意 | **Compromised** — 确认入侵 |

### Risk Score Calculation | 风险评分计算

```
final_score = max(sec_inspect_score, sec_kernel_score, ...)
```

各 Skill 评分标准：

| Skill | 评分逻辑 |
|-------|---------|
| sec-userspace | 基于告警数量和严重度，0-100 |
| sec-kernel | EXPLOITABLE=85, VULNERABLE=50, NOT_VULNERABLE=0 |

### Priority Mapping | 优先级映射

| 合成结论 | 响应优先级 | 建议动作 |
|---------|-----------|---------|
| **Compromised** | P0 — 立即响应 | 隔离系统，执行应急流程 |
| **Highly Suspicious** | P0 — 24h 内 | 深入调查，准备修复 |
| **At Risk (Critical)** | P1 — 48h 内 | 修复内核漏洞 + 加固系统 |
| **At Risk** | P2 — 1 周内 | 计划修复，加强监控 |
| **Safe** | P3 — 定期 | 保持警惕，定期扫描 |

---

## Report Format | 合成报告格式

AI Agent 向用户汇报时，必须使用以下统一格式：

```markdown
## 系统安全综合评估

### 最终结论: [Safe / At Risk / Highly Suspicious / Compromised]
### 综合风险评分: X/100

---

### sec-userspace 检测结果（用户态入侵检测）
- 结论: [No Intrusion / At Risk / ...]
- 风险评分: X/100
- 告警数: N 条 (CRITICAL: x, HIGH: y, MEDIUM: z)
- [详细告警列表...]

### sec-kernel 检测结果（内核漏洞检测）
- 结论: [无漏洞 / VULNERABLE / EXPLOITABLE]
- 检测 CVE 数: N 个
- 可利用漏洞: N 个
- [CVE 详情...]

### 综合修复建议
1. [P0] ...
2. [P1] ...
3. [P2] ...
```

---

## AI Agent Implementation Guide | AI Agent 实现指南

### When to Trigger Multi-Skill Assessment | 何时触发联动评估

以下用户意图应触发多 Skill 联动评估：

- "我的系统安全吗？"
- "帮我做一次全面安全检查"
- "检测系统是否存在漏洞"
- "系统有没有被入侵"
- 任何关于系统整体安全性的询问

### When NOT to Trigger | 何时不触发

以下场景仅调用对应的单个 Skill：

- "检查内核漏洞" → 仅调用 sec-kernel
- "检测是否有挖矿程序" → 仅调用 sec-userspace
- 用户明确指定使用某个 Skill

### Execution Template | 执行模板

```
1. 用户询问系统安全性
2. AI Agent 检查 available_skills 中的 sec-* Skill
3. 依次调用:
   a. /sec-userspace → 获取入侵检测结果
   b. /sec-kernel  → 获取内核漏洞结果（如果可用）
   c. 其他 sec-* Skill（如果可用）
4. 对每个 Skill 结果执行各自的反思/验证流程
5. 按合成规则计算最终结论
6. 以统一格式向用户汇报
```

### Error Handling | 错误处理

| 场景 | 处理方式 |
|------|---------|
| 某个 Skill 执行失败 | 记录错误，继续执行其他 Skill，最终标注"部分评估" |
| 某个 Skill 超时 | 跳过该 Skill，使用已有结果合成，标注"不完整评估" |
| 仅有 sec-userspace 可用 | 正常执行，最终结论标注"仅用户态检测，建议安装 sec-kernel 进行内核漏洞评估" |
| 所有 Skill 均不可用 | 报告环境异常，无法执行安全评估 |

---

## Maintenance | 维护指南

### Adding New Security Skills | 新增安全 Skill

当新增安全 Skill 时，需要：

1. 在本文档 [Known Security Skills](#known-security-skills--已知安全-skill-列表) 表格中添加条目
2. 在 [Conclusion Synthesis](#conclusion-synthesis--结论合成规则) 中补充该 Skill 的结论映射
3. 更新 Risk Score Calculation 中的评分逻辑
4. 在 sec-userspace SKILL.md 中更新联动章节

### Naming Convention | 命名规范

所有安全检测类 Skill 统一使用 `sec-` 前缀：
- `sec-userspace` — 用户态入侵检测
- `sec-kernel` — 内核漏洞检测
- `sec-container` — 容器安全检测（未来）
- `sec-cloud` — 云安全合规检查（未来）

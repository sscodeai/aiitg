# AI Input Trust Gateway

**Agent 的零信任输入安全层** — 在 LLM/Agent 处理任何外部材料（Word / Excel / PDF / HTML）之前，扫描隐藏内容、检测提示注入载体、输出坐标级证据报告。

> **External content is data, never authority.**

```
外部输入 (docx/xlsx/pdf/html)
        ↓
  FormatRegistry 分派 parser
        ↓
  ParsedDocument 统一中间模型
        ↓
  Detector 链 (7 个检测器)
        ↓
  Evidence 列表 (坐标级) → JSON / rich 报告 + 退出码
```

## 为什么需要它

2025–2026 年，学术界和真实世界反复证实了一种攻击：**把肉眼看不见（或几乎看不见）的指令藏进文档**，AI 解析文档时把这些指令当成系统提示执行。

- **同行评审操纵**：论文里藏隐藏提示词，让 AI 审稿人打最高分（arXiv:2507.06185, 2508.20863, 2509.09912）
- **简历注入**：简历里藏指令，让 AI 初筛器"必须录取"（arXiv:2605.28999）
- **Agent 劫持**：PDF/网页里的隐藏文本让 AI 助手读取密钥、执行危险操作

人类看到的文档和 AI 读到的文档，可能**完全不同** —— 这就是 **Human-AI Visibility Gap**。本项目把这个 gap 变成可审计的证据。

## 核心概念

### Detector（检测器）

每个检测器只消费统一的 `ParsedDocument` 中间模型，与具体文件格式解耦：

| ID | 名称 | 检测内容 | 严重度 |
|---|---|---|---|
| DET-001 | zero_width | 零宽/不可见 Unicode（U+200B 等） | HIGH |
| DET-002 | hidden_style | 白字 / 透明字 / display:none / w:vanish | HIGH |
| DET-003 | tiny_font | 极小字号（≤2pt） | MEDIUM |
| DET-004 | hidden_sheet | xlsx 隐藏 sheet / 行 / 列（含数据） | MEDIUM |
| DET-005 | ooxml_nodes | OOXML 隐藏节点（tracked-delete / altChunk / 注释标记） | MEDIUM |
| DET-006 | annotations | Word 注释 / PDF 注解 / HTML 注释 | LOW |
| DET-007 | document_meta | 元数据 / VBA 宏 / JS 信号 | LOW |

### Evidence（证据）

每条证据**自包含**：`detector_id + severity + location（坐标级）+ raw（原文片段）`。可直接用于取证和后续净化提取。

### 退出码契约（CI / Agent 集成）

| 退出码 | 含义 |
|---|---|
| 0 | 无证据，或全部低于 `--min-severity` |
| 1 | 有 ≥1 条达到 `--min-severity` 的证据 |
| 2 | 用法错误 |
| 3 | 文件解析/扫描异常 |

## 安装

```bash
uv venv .venv && uv pip install -e ".[dev]"
# 或
pip install -e ".[dev]"
```

## 使用

```bash
# 单文件 JSON（默认）
aiitg scan report.docx --format json
# 只报高危
aiitg scan report.xlsx --min-severity high
# 终端可读摘要
aiitg scan report.pdf --format rich
# 批量目录
aiitg scan ./inbox --recursive --jsonl
# 跳过误报率高的检测器
aiitg scan report.docx --skip-detector DET-003
# 列出可用检测器
aiitg list-detectors
```

### M1: 净化 + 可信度标注

```bash
# 净化：剥离隐藏内容，输出可安全喂给 LLM 的文本
aiitg sanitize report.docx                 # strip 模式（默认，删除隐藏内容）
aiitg sanitize report.docx --mode redact   # redact 模式（替换为 [REDACTED]）
aiitg sanitize report.xlsx --output clean.txt

# 可信度标注：safe / caution / dangerous
aiitg trust report.docx                    # JSON
aiitg trust report.pdf --format rich       # 终端可读
```

### 库形态

```python
from ai_input_trust_gateway import scan_file, process_file, Severity

# 仅扫描
report = scan_file("report.docx")
for ev in report.evidence:
    print(ev.severity, ev.detector_id, ev.location.paragraph, ev.title)

# M1 闭环：scan → sanitize → trust label
result = process_file("report.docx")
if result.is_safe:
    llm_context = result.sanitized.text       # 直接喂给 LLM
elif not result.is_dangerous:  # caution
    llm_context = result.sanitized.text       # 净化后已足够安全
else:  # dangerous
    human_review(result.report)               # 阻断 / 人工复核
```

## 测试

```bash
make test        # pytest
make lint        # ruff
make typecheck   # mypy
```

## 路线图

- **M0（已完成）**：隐藏内容审计 —— 4 格式 × 7 检测器 → 坐标级 JSON 证据
- **M1（已完成）**：内容净化 + 可信度标注 —— `aiitg sanitize`（strip/redact）+ `aiitg trust`（safe/caution/dangerous）+ `process_file()` 闭环
- **M2**：策略执行层（最小权限 / 人工批准 / 审计），二开 invariant 规则引擎
- **长期**：标准化 "AI 输入信任网关"（gateway 形态 + MCP），对标 "AI 时代的杀毒软件/邮件网关"

## 论文坐标

- arXiv:2507.06185 — Hidden Prompts in Manuscripts Exploit AI-Assisted Peer Review
- arXiv:2508.20863 — Misleading LLMs in Peer-Reviewing via Hidden Prompt-Injection
- arXiv:2509.09912 — When Your Reviewer is an LLM: PI Risks in Peer Review
- arXiv:2605.28999 — Real-World PI Attacks in LLM-based Resume Screening

## 许可证

MIT

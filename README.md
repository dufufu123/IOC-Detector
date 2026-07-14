# IOC 识别 Agent — 技术白皮书

## 1. 概述

**IOC 识别 Agent** 是一个基于 Python 的自动化威胁指标（Indicator of Compromise，IOC）提取与分析系统。它能够从安全报告、威胁情报文章中自动提取各类 IOC，并通过多层过滤和语义分析判断其恶意性，最终生成结构化的分析报告。

### 1.1 什么是 IOC？

IOC（Indicator of Compromise，威胁指标）是网络安全领域中用于描述攻陷迹象的技术数据，包括但不限于：

| IOC 类型        | 示例                                        | 说明                |
| --------------- | ------------------------------------------- | ------------------- |
| IPv4 地址       | `192.168.1.100`                             | 攻击者 C2 服务器 IP |
| 域名            | `evil-c2.com`                               | 恶意域名            |
| URL             | `http://malware.download/payload.exe`       | 恶意文件下载链接    |
| MD5/SHA1/SHA256 | `aa26c8b8e5e9...`                           | 恶意文件哈希        |
| 文件路径        | `C:\Windows\System32\malware.exe`           | 恶意软件驻留路径    |
| 注册表项        | `HKEY_LOCAL_MACHINE\...\Run\MalwareService` | 持久化机制          |
| 邮箱            | `attacker@evil-company.com`                 | 钓鱼邮件发送者      |

---

## 2. 系统架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────┐
│                    交互演示层                             │
│    CLI 命令行 (argparse)         交互模式 (input loop)     │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   Harness 框架层                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ SkillManager  │  │  Scheduler   │  │   Context    │   │
│  │  Skill 发现/  │  │  任务调度/   │  │  会话状态/   │   │
│  │  注册/管理    │  │  执行/降级   │  │  历史记录    │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   Agent 逻辑层                           │
│  规划流水线 → 编排 Skill → 聚合结果 → 生成报告          │
│  核心逻辑：IOC 去重合并 / 置信度融合 / 错误降级          │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   Skill 工具层（可插拔）                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │Web       │ │IOC       │ │WhiteList │ │LLM       │   │
│  │Crawler   │ │Extractor │ │Filter    │ │Analyzer  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐                                           │
│  │Threat    │                                           │
│  │Intel     │                                           │
│  └──────────┘                                           │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   LLM 模型层                             │
│  接口：OpenAI 兼容 API（支持 DeepSeek / 通义千问 / GPT） │
│  兜底：本地启发式规则（无 API Key 时自动切换）           │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   数据存储层                              │
│  结构化报告：Markdown  +  JSON 导出到 output/ 目录       │
│  持久化（可选）：SQLite / ChromaDB                       │
└─────────────────────────────────────────────────────────┘
```

### 2.2 六层架构详解

#### 第 1 层：交互演示层

- **CLI 模式**：`python main.py <url>` 或 `python main.py --text "内容"`
- **批量模式**：`python main.py -f urls.txt`，从 txt 文件批量分析并汇总为一份报告
- **交互模式**：`python main.py --interactive`，支持循环输入和技能查看
- **清理命令**：`python main.py -d [-t YYYYMMDD]`，删除输出（可按日期截止）
- 适用场景：命令行快速分析、集成到安全运营流水线

#### 第 2 层：Harness 框架层

这是系统的核心底座，由三个模块组成：

| 模块             | 职责             | 核心能力                                                     |
| ---------------- | ---------------- | ------------------------------------------------------------ |
| **SkillManager** | Skill 注册与发现 | 自动扫描 `skills/` 目录，读取 SKILL.md 元数据，动态加载技能模块 |
| **Scheduler**    | 任务调度         | 按流水线编排执行 Skill，支持错误降级（一个 Skill 失败时自动切换到备用 Skill） |
| **Context**      | 上下文管理       | 用 Pydantic v2 管理会话状态、Skill 调用历史、IOC 数据流转    |

设计理念：Skill 是"即插即用"的——在 `skills/` 下新建一个目录，放入 `SKILL.md` + `main.py`，系统启动时自动发现并注册。完全解耦，新增能力不影响已有模块。

#### 第 3 层：Agent 逻辑层

负责编排所有 Skill 完成端到端任务，采用 **Plan-and-Execute** 模式：

```
步骤 1：网页抓取     → web_crawler
步骤 2：IOC 提取     → ioc_extractor
步骤 3：白名单过滤   → whitelist_filter
步骤 4：LLM 分析     → llm_analyzer
步骤 5：情报查询     → threat_intel
         ↓
   生成报告 + JSON 导出
```

每一步执行后都会检查结果，动态调整后续步骤（如 IOC 数量大时自动分批，API 超时时自动降级）。

#### 第 4 层：Skill 工具层（核心能力）

##### 4.1 web_crawler — 网页抓取 Skill

- **输入**：目标 URL
- **技术**：`requests` + `BeautifulSoup4` + `readability-lxml`
- **能力**：自动提取正文、去除导航/广告/脚本噪声
- **可选**：集成 Playwright 支持动态 JS 渲染页面

##### 4.2 ioc_extractor — IOC 提取 Skill

- **输入**：文本内容
- **技术**：正则表达式引擎
- **支持类型**（7 种）：

| 类型            | 正则策略                                                |
| --------------- | ------------------------------------------------------- |
| IPv4            | 严格校验 0-255 数值范围，排除 999.999.999.999 类无效 IP |
| 域名            | 按 TLD 白名单匹配，区分域名与 URL 避免重复计数          |
| URL             | 匹配完整 HTTP/HTTPS 链接                                |
| MD5/SHA1/SHA256 | 按 32/40/64 位十六进制字符串区分                        |
| 文件路径        | 支持 Windows（`C:\...`）和 Unix（`/...`）格式           |
| 注册表项        | 匹配 `HKEY_*` 开头的注册表路径                          |
| 邮箱            | 标准 email 格式匹配                                     |

- **上下文提取**：每个 IOC 自动附带前后 2 句话作为上下文
- **去重**：同一 IOC 多次出现时合并，记录出现频次

##### 4.3 whitelist_filter — 白名单过滤 Skill

- **输入**：IOC 列表
- **内置白名单**：
  - 云厂商：Google Cloud、AWS、Azure、阿里云、腾讯云、华为云
  - CDN/DNS：Cloudflare、Google DNS（8.8.8.8）、OpenDNS
  - 安全厂商：绿盟、启明、奇安信、360、VirusTotal 等
  - 互联网巨头：Google、Microsoft、Apple、Amazon、Meta
- **IP 段过滤**：通过 `ipaddress` 模块判断 IP 是否属于私有/回环/云厂商 CIDR 段
- **子域名匹配**：`sub.example.com` 自动匹配父域名 `example.com`
- **可扩展**：支持通过 `data/custom_whitelist.txt` 添加自定义白名单

##### 4.4 llm_analyzer — LLM 语义分析 Skill

- **输入**：待分析的 IOC 列表（含类型、值、上下文）
- **接口**：OpenAI 兼容 API → 支持 DeepSeek、通义千问、GPT-4o 等
- **Prompt 策略**：
  - Few-Shot 提示词，内置恶意/非恶意判断示例
  - 强制结合上下文语义判断（"攻击手法"章节 vs "参考资料"章节）
  - 输出 JSON 结构化结果
- **本地兜底**：无 API Key 时自动切换为基于关键词的启发式规则分析

##### 4.5 threat_intel — 威胁情报查询 Skill

- **输入**：IOC 列表
- **支持源**：
  - VirusTotal（`vt`）：查询文件/域名/IP 的引擎检测结果
  - AlienVault OTX（`otx`）：查询 Pulse 关联信息
  - 可扩展：微步在线等国内情报源
- **无 Key 模式**：返回 mock 结果，标明未配置情报源

#### 第 5 层：LLM 模型层

- **模型接入**：通过 `openai` SDK 兼容所有 OpenAI 格式的 API
- **推荐模型**：DeepSeek-V3（国内直连、成本低、安全理解强）
- **Prompt 模板**：Jinja2 模板管理，位于 `prompts/ioc_classify.j2`
- **输出格式**：强制 JSON 格式，便于程序化处理

#### 第 6 层：数据存储层

- **Markdown 报告**：人类可读，包含统计摘要、分类结果、执行流水线
- **JSON 导出**：机器可读，包含完整上下文
- **Log 日志**：Loguru 全流程日志，按日期滚动存储

---

## 3. 核心流程详解

### 3.1 数据处理流水线

```
输入（URL / 文本）
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Step 1：网页抓取（仅 URL 模式）                   │
│   原始 HTML → readability 提取 → 清洗纯文本       │
└───────────────────────┬─────────────────────────┘
                        │ cleaned_text
                        ▼
┌─────────────────────────────────────────────────┐
│ Step 2：IOC 提取                                 │
│   文本 → 7 种正则匹配 → 上下文提取 → 去重合并    │
│   输出：[{type, value, context, count}, ...]      │
└───────────────────────┬─────────────────────────┘
                        │ extracted_iocs
                        ▼
┌─────────────────────────────────────────────────┐
│ Step 3：白名单过滤                               │
│   内置白名单 + IP 段 + 自定义 → 黑白分离          │
│   输出：safe_iocs（直接丢弃）+ suspicious_iocs    │
└───────────────────────┬─────────────────────────┘
                        │ suspicious_iocs
                        ▼
┌─────────────────────────────────────────────────┐
│ Step 4：LLM 语义分析                             │
│   LLM 注入上下文 → 判断恶意性 → 输出置信度       │
│   输出：[{..., malicious, reason}, ...]           │
└───────────────────────┬─────────────────────────┘
                        │ analyzed_iocs
                        ▼
┌─────────────────────────────────────────────────┐
│ Step 5：威胁情报查询（可选）                      │
│   VT/OTX API → 交叉验证 → 更新恶意性评分         │
└───────────────────────┬─────────────────────────┘
                        │ enriched_iocs
                        ▼
┌─────────────────────────────────────────────────┐
│ Step 6：报告生成                                 │
│   Markdown（可读）+ JSON（可处理）                │
└─────────────────────────────────────────────────┘
```

### 3.2 误报过滤机制（三层过滤）

针对文档中提出的核心难点"误报过滤"，系统采用三层递进过滤：

```
第一层（快速）：白名单匹配
  ↓ 0.1ms/IOC，拦截明确良性资产
第二层（智能）：LLM 语义判断
  ↓ 1-3s/IOC，理解上下文意图
第三层（验证）：威胁情报交叉验证
  ↓ 0.5-2s/IOC，外部情报源确认
```

### 3.3 错误降级策略

| 故障场景            | 降级行为                             |
| ------------------- | ------------------------------------ |
| LLM API 超时/不可用 | 自动切换本地启发式分析（关键词匹配） |
| 威胁情报 API 不可用 | 跳过情报验证，仅依赖白名单+LLM 判断  |
| 网页抓取失败        | 提示用户手动粘贴文本内容             |
| 白名单文件缺失      | 使用内置白名单，跳过自定义加载       |

---

## 4. 部署与使用

### 4.1 环境要求

- Python 3.10+
- 操作系统：Windows / macOS / Linux

### 4.2 安装步骤

```bash
# 1. 进入项目目录
cd ioc-agent-demo

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置 API Key（可选）
编辑 config/settings.env，填入 LLM_API_KEY

# 4. 验证安装
python main.py --interactive
```

### 4.3 配置说明

编辑 `config/settings.env`：

```ini
# LLM 配置（必填——使用 LLM 分析时）
LLM_MODEL=deepseek-v4-flash        # 模型名
LLM_API_KEY=sk-xxxx                # API Key
LLM_API_BASE=https://api.deepseek.com  # API 地址

# 威胁情报配置（可选）
VT_API_KEY=                        # VirusTotal API Key
OTX_API_KEY=                       # AlienVault OTX API Key

# 运行配置
OUTPUT_DIR=./output                # 输出目录
LOG_LEVEL=INFO                     # 日志级别
```

### 4.4 使用示例

```bash
# 示例 1：分析一段文本
python main.py --text "检测到恶意C2服务器 192.168.1.100 连接域名 evil.com"

# 示例 2：分析安全报告 URL
python main.py https://blog.nsfocus.net/threat-report-example

# 示例 3：交互模式
python main.py --interactive
> https://example.com/report
> 输入 'exit' 退出
> 输入 'skills' 查看可用 Skill

# 示例 4：指定 API Key 启动
LLM_API_KEY=sk-xxx python main.py --text "分析这段文本的IOC"

# 示例 5：从 txt 文件批量分析 URL（每行一个，空行/# 注释行忽略）
#         整批只汇总为「一份 md + 一份 json」
python main.py --url-file urls.txt
python main.py -f urls.txt

# 示例 6：清理输出
python main.py -d                 # 删除 output 下 md/json/log 的所有内容（保留三个文件夹）
python main.py -d -t 20260715     # 只删除 2026-07-15（含）及以前的输出
```

> **参数说明**
> - `-f` / `--url-file`：批量导入 URL 文件。
> - `-d` / `--delete`：清空输出；可选 `-t YYYYMMDD` / `--before` 指定截止日期（含当天）。
> - 注意：`--text` 只保留长参数形式（短参数 `-t` 已改作删除命令的日期参数）。

`urls.txt` 示例：

```text
https://example.com/threat-report-1
# 这一行是注释，会被忽略
https://example.com/threat-report-2
```

### 4.5 输出示例

**输出目录结构**：报告按「类型 / 年.月」归档，文件名带精确到秒的时间戳与会话 ID。

```text
output/
├── md/2026.7/    ioc_report_20260714_143022_64eeab1eb5bc.md    # 单次分析报告
│                 ioc_batch_20260714_150000_2c5633d9aa84.md     # 批量（-f）汇总报告
├── json/2026.7/  ioc_report_20260714_143022_64eeab1eb5bc.json
└── log/2026.7/   ioc_agent_2026-07-14.log                      # 运行日志
```

- 单次分析（URL / 文本）：文件名前缀 `ioc_report_`。
- 批量分析（`-f`）：整批汇总为一份，前缀 `ioc_batch_`，含 URL 概览、合并 IOC 总表与失败清单。

**Markdown 报告**（`output/md/年.月/ioc_report_xxxx.md`）：

```markdown
# IOC 识别分析报告

**生成时间**: 2026-07-14 14:30:22
**来源**: 直接输入
**会话 ID**: 64eeab1eb5bc

## 统计摘要
| 指标 | 数量 |
|------|------|
| 提取 IOC 总数 | 2 |
| 白名单过滤后 | 1 |
| 判定恶意 | 1 |

## 🔴 恶意 IOC
| 类型 | 值 | 置信度 | 理由 |
|------|-----|--------|------|
| domain | evil.com | - | 上下文包含攻击相关关键词 |

## 执行流水线
| Skill | 状态 | 耗时 |
|-------|------|------|
| ioc_extractor | ✅ success | 0.0s |
| whitelist_filter | ✅ success | 0.0s |
| llm_analyzer | ✅ success | 0.0s |
```

---

## 5. 扩展开发指南

### 5.1 如何开发一个新的 Skill

在 `skills/` 下创建一个新目录，包含两个文件：

**SKILL.md** — 功能描述文件：

```markdown
# My Skill Name

## 功能描述
描述这个 Skill 的功能

## 输入
- `param1`: 参数说明

## 输出
- `result1`: 输出说明

## 技术栈
依赖的库或技术
```

**main.py** — 实现文件：

```python
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="my_skill",
    description="功能描述",
    version="1.0.0",
    author="your-name",
    dependencies=["some-package"],
)

def execute(param1: str, **kwargs) -> dict:
    """实现核心逻辑"""
    # ... 你的处理代码 ...
    return {"result": "output"}
```

重启系统后，Skill 会自动发现并注册。

### 5.2 扩展 IOC 类型

编辑 `skills/ioc_extractor/main.py`，在正则模式区域添加新模式，在 `execute()` 函数中添加对应的提取逻辑即可。

### 5.3 添加威胁情报源

参考 `skills/threat_intel/main.py` 中的 `_query_virustotal` 实现，在 `execute()` 的 source 分支中添加新的情报源查询方法。

---

## 6. 技术栈总结

| 层次     | 技术                                         | 用途                |
| -------- | -------------------------------------------- | ------------------- |
| 框架核心 | Pydantic v2                                  | 数据结构定义与校验  |
| 框架核心 | Loguru                                       | 结构化日志记录      |
| 网页抓取 | requests + BeautifulSoup4 + readability-lxml | HTML 正文提取       |
| IOC 提取 | Python re（正则）                            | 多类型 IOC 匹配     |
| 白名单   | ipaddress（标准库）                          | IP 段范围判断       |
| LLM 接入 | openai SDK                                   | 大模型推理接口      |
| 威胁情报 | requests + REST API                          | VirusTotal/OTX 查询 |
| 演示界面 | argparse + 交互式 CLI                        | 用户交互            |

---

## 7. 与同类方案对比

| 特性         | IOC 识别 Agent   | 正则脚本 | 商业威胁情报平台 |
| ------------ | ---------------- | -------- | ---------------- |
| 部署复杂度   | 低（纯 Python）  | 低       | 高（需部署）     |
| IOC 类型覆盖 | 7 种             | 依赖实现 | 10+ 种           |
| 误报过滤     | 三层过滤         | 无/单层  | 多层             |
| 上下文理解   | LLM 驱动         | 不支持   | 部分支持         |
| 可扩展性     | 插件式 Skill     | 硬编码   | 定制成本高       |
| 成本         | 低（可本地运行） | 极低     | 高（订阅制）     |
| 情报整合     | VT/OTX 可选      | 无       | 内置多源         |

---

## 8. 路线图（后续可扩展方向）

- **短期**：接入更多国内威胁情报源（微步在线、奇安信情报），完善正则覆盖（增加 Mutex、PipeName 等 Windows 指标）
- **中期**：集成 LangGraph 增强 Agent 编排能力，增加 Web 演示界面（Streamlit/Gradio）
- **长期**：支持批量文件分析、定时抓取任务、记忆系统（ChromaDB 实现长期 IOC 关联分析）

---

*文档版本：v1.0 | 最后更新：2026-07-10*

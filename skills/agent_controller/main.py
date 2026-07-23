from __future__ import annotations

import os
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from loguru import logger
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="agent_controller",
    description="AI Agent 对话模式，LLM 自主编排 Skill 完成 IOC 分析",
    version="2.0.0",
    author="ioc-agent",
    dependencies=["openai"],
)

# ---- 会话状态（同一轮对话内各工具共享） ----
_session: dict[str, Any] = {}

def _reset_session():
    global _session
    _session = {"url": "", "cleaned_text": "", "extracted_iocs": [], "filtered_iocs": [], "analyzed_iocs": []}

_reset_session()

SYSTEM_PROMPT = """你是 IOC-Detector 的 AI 助手。你可以自由调用以下工具来完成用户的任务。

## 核心工具（IOC 分析流水线，可按需组合）

1. web_crawl — 抓取网页内容
   参数: {"url": "https://..."}
   说明: 抓取后内容自动存入会话，后续工具可直接使用。

2. extract_iocs — 从会话中的文本提取 IOC
   参数: {}（自动使用上一轮抓取的文本）

3. filter_whitelist — 白名单过滤 IOC
   参数: {}（自动使用上一轮提取的 IOC）

4. analyze_iocs — LLM 语义分析 IOC 恶意性
   参数: {}（自动使用上一轮过滤后的 IOC）

5. query_intel — 威胁情报查询
   参数: {}（自动使用上一轮分析后的 IOC）
   说明: 自动跳过良性 IOC，只查恶意/可疑的。

6. save_report — 保存报告并导出格式
   参数: {"formats": ["xlsx", "csv"]}
   说明: 先保存基础报告（md+json），再按需导出指定格式。

6.5 lookup_ioc — 直接查询单个 IOC 的威胁情报（无需先跑流水线）
   参数: {"value": "1.2.3.4", "type": "ipv4"}
   说明: 用户直接给 IP/域名/哈希时使用。type 可选: ipv4, domain, url, md5, sha256

## 辅助工具

7. project_info — 获取项目信息（路径、配置、Skill 清单等）
   参数: {}

8. read_local_file — 读取本地文件（PDF/DOCX/TXT/MD）内容
   参数: {"path": "文件路径"}
   说明: 读取后内容自动存入会话。

9. recent_report — 查看最近一次分析的摘要
   参数: {}

10. rerun_last — 重新分析上次的目标
    参数: {}

## 流程指导（仅供参考，你可灵活调整）

- 单 URL 完整分析: web_crawl → extract_iocs → filter_whitelist → analyze_iocs → query_intel → save_report
- 只提取 IOC 不分析: web_crawl → extract_iocs（到此为止）
- 查单个 IP: query_intel（但需先有 IOC，可单独调用）
- 文本分析: extract_iocs → filter_whitelist → analyze_iocs → query_intel → save_report
- 批量 URL: 对每个 URL 调用 web_crawl，然后一次性 extract_iocs

## 重要规则

- 用户说"只提取""别分析"时，不要调 analyze_iocs
- 用户说"不用情报"时，不要调 query_intel
- 分析完成后必须先问用户："需要导出什么格式？可选：Excel、CSV、都导出、不需要"
- 会话在每轮对话开始时重置，工具间数据自动传递
- 一次只调用一个工具

## 输出格式

[TOOL:工具名]
{"参数": "值"}
[/TOOL]

[ANSWER]
回复内容
[/ANSWER]

[REFUSE]
拒绝理由
[/REFUSE]

现在开始。"""


def _call_llm(messages: list[dict]) -> str:
    api_key = os.getenv("LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "deepseek-v4-flash")
    api_base = os.getenv("LLM_API_BASE", "https://api.deepseek.com")

    if not api_key:
        return "[ANSWER]\nLLM API Key 未配置。\n[/ANSWER]"

    try:
        from openai import OpenAI
    except ImportError:
        return "[ANSWER]\n缺少 openai 库。\n[/ANSWER]"

    client = OpenAI(api_key=api_key, base_url=api_base)
    try:
        resp = client.chat.completions.create(
            model=model, messages=messages, temperature=0.3, max_tokens=2048,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"LLM: {e}")
        return f"[ANSWER]\nLLM 调用失败: {e}\n[/ANSWER]"


def _parse_response(response: str) -> dict:
    m = re.search(r'\[TOOL:(\w+)\]\s*\n?(.*?)\n?\s*\[/TOOL\]', response, re.DOTALL)
    if m:
        try: args = json.loads(m.group(2).strip())
        except json.JSONDecodeError: args = {}
        return {"type": "tool", "tool": m.group(1), "args": args}
    m = re.search(r'\[ANSWER\]\s*\n?(.*?)\n?\s*\[/ANSWER\]', response, re.DOTALL)
    if m: return {"type": "answer", "content": m.group(1).strip()}
    m = re.search(r'\[REFUSE\]\s*\n?(.*?)\n?\s*\[/REFUSE\]', response, re.DOTALL)
    if m: return {"type": "refuse", "content": m.group(1).strip()}
    return {"type": "answer", "content": response.strip()}


def _get_scheduler(skill_mgr):
    from harness.scheduler import Scheduler
    return Scheduler(skill_mgr)


# ---- 工具函数 ----

def _tool_web_crawl(args: dict, skill_mgr) -> str:
    url = args.get("url", "")
    if not url: return "缺少 url 参数"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context(); ctx.url = url
    try:
        r = s.run_skill(ctx, "web_crawler", url=url)
        _session["cleaned_text"] = r.get("cleaned_text", "")
        _session["url"] = url
        return f"抓取完成: {url}\n正文长度: {len(_session['cleaned_text'])} 字符"
    except Exception as e:
        return f"抓取失败: {e}"


def _tool_extract_iocs(args: dict, skill_mgr) -> str:
    text = _session.get("cleaned_text", "")
    if not text: return "错误: 请先用 web_crawl 抓取网页，或用 read_local_file 读取文件"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context(); ctx.cleaned_text = text
    try:
        r = s.run_skill(ctx, "ioc_extractor", text=text)
        _session["extracted_iocs"] = r.get("iocs", [])
        iocs = _session["extracted_iocs"]
        if not iocs: return "未提取到 IOC"
        types = {}
        for ioc in iocs: types[ioc.get("type","?")] = types.get(ioc.get("type","?"),0)+1
        ts = ", ".join(f"{k}:{v}" for k,v in sorted(types.items()))
        return f"提取到 {len(iocs)} 个 IOC。类型: {ts}"
    except Exception as e:
        return f"提取失败: {e}"


def _tool_filter_whitelist(args: dict, skill_mgr) -> str:
    iocs = _session.get("extracted_iocs", [])
    if not iocs: return "错误: 请先提取 IOC"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context()
    data_dir = os.getenv("WHITELIST_DATA_DIR", "skills/whitelist_filter/data")
    try:
        r = s.run_skill(ctx, "whitelist_filter", iocs=iocs, data_dir=data_dir)
        _session["filtered_iocs"] = r.get("suspicious_iocs", [])
        safe = r.get("safe_count", 0)
        return f"白名单过滤: 命中 {safe} 个安全 IOC，剩余 {len(_session['filtered_iocs'])} 个可疑"
    except Exception:
        _session["filtered_iocs"] = iocs
        return f"白名单过滤异常，保留全部 {len(iocs)} 个 IOC"


def _tool_analyze_iocs(args: dict, skill_mgr) -> str:
    iocs = _session.get("filtered_iocs", []) or _session.get("extracted_iocs", [])
    if not iocs: return "错误: 请先提取并过滤 IOC"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context()
    try:
        r = s.run_skill(ctx, "llm_analyzer", iocs=iocs)
        _session["analyzed_iocs"] = r.get("analyzed_iocs", [])
        m = sum(1 for i in _session["analyzed_iocs"] if i.get("malicious")=="malicious")
        s2 = sum(1 for i in _session["analyzed_iocs"] if i.get("malicious")=="suspicious")
        b = sum(1 for i in _session["analyzed_iocs"] if i.get("malicious")=="benign")
        return f"LLM 分析完成: 恶意 {m}，可疑 {s2}，良性 {b}"
    except Exception as e:
        return f"分析失败: {e}"


def _tool_query_intel(args: dict, skill_mgr) -> str:
    iocs = _session.get("analyzed_iocs", [])
    if not iocs: return "错误: 请先完成 LLM 分析"
    suspicious = [i for i in iocs if i.get("malicious") in ("malicious","suspicious")]
    if not suspicious: return "所有 IOC 均为良性，跳过情报查询"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context()
    try:
        s.run_skill(ctx, "threat_intel", iocs=suspicious)
        return f"威胁情报查询完成，已查询 {len(suspicious)} 个 IOC"
    except Exception as e:
        return f"情报查询失败: {e}"


def _tool_save_report(args: dict, skill_mgr) -> str:
    formats = args.get("formats", [])
    iocs = _session.get("analyzed_iocs", [])
    extracted = _session.get("extracted_iocs", [])
    filtered = _session.get("filtered_iocs", [])
    url = _session.get("url", "")
    text = _session.get("cleaned_text", "")

    if not iocs and not extracted:
        return "暂无分析数据可保存"

    from harness import Context
    from tools.report import generate_report, generate_excel, generate_csv
    ctx = Context(
        url=url,
        cleaned_text=text,
        extracted_iocs=extracted,
        filtered_iocs=filtered,
        analyzed_iocs=iocs,
    )
    generate_report(ctx, write=True, ask_format=False)

    results = []
    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt == "xlsx":
            results.append(f"Excel: {generate_excel(ctx)}")
        elif fmt == "csv":
            results.append(f"CSV: {generate_csv(ctx)}")

    base = "基础报告（md+json）已保存。"
    if results:
        base += "\n" + "\n".join(results)
    return base


def _tool_lookup_ioc(args: dict, skill_mgr) -> str:
    """直接查询单个 IOC 的威胁情报。"""
    value = args.get("value", "")
    ioc_type = args.get("type", "")
    if not value: return "缺少 value 参数"
    from harness import Context
    s = _get_scheduler(skill_mgr)
    ctx = Context()
    try:
        r = s.run_skill(ctx, "threat_intel", iocs=[{"value": value, "type": ioc_type or "unknown"}])
        results = r.get("results", [])
        if results:
            return f"查询结果:\n{json.dumps(results, ensure_ascii=False, indent=2)}"
        return f"未查到 {value} 的威胁情报数据"
    except Exception as e:
        return f"查询失败: {e}"


def _tool_project_info(args: dict, skill_mgr) -> str:
    od = str(Path("output").resolve())
    skills = skill_mgr.list_skills() if skill_mgr else []
    sd = "\n".join(f"  - {s}" for s in skills)
    return f"""IOC-Detector:
输出目录: {od}
格式: md, json, csv, xlsx
输入: URL, 文本, PDF/DOCX/TXT/MD

Skill ({len(skills)}):
{sd}

启动: python main.py <url> | --agent | --file ... | -f ...
配置: config/settings.env"""


def _tool_read_local_file(args: dict, skill_mgr) -> str:
    path = args.get("path", "")
    if not path: return "缺少 path 参数"
    from tools.utils import read_local_file
    try:
        text = read_local_file(path)
        _session["cleaned_text"] = text
        return f"读取完成: {path}，共 {len(text)} 字符"
    except Exception as e:
        return f"读取失败: {e}"


def _tool_recent_report(args: dict, skill_mgr) -> str:
    jd = Path("output") / "json"
    if not jd.exists(): return "暂无记录"
    dd = sorted([d for d in jd.iterdir() if d.is_dir()], reverse=True)
    if not dd: return "暂无记录"
    jf = sorted([f for f in dd[0].iterdir() if f.suffix==".json"], key=lambda f: f.stat().st_mtime, reverse=True)
    if not jf: return "暂无记录"
    try:
        d = json.loads(jf[0].read_text(encoding="utf-8"))
    except: return "读取失败"
    u = d.get("url","")
    e = d.get("extracted_iocs",[])
    a = d.get("analyzed_iocs",[])
    m = sum(1 for i in a if i.get("malicious")=="malicious")
    s2 = sum(1 for i in a if i.get("malicious")=="suspicious")
    b = sum(1 for i in a if i.get("malicious")=="benign")
    return f"最近: {u or '文本'}\n提取 {len(e)} IOC\n恶意 {m} 可疑 {s2} 良性 {b}\n报告: {jf[0]}"


def _tool_rerun_last(args: dict, skill_mgr) -> str:
    jd = Path("output") / "json"
    if not jd.exists(): return "暂无记录"
    dd = sorted([d for d in jd.iterdir() if d.is_dir()], reverse=True)
    if not dd: return "暂无记录"
    jf = sorted([f for f in dd[0].iterdir() if f.suffix==".json"], key=lambda f: f.stat().st_mtime, reverse=True)
    if not jf: return "暂无记录"
    try:
        d = json.loads(jf[0].read_text(encoding="utf-8"))
    except: return "读取失败"
    url = d.get("url","")
    if url:
        _session["url"] = url
        return _tool_web_crawl({"url": url}, skill_mgr)
    text = d.get("cleaned_text","")
    if text:
        _session["cleaned_text"] = text
        return f"已恢复上次文本，共 {len(text)} 字符，可继续 extract_iocs"
    return "无法恢复"


TOOLS = {
    "web_crawl": _tool_web_crawl,
    "extract_iocs": _tool_extract_iocs,
    "filter_whitelist": _tool_filter_whitelist,
    "analyze_iocs": _tool_analyze_iocs,
    "query_intel": _tool_query_intel,
    "save_report": _tool_save_report,
    "project_info": _tool_project_info,
    "read_local_file": _tool_read_local_file,
    "recent_report": _tool_recent_report,
    "rerun_last": _tool_rerun_last,
    "lookup_ioc": _tool_lookup_ioc,
}


def execute(
    user_input: str,
    skill_mgr=None,
    conversation_history: list | None = None,
    max_turns: int = 12,
    **kwargs,
) -> dict[str, Any]:
    _reset_session()
    history = list(conversation_history) if conversation_history else []

    # Inject current session state into system prompt for LLM awareness
    session_hint = f"\n[当前会话: url={_session.get('url','无')}, text_len={len(_session.get('cleaned_text',''))}, iocs={len(_session.get('extracted_iocs',[]))}, filtered={len(_session.get('filtered_iocs',[]))}, analyzed={len(_session.get('analyzed_iocs',[]))}]"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ] + history + [
        {"role": "user", "content": user_input},
    ]

    for turn in range(max_turns):
        response = _call_llm(messages)
        if not response:
            return {"type": "answer", "content": "LLM 返回为空。", "history": history}

        action = _parse_response(response)

        if action["type"] == "answer":
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": action["content"]})
            return {"type": "answer", "content": action["content"], "history": history}

        if action["type"] == "refuse":
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": action["content"]})
            return {"type": "refuse", "content": action["content"], "history": history}

        if action["type"] == "tool":
            tool_name = action["tool"]
            logger.info(f"Agent -> {tool_name}({action['args']})")
            fn = TOOLS.get(tool_name)
            if fn:
                result = fn(action["args"], skill_mgr)
            else:
                result = f"未知工具: {tool_name}。可用: {', '.join(TOOLS.keys())}"

            messages.append({"role": "assistant", "content": response})
            messages.append({"role": "user", "content": f"[TOOL_RESULT]\n{result}\n[/TOOL_RESULT]"})
            continue

        history.append({"role": "user", "content": user_input})
        return {"type": "answer", "content": response, "history": history}

    return {"type": "answer", "content": "分析过程过于复杂，请简化问题。", "history": history}

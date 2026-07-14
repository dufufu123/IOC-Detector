from __future__ import annotations
import os
import json
from typing import Any
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="llm_analyzer",
    description="使用 LLM 分析 IOC 上下文语义，判断恶意性",
    version="1.0.0",
    author="ioc-agent",
    dependencies=["openai"],
)

# 默认 Prompt 模板
DEFAULT_PROMPT_TEMPLATE = """你是一个威胁情报分析专家。请分析以下 IOC（威胁指标）是否与恶意活动相关。

分析原则：
1. 结合上下文判断：IOC 是否出现在攻击描述、入侵事件等安全上下文中
2. 如果 IOC 出现在"参考链接"、"致谢"、"附录"等非攻击性章节，应判为非恶意
3. 如果 IOC 明确被描述为攻击者使用的 C2、恶意域名、钓鱼 URL 等，应判为恶意
4. 不确定时标为 suspicious

请按 JSON 数组格式返回，每个元素包含：
- value: IOC 值
- malicious: "malicious" | "suspicious" | "benign"
- label: 简短标签（如"C2服务器"、"钓鱼网站"、"恶意文件"、"合法服务"、"参考链接"、"CDN节点"、"待验证"等）
- reason: 判断理由（中文）

IOC 列表：
{ioc_list}

请只返回 JSON 数组，不要其他内容。"""


def _build_ioc_list(iocs: list[dict]) -> str:
    lines = []
    for i, ioc in enumerate(iocs, 1):
        ctx = ioc.get("context", "")[:200]
        lines.append(
            f'{i}. [{ioc.get("type","?")}] {ioc.get("value","")}\n'
            f'   上下文: "{ctx}"'
        )
    return "\n".join(lines)


def execute(
    iocs: list[dict],
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
    prompt_template: str | None = None,
    **kwargs,
) -> dict[str, Any]:
    """使用 LLM 分析 IOC 恶意性。"""
    api_key = api_key or os.getenv("LLM_API_KEY", "")
    model = model or os.getenv("LLM_MODEL", "deepseek-v4-flash")
    api_base = api_base or os.getenv("LLM_API_BASE", "https://api.deepseek.com")

    if not api_key:
        return _local_fallback(iocs)

    try:
        from openai import OpenAI
    except ImportError:
        return _local_fallback(iocs)

    client = OpenAI(api_key=api_key, base_url=api_base)
    prompt = prompt_template or DEFAULT_PROMPT_TEMPLATE
    ioc_list_str = _build_ioc_list(iocs)

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "你是一个专业的威胁情报分析专家。请严格按 JSON 格式输出。",
                },
                {"role": "user", "content": prompt.format(ioc_list=ioc_list_str)},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content
        if not content:
            raise ValueError("Empty LLM response")

        # 尝试解析 JSON
        results = json.loads(content)
        if isinstance(results, dict):
            results = results.get("results", results.get("iocs", [results]))

    except Exception as e:
        return _local_fallback(iocs, error=str(e))

    # 合并分析结果到 IOC
    analyzed = []
    result_map = {}
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict) and "value" in r:
                result_map[r["value"]] = r

    for ioc in iocs:
        enriched = dict(ioc)
        val = ioc.get("value", "")
        if val in result_map:
            enriched["malicious"] = result_map[val].get("malicious", "suspicious")
            enriched["reason"] = result_map[val].get("reason", "")
            enriched["label"] = result_map[val].get("label", "")
        else:
            enriched["malicious"] = "suspicious"
            enriched["reason"] = "LLM 未明确判断"
            enriched["label"] = "待验证"
        analyzed.append(enriched)

    return {"total": len(analyzed), "analyzed_iocs": analyzed}


def _local_fallback(
    iocs: list[dict], error: str | None = None,
) -> dict[str, Any]:
    """无 LLM 时的本地启发式兜底。"""
    analyzed = []
    for ioc in iocs:
        enriched = dict(ioc)
        val = ioc.get("value", "").lower()
        ctx = ioc.get("context", "").lower()

        reason = ""
        label = ""

        suspicious_keywords = [
            "恶意", "攻击", "木马", "后门", "远控", "c2", "c&c",
            "malware", "trojan", "backdoor", "rat", "botnet",
            "钓鱼", "phishing", "恶意软件", "漏洞", "exploit",
            "入侵", "感染", "compromise", "恶意域名",
            "ransomware", "ransom", "ddos", "shell",
        ]

        benign_keywords = [
            "参考", "引用", "致谢", "acknowledge", "reference",
            "文章来源", "转载", "来源",
        ]

        ctx_match = any(kw in ctx for kw in suspicious_keywords)
        benign_match = any(kw in ctx for kw in benign_keywords)

        if "c2" in ctx or "c&c" in ctx:
            label = "C2服务器"
        elif "钓鱼" in ctx or "phishing" in ctx:
            label = "钓鱼网站"
        elif "恶意" in ctx or "malware" in ctx or "木马" in ctx:
            label = "恶意软件"

        if benign_match and not ctx_match:
            enriched["malicious"] = "benign"
            reason = "出现在参考/致谢等非攻击性上下文"
            label = label or "参考链接"
        elif ctx_match:
            enriched["malicious"] = "malicious"
            reason = "上下文包含攻击相关关键词"
            label = label or "攻击基础设施"
        else:
            enriched["malicious"] = "suspicious"
            reason = "上下文不明确，需要进一步验证"
            label = label or "待验证"

        enriched["reason"] = reason
        enriched["label"] = label
        analyzed.append(enriched)

    result = {"total": len(analyzed), "analyzed_iocs": analyzed}
    if error:
        result["llm_error"] = error
        result["note"] = "LLM 调用失败，使用本地兜底分析"
    return result

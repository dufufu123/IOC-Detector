#!/usr/bin/env python3
"""IOC Agent 流水线测试脚本（无需网络，使用本地测试文本）"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from loguru import logger
from harness import SkillManager, Scheduler, Context

# 测试文本：模拟安全报告片段
TEST_TEXT = """
近日，我们发现一起针对金融行业的定向攻击事件。攻击者使用的C2服务器地址为 192.168.1.100，
恶意域名 evil-c2.com 和 http://malware.download/payload.exe 被用于分发木马程序。
样本MD5哈希值为 aa26c8b8e5e9b8c8d8e8f8a8b8c8d8e8，
SHA256为 9b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f8a8b。

该恶意软件会驻留在 C:\\Windows\\System32\\malware.exe，并修改注册表项
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MalwareService。
攻击者邮箱为 attacker@evil-company.com。

参考链接：https://www.microsoft.com/en-us/security/blog 和 https://google.com 提供了相关安全建议。
Google DNS 8.8.8.8 用于正常网络通信。
"""


def main():
    logger.remove()
    logger.add(sys.stderr, level="DEBUG",
               format="<green>{time:HH:mm:ss}</green> | <level>{level:7}</level> | {message}")

    logger.info("=" * 50)
    logger.info("IOC Agent 流水线测试")
    logger.info("=" * 50)

    # 1. 初始化
    base_dir = Path(__file__).parent
    skill_mgr = SkillManager(base_dir / "skills")
    discovered = skill_mgr.discover_skills()
    logger.info(f"发现 {len(discovered)} 个 Skill:")
    for s in discovered:
        logger.info(f"  ✅ {s.name}: {s.description}")

    scheduler = Scheduler(skill_mgr)

    assert len(discovered) >= 4, f"预期至少 4 个 Skill，实际发现 {len(discovered)}"

    # 2. IOC 提取测试
    logger.info("\n📌 测试 IOC 提取...")
    ctx = Context()
    extract_result = scheduler.run_skill(ctx, "ioc_extractor", text=TEST_TEXT)

    extracted = extract_result.get("iocs", [])
    assert len(extracted) > 0, "应提取到 IOC"
    logger.success(f"提取 {len(extracted)} 个 IOC")

    # 按类型统计
    type_counts = {}
    for ioc in extracted:
        t = ioc.get("type", "?")
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        logger.info(f"  {t}: {c} 个")
        for ioc in extracted:
            if ioc["type"] == t:
                logger.info(f"    - {ioc['value']}")

    # 验证各类型 IOC 是否被正确提取
    types_found = {i["type"] for i in extracted}
    expected_types = {"ipv4", "domain", "url", "md5", "sha256", "filepath", "email"}
    found_expected = types_found & expected_types
    assert len(found_expected) >= 3, f"应提取至少 3 种类型，当前: {types_found}"
    logger.success(f"提取类型: {types_found}")

    # 3. 白名单过滤测试
    logger.info("\n📌 测试白名单过滤...")
    filter_result = scheduler.run_skill(
        ctx, "whitelist_filter",
        iocs=extracted,
        data_dir=str(base_dir / "skills" / "whitelist_filter" / "data"),
    )
    suspicious = filter_result.get("suspicious_iocs", [])
    safe = filter_result.get("safe_iocs", [])
    logger.success(f"白名单命中 {len(safe)} 个，剩余可疑 {len(suspicious)} 个")

    # 验证 google.com 和 microsoft.com 被过滤
    safe_values = {i["value"].lower() for i in safe}
    assert any("google" in v for v in safe_values), "google.com 应被过滤"
    assert any("microsoft" in v for v in safe_values), "microsoft.com 应被过滤"

    # 4. LLM 分析测试（本地兜底模式）
    logger.info("\n📌 测试 LLM 分析（本地兜底模式）...")
    llm_result = scheduler.run_skill(
        ctx, "llm_analyzer",
        iocs=suspicious,
    )
    analyzed = llm_result.get("analyzed_iocs", [])
    assert len(analyzed) == len(suspicious), "分析结果数量应匹配"
    logger.success(f"LLM 分析完成 {len(analyzed)} 个 IOC")

    # 验证每个 IOC 都有 malicious 字段
    for ioc in analyzed:
        assert "malicious" in ioc, f"IOC {ioc['value']} 缺少 malicious 字段"
        assert ioc["malicious"] in ("malicious", "suspicious", "benign")
        logger.info(f"  [{ioc['type']}] {ioc['value']} -> {ioc['malicious']}: {ioc.get('reason','')}")

    # 5. 威胁情报查询（模拟模式）
    logger.info("\n📌 测试威胁情报查询（模拟模式）...")
    intel_result = scheduler.run_skill(
        ctx, "threat_intel",
        iocs=analyzed,
        source="vt",
    )
    intel_results = intel_result.get("results", [])
    assert intel_result.get("mock", False), "无 API Key 时应返回 mock 结果"
    logger.success(f"威胁情报查询完成 {len(intel_results)} 个 IOC（模拟）")

    # 6. 完整流水线测试
    logger.info("\n📌 测试完整流水线...")
    ctx2 = Context()
    plan = [
        {"skill": "ioc_extractor", "text": TEST_TEXT},
        {
            "skill": "whitelist_filter",
            "iocs": [],  # 将在运行时从上一步结果获取
            "data_dir": str(base_dir / "skills" / "whitelist_filter" / "data"),
        },
        {"skill": "llm_analyzer", "iocs": []},
    ]
    plan_results = scheduler.pipeline(ctx2, plan)
    logger.success(f"流水线完成，执行了 {len(plan_results)} 个步骤")

    # 输出最终统计
    logger.info("\n" + "=" * 50)
    logger.info("测试全部通过！✅")
    logger.info(f"提取 IOC: {len(extracted)}")
    logger.info(f"白名单过滤: {len(suspicious)} 可疑")
    logger.info(f"LLM 分析完成: {len(analyzed)}")
    logger.info("=" * 50)

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

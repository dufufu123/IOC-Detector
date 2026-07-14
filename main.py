#!/usr/bin/env python3
"""
IOC 识别 Agent - 入口

支持两种运行模式：
1. CLI 模式：python main.py <url>
2. 交互模式：python main.py --interactive

用法:
  python main.py https://example.com/threat-report
  python main.py --text "检测到恶意IP 192.168.1.1 连接C2服务器"
  python main.py --interactive
"""

from __future__ import annotations

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

from loguru import logger

from harness import SkillManager, Scheduler, Context


def setup_logging(level: str = "INFO"):
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:7}</level> | {message}",
    )
    logger.add(
        "output/ioc_agent_{time:YYYY-MM-DD}.log",
        level="DEBUG",
        rotation="10 MB",
        retention=3,
    )


def load_env_settings(env_path: str | Path = "config/settings.env"):
    """加载环境变量配置文件。"""
    env_path = Path(env_path)
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if value:
                os.environ.setdefault(key, value)


def init_agent() -> tuple[SkillManager, Scheduler]:
    """初始化 Agent 核心组件。"""
    base_dir = Path(__file__).parent
    skills_dir = base_dir / "skills"

    logger.info(f"Scanning skills from: {skills_dir}")
    skill_mgr = SkillManager(skills_dir)
    discovered = skill_mgr.discover_skills()

    if not discovered:
        logger.warning("No skills discovered!")
    else:
        logger.info(f"Discovered {len(discovered)} skills:")
        for s in discovered:
            logger.info(f"  ✅ {s.name}: {s.description}")

    scheduler = Scheduler(skill_mgr)
    return skill_mgr, scheduler


def run_pipeline(url: str | None = None, text: str | None = None) -> Context:
    """
    执行完整的 IOC 识别流水线：
    1. 网页抓取（如果有 URL）
    2. IOC 提取
    3. 白名单过滤
    4. LLM 语义分析
    5. 威胁情报查询
    """
    skill_mgr, scheduler = init_agent()
    ctx = Context()

    # ── 第 1 步：网页抓取 ──────────────────
    if url:
        ctx.url = url
        logger.info(f"[1/5] 抓取网页: {url}")
        result = scheduler.run_skill(ctx, "web_crawler", url=url)
        ctx.cleaned_text = result.get("cleaned_text", "")
        logger.success(f"  抓取完成，正文长度: {len(ctx.cleaned_text)} 字")
    elif text:
        ctx.cleaned_text = text
    else:
        raise ValueError("请提供 URL 或 --text 参数")

    if not ctx.cleaned_text.strip():
        logger.error("抓取内容为空，无法分析")
        return ctx

    # ── 第 2 步：IOC 提取 ──────────────────
    logger.info("[2/5] 提取 IOC 指标")
    result = scheduler.run_skill(ctx, "ioc_extractor", text=ctx.cleaned_text)
    ctx.extracted_iocs = result.get("iocs", [])
    logger.success(f"  提取到 {len(ctx.extracted_iocs)} 个 IOC")

    if not ctx.extracted_iocs:
        logger.warning("未提取到任何 IOC")
        return ctx

    # 按类型统计
    type_counts: dict[str, int] = {}
    for ioc in ctx.extracted_iocs:
        t = ioc.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        logger.info(f"    {t}: {c} 个")

    # ── 第 3 步：白名单过滤 ──────────────────
    logger.info("[3/5] 白名单过滤")
    data_dir = os.getenv("WHITELIST_DATA_DIR", "skills/whitelist_filter/data")
    result = scheduler.run_skill(
        ctx, "whitelist_filter",
        iocs=ctx.extracted_iocs,
        data_dir=data_dir,
    )
    ctx.filtered_iocs = result.get("suspicious_iocs", [])
    safe_count = result.get("safe_count", 0)
    logger.success(f"  白名单命中: {safe_count} 个，剩余可疑: {len(ctx.filtered_iocs)} 个")

    if not ctx.filtered_iocs:
        logger.info("所有 IOC 均已通过白名单过滤，无需进一步分析")
        return ctx

    # ── 第 4 步：LLM 语义分析 ───────────────
    logger.info("[4/5] LLM 语义分析")
    result = scheduler.run_skill(
        ctx, "llm_analyzer",
        iocs=ctx.filtered_iocs,
    )
    ctx.analyzed_iocs = result.get("analyzed_iocs", [])

    malicious = sum(1 for i in ctx.analyzed_iocs if i.get("malicious") == "malicious")
    suspicious = sum(1 for i in ctx.analyzed_iocs if i.get("malicious") == "suspicious")
    benign = sum(1 for i in ctx.analyzed_iocs if i.get("malicious") == "benign")
    logger.success(f"  LLM 分析完成: 恶意={malicious}, 可疑={suspicious}, 良性={benign}")

    # ── 第 5 步：威胁情报查询 ───────────────
    logger.info("[5/5] 威胁情报查询（可选）")
    if os.getenv("VT_API_KEY") or os.getenv("OTX_API_KEY"):
        source = "vt" if os.getenv("VT_API_KEY") else "otx"
        result = scheduler.run_skill(
            ctx, "threat_intel",
            iocs=ctx.analyzed_iocs,
            source=source,
        )
        intel_results = result.get("results", [])
        intel_map = {r["value"]: r for r in intel_results}
        for ioc in ctx.analyzed_iocs:
            val = ioc.get("value", "")
            if val in intel_map:
                ioc["threat_intel"] = intel_map[val]
        logger.success(f"  威胁情报查询完成")
    else:
        logger.info("  跳过（未配置 API Key）")

    # ── 生成报告 ──────────────────────────────
    generate_report(ctx)
    return ctx


def _map_to_label(ioc: dict) -> str:
    """根据 IOC 的 reason 和 type 推断标签。"""
    reason = (ioc.get("reason", "") or "").lower()
    val = ioc.get("value", "")
    ioc_type = ioc.get("type", "")

    # 恶意标签
    if "c2" in reason or "c&c" in reason or "命令与控制" in reason:
        return "C2服务器"
    if "钓鱼" in reason or "phishing" in reason:
        return "钓鱼网站"
    if "恶意软件" in reason or "木马" in reason or "trojan" in reason or "后门" in reason:
        return "恶意软件"
    if "恶意载荷" in reason or "payload" in reason or "恶意文件" in reason:
        return "恶意文件"
    if "下载" in reason and ("恶意" in reason or "攻击" in reason):
        return "恶意下载链接"
    if "攻击基础设施" in reason or "攻击" in reason or "恶意" in reason:
        return "攻击基础设施"
    if "ransomware" in reason or "勒索" in reason:
        return "勒索软件"
    if "矿池" in reason or "coin" in reason:
        return "挖矿相关"

    # 非恶意标签
    if "参考" in reason or "致谢" in reason or "引用" in reason:
        return "参考链接"
    if "白名单" in reason or "合法" in reason:
        return "合法服务"
    if "cdn" in reason or "云服务" in reason:
        return "CDN/云服务节点"
    if "上下文不明确" in reason or "未明确判断" in reason:
        return "待验证"
    if ioc_type == "registry":
        return "系统路径"

    return "待验证"


def _map_classification(malicious: str) -> str:
    """将三类判定映射为文档要求的两类结果。"""
    return {"malicious": "恶意IOC", "suspicious": "恶意IOC", "benign": "非恶意IOC"}.get(
        malicious, "待判定"
    )


_IOC_TYPE_LABEL = {
    "ipv4": "IP地址", "ipv6": "IP地址", "domain": "域名",
    "url": "URL", "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256",
    "filepath": "文件路径", "email": "邮箱地址", "registry": "注册表项",
}


def generate_report(ctx: Context):
    """生成最终 IOC 分析报告。"""
    malicious = [i for i in ctx.analyzed_iocs if i.get("malicious") == "malicious"]
    suspicious = [i for i in ctx.analyzed_iocs if i.get("malicious") == "suspicious"]
    benign = [i for i in ctx.analyzed_iocs if i.get("malicious") == "benign"]

    lines = []
    lines.append("# IOC 识别分析报告")
    lines.append(f"\n**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**来源**: {ctx.url or '直接输入'}")
    lines.append(f"**会话 ID**: {ctx.session_id}")
    lines.append("")

    # 统计摘要
    lines.append("## 统计摘要")
    lines.append(f"| 指标 | 数量 |")
    lines.append(f"|------|------|")
    lines.append(f"| 提取 IOC 总数 | {len(ctx.extracted_iocs)} |")
    lines.append(f"| 白名单过滤后 | {len(ctx.filtered_iocs)} |")
    lines.append(f"| 判定恶意 | {len(malicious) + len(suspicious)} |")
    lines.append(f"| 判定非恶意 | {len(benign)} |")
    lines.append("")

    # 合并所有已分析的 IOC 并按恶意/非恶意排序
    all_classified = []
    for i in malicious:
        all_classified.append((i, "malicious"))
    for i in suspicious:
        all_classified.append((i, "suspicious"))
    for i in benign:
        all_classified.append((i, "benign"))

    if all_classified:
        lines.append("## IOC 详细列表")
        lines.append(
            "| 序号 | IOC类型 | IOC值 | 分类结果 | 标签 | 判断依据 |"
        )
        lines.append(
            "|------|---------|-------|----------|------|----------|"
        )
        for idx, (ioc, verdict) in enumerate(all_classified, 1):
            ioc_type_display = _IOC_TYPE_LABEL.get(
                ioc.get("type", ""), ioc.get("type", "")
            )
            classification = _map_classification(verdict)
            label = ioc.get("label", "") or _map_to_label(ioc)
            reason = ioc.get("reason", "")
            lines.append(
                f"| {idx} "
                f"| {ioc_type_display} "
                f"| {ioc.get('value','')} "
                f"| {classification} "
                f"| {label} "
                f"| {reason} |"
            )
        lines.append("")

    # Skill 调用历史
    lines.append("## 执行流水线")
    lines.append("| Skill | 状态 | 耗时 |")
    lines.append("|-------|------|------|")
    for rec in ctx.skill_history:
        duration = ""
        if rec.started_at and rec.finished_at:
            from datetime import datetime as dt
            try:
                t1 = dt.fromisoformat(rec.started_at)
                t2 = dt.fromisoformat(rec.finished_at)
                duration = f"{(t2 - t1).total_seconds():.1f}s"
            except Exception:
                pass
        status_icon = {"success": "✅", "failed": "❌", "running": "⏳", "pending": "⏳"}.get(
            rec.status, "❓"
        )
        lines.append(f"| {rec.skill_name} | {status_icon} {rec.status} | {duration} |")

    ctx.final_report = "\n".join(lines)

    # 写入文件
    output_dir = Path(os.getenv("OUTPUT_DIR", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"ioc_report_{ctx.session_id}.md"
    report_path.write_text(ctx.final_report, encoding="utf-8")
    logger.success(f"报告已保存: {report_path}")

    # 同时导出 JSON
    json_path = output_dir / f"ioc_report_{ctx.session_id}.json"
    json.dump(ctx.to_dict(), open(json_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    logger.success(f"JSON 已导出: {json_path}")


def run_interactive(skill_mgr: SkillManager):
    """交互式 IOC 分析。"""
    print("\n🧠 IOC 识别 Agent (交互模式)")
    print("=" * 50)
    print("输入 URL 或直接粘贴文本进行分析")
    print("输入 'exit' 退出")
    print("输入 'skills' 查看可用 Skill")
    print("=" * 50)

    while True:
        try:
            inp = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见！")
            break

        if not inp:
            continue
        if inp.lower() == "exit":
            print("再见！")
            break
        if inp.lower() == "skills":
            print("\n可用 Skill:")
            for name in skill_mgr.list_skills():
                info = skill_mgr.get_skill(name).info
                print(f"  - {name}: {info.description}")
            continue

        if inp.startswith("http://") or inp.startswith("https://"):
            ctx = run_pipeline(url=inp)
        else:
            ctx = run_pipeline(text=inp)

        if ctx.final_report:
            print("\n" + ctx.final_report[:2000])
            if len(ctx.final_report) > 2000:
                print(f"\n... (共 {len(ctx.final_report)} 字，完整报告见 output/ 目录)")
        else:
            print("\n⚠️  未生成报告，可能未提取到 IOC")


def main():
    parser = argparse.ArgumentParser(
        description="IOC 识别 Agent - 自动化威胁指标提取与分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("url", nargs="?", help="目标安全报告 URL")
    parser.add_argument("--text", "-t", help="直接输入文本内容")
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="交互模式",
    )
    parser.add_argument(
        "--env",
        default="config/settings.env",
        help="环境变量配置文件路径",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别",
    )

    args = parser.parse_args()

    # 初始化
    load_env_settings(args.env)
    setup_logging(args.log_level or os.getenv("LOG_LEVEL", "INFO"))

    logger.info("IOC 识别 Agent 启动")

    if args.interactive:
        skill_mgr, _ = init_agent()
        run_interactive(skill_mgr)
    elif args.url:
        run_pipeline(url=args.url)
    elif args.text:
        run_pipeline(text=args.text)
    else:
        parser.print_help()
        print("\n请提供 URL、--text 参数，或使用 --interactive 进入交互模式")


if __name__ == "__main__":
    main()

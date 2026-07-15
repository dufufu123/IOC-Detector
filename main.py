#!/usr/bin/env python3
"""
IOC 识别 Agent - 入口

支持两种运行模式：
1. CLI 模式：python main.py <url>
2. 交互模式：python main.py --interactive（或不带参数，默认进入）

用法:
  python main.py https://example.com/threat-report
  python main.py --text "检测到恶意IP 192.168.1.1 连接C2服务器"
  python main.py --url-file urls.txt
  python main.py                       # 默认进入交互模式
  python main.py --interactive
"""

from __future__ import annotations

import os
import argparse
from pathlib import Path

from loguru import logger

from harness import SkillManager, Scheduler, Context
from tools.report import generate_report, generate_batch_report
from tools.delete import run_delete
from tools.utils import setup_logging, load_env_settings, _print_banner, _resolve_data_path


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


def run_pipeline(url: str | None = None, text: str | None = None,
                 write_report: bool = True) -> Context:
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
    generate_report(ctx, write=write_report)
    return ctx


def run_interactive(skill_mgr: SkillManager):
    """交互式 IOC 分析。"""

    print("=" * 50)
    print("输入 URL 或直接粘贴文本进行分析")
    print("输入 'file <文件名或路径>' 批量分析 URL（仅文件名默认从 data/ 查找）")
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

        # 批量分析：file <文件名或路径>
        low = inp.lower()
        if low == "file" or low.startswith("file "):
            parts = inp.split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip():
                print("用法: file <文件名或路径>  （仅文件名时默认从 data/ 目录查找）")
                continue
            file_path = _resolve_data_path(parts[1].strip())
            run_batch(file_path)
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


def run_batch(url_file: str | Path):
    """从 txt 文件批量分析 URL。

    文件格式：每行一个 URL；空行与 # 开头的注释行会被忽略。
    每个 URL 独立生成一份报告；单个 URL 失败不会中断整批。
    """
    path = Path(url_file)
    if not path.exists():
        logger.error(f"URL 文件不存在: {path}")
        return

    urls: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)

    if not urls:
        logger.warning(f"文件 {path} 中没有可用的 URL")
        return

    total = len(urls)
    logger.info(f"从 {path} 读取到 {total} 个 URL，开始批量分析")
    contexts: list[Context] = []
    success, failed = 0, 0
    for idx, url in enumerate(urls, 1):
        logger.info(f"═════ [{idx}/{total}] {url} ═════")
        try:
            ctx = run_pipeline(url=url, write_report=False)  # 只算不写
            success += 1
        except Exception as e:
            failed += 1
            logger.error(f"URL 分析失败 [{url}]: {e}")
            ctx = Context()
            ctx.url = url
            ctx.metadata["batch_error"] = str(e)
        contexts.append(ctx)

    # 整批汇总为「一份 md + 一份 json」（以一次命令为单位）
    generate_batch_report(contexts, str(path))
    logger.success(f"批量分析完成：成功 {success} 个，失败 {failed} 个，共 {total} 个")


def main():
    parser = argparse.ArgumentParser(
        description="IOC 识别 Agent - 自动化威胁指标提取与分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("url", nargs="?", help="目标安全报告 URL")
    parser.add_argument("--text", help="直接输入文本内容")
    parser.add_argument(
        "--url-file", "-f",
        help="从 txt 文件批量导入 URL（每行一个，空行/# 注释行忽略）",
    )
    parser.add_argument(
        "--delete", "-d",
        action="store_true",
        help="删除 output 下 md/json 报告（保留日志，日志自动滚动）",
    )
    parser.add_argument(
        "--before", "-t",
        metavar="YYYYMMDD",
        help="配合 -d：仅删除该日期（含）及以前的输出，例如 -d -t 20260715",
    )
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

    logger.info("IOC Detector Agent 启动")

    if args.delete:
        run_delete(args.before)
    elif args.before:
        logger.warning("-t/--before 需配合 -d/--delete 使用，已忽略")
        parser.print_help()
    elif args.interactive:
        _print_banner()
        skill_mgr, _ = init_agent()
        run_interactive(skill_mgr)
    elif args.url_file:
        run_batch(args.url_file)
    elif args.url:
        run_pipeline(url=args.url)
    elif args.text:
        run_pipeline(text=args.text)
    else:
        # 无参数默认进入交互模式
        _print_banner()
        skill_mgr, _ = init_agent()
        run_interactive(skill_mgr)


if __name__ == "__main__":
    main()

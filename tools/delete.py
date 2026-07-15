"""输出清理工具：按日期或全量删除 md/json 报告（保留日志）。"""

from __future__ import annotations

import os
import re
from pathlib import Path
from datetime import date, datetime

from loguru import logger


# 从文件名中提取日期：匹配 20260714 或 2026-07-14 两种写法
_FILE_DATE_RE = re.compile(r"(\d{4})-?(\d{2})-?(\d{2})")


def _extract_file_date(name: str) -> date | None:
    """从文件名解析出日期（取第一个日期样式）。解析不出返回 None。"""
    m = _FILE_DATE_RE.search(name)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _remove_empty_subdirs(top: Path):
    """自底向上删除 top 下的空子目录，保留 top 本身。"""
    for p in sorted(top.rglob("*"), reverse=True):
        if p.is_dir():
            try:
                p.rmdir()          # 仅当目录为空时成功
            except OSError:
                pass


def run_delete(before: str | None = None):
    """删除 output 下 md/json 报告（保留日志，日志由 loguru 自动滚动清理）。

    before 为 None 时删除全部；否则仅删除该日期（含）及以前的文件，
    日期取自文件名（如 ioc_report_20260714_...、ioc_batch_...）。
    """
    cutoff: date | None = None
    if before:
        try:
            cutoff = datetime.strptime(before, "%Y%m%d").date()
        except ValueError:
            logger.error(f"-t 日期格式错误：{before!r}，应为 YYYYMMDD，例如 20260715")
            return

    base_dir = Path(os.getenv("OUTPUT_DIR", "./output"))
    deleted = skipped = 0

    for sub in ("md", "json"):
        d = base_dir / sub
        if not d.exists():
            continue                       # 文件夹不存在则跳过
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            if cutoff is not None:
                fdate = _extract_file_date(f.name)
                # 无法判断日期、或晚于截止日 -> 保留
                if fdate is None or fdate > cutoff:
                    continue
            try:
                f.unlink()
                deleted += 1
            except OSError as e:
                skipped += 1               # 例如占用/无权限
                logger.warning(f"无法删除 {f}: {e}")
        _remove_empty_subdirs(d)

    scope = f"（{before} 及以前）" if before else "（全部）"
    msg = f"删除完成{scope}，共删除 {deleted} 个报告文件"
    if skipped:
        msg += f"，跳过 {skipped} 个（占用/无权限）"
    logger.success(msg)

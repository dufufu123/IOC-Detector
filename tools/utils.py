"""启动配置与路径解析工具：日志、环境变量、字符画、data/ 路径解析。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from loguru import logger

# tools/ 在项目根下一层，parent.parent 即项目根
_PROJECT_ROOT = Path(__file__).parent.parent


def setup_logging(level: str = "INFO"):
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:7}</level> | {message}",
    )
    output_dir = os.getenv("OUTPUT_DIR", "./output").rstrip("/\\")
    logger.add(
        output_dir + "/log/{time:YYYY.M}/ioc_agent_{time:YYYY-MM-DD}.log",
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


def _print_banner():
    print("\n" * 1)
    """打印 data/banner.txt 中的字符画；文件缺失时退化为纯文字标题。"""
    banner_path = _PROJECT_ROOT / "data" / "banner.txt"
    if banner_path.exists():
        print(banner_path.read_text(encoding="utf-8"), end="")
    else:
        print("IOC Detector Agent")
    print("\n" * 2)


def _resolve_data_path(filename: str) -> Path:
    """解析文件路径：仅有文件名（无目录部分）时默认从 data/input/ 目录查找，否则按原路径使用。"""
    p = Path(filename)
    if p.parent == Path("."):
        return _PROJECT_ROOT / "data" / "input" / filename
    return p

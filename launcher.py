#!/usr/bin/env python3
"""
IOC-Detector 启动器 —— 自动发现 Skills 并交互选择运行模式

使用方式: python launcher.py
"""

from __future__ import annotations
import os, sys, subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from harness import SkillManager

PROJECT_DIR = Path(__file__).parent


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def main():
    _clear()

    # ── 发现所有 Skills ──
    skill_mgr = SkillManager(PROJECT_DIR / "skills")
    skills = skill_mgr.discover_skills()
    has_gui = any(s.name == "gui" for s in skills)

    print()
    print("  ┌──────────────────────────────────────────┐")
    print("  │       ■ IOC-Detector v1.1 ■              │")
    print("  │    威胁指标自动提取与分析平台             │")
    print("  ├──────────────────────────────────────────┤")
    print("  │    已发现 Skills:                         │")
    for s in skills:
        marker = " ◉" if s.name == "gui" else "  ·"
        print(f"  │  {marker} {s.name}: {s.description[:30]}")

    print("  ├──────────────────────────────────────────┤")
    print("  │    请选择运行模式:                        │")
    if has_gui:
        print("  │    [1] ▸ Web GUI 界面 (Streamlit)        │")
        print("  │    [2] ▸ 终端 CLI 模式                   │")
    else:
        print("  │    [1] ▸ 终端 CLI 模式                   │")
    print("  │    [0] 退出                              │")
    print("  └──────────────────────────────────────────┘")
    print()

    try:
        choice = input("  >>> 请输入选项: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  已退出.")
        return

    if has_gui and choice == "1":
        skill_mgr.get_skill("gui").execute()
    elif (has_gui and choice == "2") or (not has_gui and choice == "1"):
        _clear()
        os.chdir(str(PROJECT_DIR))
        subprocess.run([sys.executable, "main.py"])
    elif choice == "0":
        print("  已退出.")
    else:
        print("  无效选项，请重新运行.")


if __name__ == "__main__":
    main()

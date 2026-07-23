"""GUI Skill —— 启动 Streamlit Web 界面"""

from __future__ import annotations
import sys, os, subprocess, webbrowser, time
from pathlib import Path
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="gui",
    description="启动 Web GUI 界面（Streamlit），提供可视化的 IOC 分析操作",
    version="1.0.0",
    author="yyy",
    dependencies=["streamlit>=1.28", "openpyxl"],
    enabled=True,
)


def execute(**kwargs) -> dict:
    """启动 Streamlit GUI 服务器"""
    project_root = Path(__file__).parent.parent.parent  # skills/gui -> skills -> IOC-Detector/
    app_path = project_root / "app.py"

    if not app_path.exists():
        print(f"\n  ❌ app.py 不存在: {app_path}")
        return {"status": "error", "message": str(app_path)}

    # 加载 settings.env
    env_vars = os.environ.copy()
    env_path = project_root / "config" / "settings.env"
    if env_path.exists():
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("\"'")
                if value:
                    env_vars[key] = value

    url = "http://localhost:8501"

    print(f"\n  ■ 正在启动 Streamlit Web GUI ...")
    print(f"  ■ 浏览器地址: {url}")
    print(f"  ■ 按 Ctrl+C 停止服务\n")

    # 延迟打开浏览器，等 Streamlit 启动
    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", str(app_path),
             "--server.port", "8501",
             "--server.headless", "true",
             "--browser.gatherUsageStats", "false"],
            cwd=str(project_root),
            env=env_vars,
            check=False,
        )
    except KeyboardInterrupt:
        print("\n  ■ GUI 服务已停止")
    except Exception as e:
        print(f"\n  ❌ 启动失败: {e}")
        return {"status": "error", "message": str(e)}

    return {"status": "ok", "message": "GUI 已关闭"}

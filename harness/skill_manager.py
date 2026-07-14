from __future__ import annotations
import os
import sys
import importlib.util
from pathlib import Path
from typing import Any, Protocol
from pydantic import BaseModel, Field


class SkillInfo(BaseModel):
    name: str
    description: str
    version: str = "1.0.0"
    author: str = ""
    dependencies: list[str] = []
    enabled: bool = True


class BaseSkill(Protocol):
    info: SkillInfo

    def execute(self, **kwargs) -> Any: ...


class SkillManager:
    def __init__(self, skills_dir: str | Path):
        self.skills_dir = Path(skills_dir)
        self._registry: dict[str, BaseSkill] = {}

    def discover_skills(self) -> list[SkillInfo]:
        if not self.skills_dir.exists():
            return []
        discovered = []
        for entry in sorted(self.skills_dir.iterdir()):
            if not entry.is_dir() or entry.name.startswith("_"):
                continue
            main_py = entry / "main.py"
            if not main_py.exists():
                continue
            skill_mod = self._load_module(entry.name, str(main_py))
            if skill_mod is None:
                continue
            skill_instance = self._extract_skill(skill_mod)
            if skill_instance is not None:
                self._registry[entry.name] = skill_instance
                discovered.append(skill_instance.info)
        return discovered

    def get_skill(self, name: str) -> BaseSkill | None:
        return self._registry.get(name)

    def list_skills(self) -> list[str]:
        return list(self._registry.keys())

    def _load_module(self, name: str, path: str) -> object | None:
        try:
            # 确保项目根目录在 sys.path 中，使技能模块可以 import harness
            project_root = str(self.skills_dir.parent)
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            spec = importlib.util.spec_from_file_location(f"skills.{name}", path)
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        except Exception as e:
            print(f"  [SkillManager] Failed to load skill '{name}': {e}")
            return None

    def _extract_skill(self, mod: object) -> BaseSkill | None:
        # 方式 1：模块级 info + execute 模式
        mod_info = getattr(mod, "info", None)
        mod_execute = getattr(mod, "execute", None)
        if isinstance(mod_info, SkillInfo) and callable(mod_execute):
            # 将模块本身作为 skill 对象（info + execute 属性）
            return mod

        # 方式 2：类实例模式（info 作为实例属性）
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if isinstance(attr, type):
                continue
            if hasattr(attr, "info") and isinstance(getattr(attr, "info", None), SkillInfo):
                return attr
            if hasattr(attr, "execute") and callable(attr.execute):
                info = getattr(attr, "info", None)
                if isinstance(info, SkillInfo):
                    return attr
        return None

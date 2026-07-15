from __future__ import annotations
from typing import Any
from loguru import logger
from .skill_manager import SkillManager
from .context import Context


class Scheduler:
    def __init__(self, skill_manager: SkillManager):
        self.skill_manager = skill_manager

    def run_skill(self, ctx: Context, skill_name: str, **kwargs) -> Any:
        skill = self.skill_manager.get_skill(skill_name)
        if skill is None:
            msg = f"Skill '{skill_name}' not found"
            logger.error(msg)
            raise ValueError(msg)

        record = ctx.start_skill(skill_name, **kwargs)
        logger.info(f"Executing skill: {skill_name}")
        try:
            result = skill.execute(**kwargs)
            ctx.finish_skill(record, result)
            logger.success(f"Skill '{skill_name}' completed")
            return result
        except Exception as e:
            logger.error(f"Skill '{skill_name}' failed: {e}")
            ctx.fail_skill(record, str(e))
            raise

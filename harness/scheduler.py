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

    def pipeline(self, ctx: Context, plan: list[dict[str, Any]]) -> dict[str, Any]:
        results = {}
        for step in plan:
            name = step["skill"]
            params = {k: v for k, v in step.items() if k != "skill"}
            fallback = step.get("fallback", None)
            try:
                results[name] = self.run_skill(ctx, name, **params)
            except Exception as e:
                if fallback:
                    logger.warning(f"Skill '{name}' failed, using fallback: {fallback}")
                    fb_name = fallback.get("skill")
                    fb_params = {k: v for k, v in fallback.items() if k != "skill"}
                    results[name] = self.run_skill(ctx, fb_name, **fb_params)
                else:
                    results[name] = {"error": str(e)}
        return results

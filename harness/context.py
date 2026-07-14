import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class SkillCallRecord(BaseModel):
    skill_name: str
    status: str = "pending"  # pending | running | success | failed
    input_data: dict[str, Any] = {}
    output_data: Any = None
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class Context(BaseModel):
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    url: str = ""
    raw_text: str = ""
    cleaned_text: str = ""
    extracted_iocs: list[dict[str, Any]] = []
    filtered_iocs: list[dict[str, Any]] = []
    analyzed_iocs: list[dict[str, Any]] = []
    final_report: str = ""
    skill_history: list[SkillCallRecord] = []
    metadata: dict[str, Any] = {}

    def start_skill(self, name: str, **kwargs) -> SkillCallRecord:
        record = SkillCallRecord(
            skill_name=name,
            status="running",
            input_data=kwargs,
            started_at=datetime.now().isoformat(),
        )
        self.skill_history.append(record)
        return record

    def finish_skill(self, record: SkillCallRecord, output: Any = None):
        record.status = "success"
        record.output_data = output
        record.finished_at = datetime.now().isoformat()

    def fail_skill(self, record: SkillCallRecord, error: str):
        record.status = "failed"
        record.error = error
        record.finished_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

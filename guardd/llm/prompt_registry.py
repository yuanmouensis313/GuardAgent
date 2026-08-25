from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from guardd.security import digest_payload


@dataclass(frozen=True)
class PromptTemplate:
    template_id: str
    version: str
    content: str
    digest: str


class PromptRegistry:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(__file__).with_name("prompts")

    def load(self, template_id: str, version: str) -> PromptTemplate:
        safe_id = template_id.replace("_", "-")
        safe_version = version.replace(".", "-")
        path = self.root / f"{safe_id}-v{safe_version}.md"
        if not path.is_file():
            raise ValueError(f"prompt template not found: {template_id}@{version}")
        content = path.read_text(encoding="utf-8")
        if not content.strip():
            raise ValueError(f"prompt template is empty: {template_id}@{version}")
        return PromptTemplate(
            template_id=template_id,
            version=version,
            content=content,
            digest=digest_payload({"template_id": template_id, "version": version, "content": content}),
        )
